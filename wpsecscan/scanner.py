from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import __version__
from .checks import select_checks
from .http import Client
from .models import CheckResult, ScanReport
from .prove import PROVERS

DEFAULT_USER_AGENT = f"WPSecScan/{__version__} (+defensive-recon)"

ProgressCallback = Callable[[str, str, str, CheckResult | None], None]
# (event, check_id, check_name, result_or_none)
# event ∈ {"start", "done", "step"}; for "step", result_or_none carries the sub-step
# label via CheckResult.error (overloaded).

StepCallback = Callable[[str], None]
# Checks can call ctx["step"]("now probing /wp-config.php.bak") to update the GUI.


async def _run_check(
    check_id: str, check_name: str, fn, client: Client, ctx: dict,
    on_progress: ProgressCallback | None,
) -> CheckResult:
    if on_progress:
        try:
            on_progress("start", check_id, check_name, None)
        except Exception:  # noqa: BLE001
            pass
    started = time.perf_counter()
    result = CheckResult(check_id=check_id, check_name=check_name)
    # J20: skip checks auto-disabled this run after 3 failures
    try:
        from . import check_health as _ch
        if _ch.is_disabled_for_run(check_id):
            result.error = "auto-disabled this run after repeated failures"
            return result
    except ImportError:
        pass
    try:
        findings = await fn(client, ctx)
        if findings:
            result.findings.extend(findings)
    except Exception as e:  # noqa: BLE001 — checks must not crash the scan
        result.error = f"{type(e).__name__}: {e}"
        try:
            from . import check_health as _ch
            _ch.record_failure(check_id)
        except ImportError:
            pass
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    # J21: record duration to the rolling baseline.
    # Skip when the check raised — exception-aborted durations distort the
    # baseline (short exception-exit times pull the median down so the
    # is_over_budget heuristic stops firing for genuine outliers).
    if result.error is None:
        try:
            from . import check_health as _ch
            _ch.record_duration(check_id, result.duration_ms)
        except (ImportError, OSError):
            pass
    if on_progress:
        try:
            on_progress("done", check_id, check_name, result)
        except Exception:  # noqa: BLE001
            pass
    return result


async def scan(
    target: str,
    *,
    timeout: float = 15.0,
    user_agent: str = DEFAULT_USER_AGENT,
    concurrency: int = 10,
    verify_tls: bool = True,
    wpscan_token: str | None = None,
    aggressive: bool = False,
    prove: bool = False,
    sequential: bool = True,
    auth_user: str | None = None,
    auth_pass: str | None = None,
    auth_app_password: str | None = None,
    auth_totp: str | None = None,
    companion_token: str | None = None,
    proxy: str | None = None,            # round-61
    proxy_auth: str | None = None,       # round-61
    hibp_token: str | None = None,
    deep_throttle: bool = False,
    deep_throttle_attempts: int | None = None,
    deep_throttle_pacing_s: float | None = None,
    har: bool = False,
    har_path=None,  # Path | None — writes the HAR to disk before client closes
    parallel_groups: bool = False,  # B3: run within-group checks concurrently
    checkpoint: bool = False,       # B1: resumable scans via ~/.wpsecscan/checkpoint.json
    abuseipdb_token: str | None = None,   # C6 / round-S
    vt_token: str | None = None,          # C5 / round-S
    github_search_token: str | None = None,  # B6 / round-S
    since=None,  # K26 incremental: datetime — skip low-churn checks when target snapshot is newer
    on_progress: ProgressCallback | None = None,
    is_cancelled: Callable[[], bool] | None = None,
) -> ScanReport:
    """Run every check against `target` and return a ScanReport.

    aggressive=True enables active payload checks (SQLi probes, reflected XSS,
    open-redirect tests, plugin-CVE matching). Only use on sites you own.

    sequential=True (default) runs checks one at a time so dependent checks
    (e.g. plugin_cves needs plugins to have populated ctx['shared']['plugins'])
    see each other's output, and a UI can narrate progress. Setting
    sequential=False is a perf optimization for passive-only scans, but
    silently breaks CVE matching and proof extraction.
    """
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    started_wall = datetime.now(timezone.utc).isoformat()
    started = time.perf_counter()

    # round-61: proxy resolution order:
    #   1. explicit `proxy=` arg (from --proxy CLI or per-site config)
    #   2. WPSECSCAN_PROXY_URL env var
    #   3. httpx auto-fallback to HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
    import os as _os
    effective_proxy = proxy or _os.environ.get("WPSECSCAN_PROXY_URL") or None
    effective_proxy_auth = proxy_auth or _os.environ.get("WPSECSCAN_PROXY_AUTH") or None
    client = Client(
        target,
        timeout=timeout,
        user_agent=user_agent,
        concurrency=concurrency,
        verify=verify_tls,
        cache=True,  # huge speedup — many checks fetch / and /wp-login.php
        har=har,
        proxy=effective_proxy,
        proxy_auth=effective_proxy_auth,
    )
    # The per-check step callback lets checks narrate sub-steps to the GUI
    # in real time (e.g. "probing /wp-config.php.bak").
    current_check_id = {"id": "", "name": ""}

    def _emit_step(label: str) -> None:
        # Stash the step label on a mutable slot the callback can read
        ctx["_last_step"] = label
        if on_progress:
            try:
                on_progress("step", current_check_id["id"], label, None)  # label rides in check_name slot
            except Exception:  # noqa: BLE001
                pass

    ctx: dict = {
        "target": target,
        "wpscan_token": wpscan_token,
        "hibp_token": hibp_token,
        "abuseipdb_token": abuseipdb_token,
        "vt_token": vt_token,
        "github_search_token": github_search_token,
        "aggressive": aggressive,
        "deep_throttle": deep_throttle,
        "deep_throttle_attempts": deep_throttle_attempts,
        "deep_throttle_pacing_s": deep_throttle_pacing_s,
        "auth_user": auth_user,
        "auth_pass": auth_pass,
        "auth_app_password": auth_app_password,
        "auth_totp": auth_totp,
        "companion_token": companion_token,
        "shared": {},  # checks can stash data here (e.g. discovered plugins)
        "step": _emit_step,
        # #14: long-running checks (deep throttle, etc.) can poll this to bail cleanly.
        "is_cancelled": is_cancelled or (lambda: False),
    }
    auth_enabled = bool(
        companion_token or
        (auth_user and (auth_pass or auth_app_password))
    )
    checks = select_checks(aggressive, authenticated_enabled=auth_enabled)
    # Proof extraction needs sequential ordering — silently force it on.
    if prove:
        sequential = True
    # B4: smart-skip aggressive checks after consecutive WAF blocks.
    AGGRESSIVE_IDS = {"sqli", "xss_reflected", "open_redirect", "ssrf",
                      "path_traversal", "file_upload", "default_creds",
                      "ajax_surface", "sendmail_injection", "core_tampering",
                      "prototype_pollution",
                      "csv_export_csp", "waf_bypass_probe", "xxe_upload"}
    waf_block_streak = 0
    WAF_SKIP_THRESHOLD = 3
    skipped_due_to_waf: list[str] = []

    def _looks_like_waf_block(result) -> bool:
        """Heuristic: aggressive check returned only info/empty findings — likely WAF-filtered."""
        if result.error:
            return False
        non_info = [f for f in result.findings if f.severity != "info"]
        if non_info:
            return False
        # An info-only result is the typical "WAF blocked everything" signal
        return True

    # B1: resumable scans — load any prior checkpoint for this target
    completed_check_ids: set[str] = set()
    prior_results: list = []
    checkpoint_path = None
    if checkpoint:
        from . import history as _h
        cp_dir = Path(_h._home()) / "checkpoints"
        cp_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = cp_dir / (_h._safe_filename(target) + ".json")
        if checkpoint_path.exists():
            try:
                import json as _json
                from .models import CheckResult, Finding
                blob = _json.loads(checkpoint_path.read_text(encoding="utf-8"))
                if blob.get("target") == target:
                    completed_check_ids = set(blob.get("completed", []) or [])
                    for r_dict in blob.get("results", []) or []:
                        prior_results.append(CheckResult(
                            check_id=r_dict["check_id"],
                            check_name=r_dict["check_name"],
                            error=r_dict.get("error"),
                            duration_ms=r_dict.get("duration_ms", 0),
                            findings=[Finding(**f) for f in r_dict.get("findings", [])],
                        ))
                    _emit_step(f"resuming from checkpoint: {len(completed_check_ids)} checks already done")
            except (OSError, ValueError, KeyError, TypeError):
                # Checkpoint corrupted — start fresh.
                completed_check_ids = set()
                prior_results = []

    def _save_checkpoint(current_results: list) -> None:
        """B1: persist completed checks to disk so a Ctrl+C is resumable."""
        if not checkpoint or checkpoint_path is None:
            return
        try:
            import json as _json
            blob = {
                "target": target,
                "scanned_at": started_wall,
                "completed": [r.check_id for r in current_results],
                "results": [r.to_dict() for r in current_results],
            }
            checkpoint_path.write_text(_json.dumps(blob, indent=2), encoding="utf-8")
        except (OSError, ValueError):
            pass

    try:
        if sequential or parallel_groups:
            # Both sequential and parallel-groups modes share this loop; parallel-groups
            # just runs a batch of checks at once inside the loop body.
            results = list(prior_results)  # B1: start with what's already on disk
            from .models import CheckResult

            # B3: partition checks into 4 groups for the parallel mode
            if parallel_groups:
                RECON = {"waf", "core_version", "plugins", "themes", "users", "subdomains",
                         "dns_security", "favicon_fingerprint", "http2_settings",
                         "security_txt"}
                # Aggressive runs sequentially even in this mode (mutation risk)
                aggressive_ids = AGGRESSIVE_IDS
                groups: list[list] = [
                    [c for c in checks if c[0] in RECON],            # group 0: recon (populates shared)
                    [c for c in checks if c[0] not in RECON
                                          and c[0] not in aggressive_ids],  # group 1: surface + APIs
                    [c for c in checks if c[0] in aggressive_ids],   # group 2: aggressive (sequential)
                ]
            else:
                groups = [list(checks)]

            for group_idx, group in enumerate(groups):
                if not group:
                    continue
                # B3: parallel mode — for non-aggressive groups, gather concurrently.
                # The aggressive group always runs sequentially.
                run_in_parallel = (parallel_groups and group_idx in (0, 1))
                if run_in_parallel:
                    # Filter out completed (B1) and WAF-skipped (B4)
                    active = []
                    for cid, cname, fn in group:
                        if cid in completed_check_ids:
                            continue
                        if cid in AGGRESSIVE_IDS and waf_block_streak >= WAF_SKIP_THRESHOLD:
                            skipped_due_to_waf.append(cid)
                            results.append(CheckResult(check_id=cid, check_name=cname,
                                                        error=f"Skipped: WAF blocked {waf_block_streak} prior aggressive checks."))
                            continue
                        # K26 incremental: skip low-churn checks for unchanged targets
                        if since is not None:
                            try:
                                from . import incremental as _inc
                                if _inc.should_skip_check(cid, target, since):
                                    results.append(CheckResult(
                                        check_id=cid, check_name=cname,
                                        error="Skipped: incremental mode — no target change since baseline.",
                                    ))
                                    continue
                            except ImportError:
                                pass
                        active.append((cid, cname, fn))
                    if is_cancelled and is_cancelled():
                        break
                    if active:
                        tasks = [_run_check(cid, cname, fn, client, ctx, on_progress) for cid, cname, fn in active]
                        raw = await asyncio.gather(*tasks, return_exceptions=True)
                        for (cid, cname, _fn), r in zip(active, raw):
                            if isinstance(r, BaseException):
                                results.append(CheckResult(check_id=cid, check_name=cname,
                                                            error=f"{type(r).__name__}: {r}"))
                            else:
                                results.append(r)
                        _save_checkpoint(results)
                    continue

                # Sequential per-check loop (used for sequential mode + aggressive group)
                for cid, cname, fn in group:
                    if is_cancelled and is_cancelled():
                        break
                    if cid in completed_check_ids:
                        continue
                    # K26 incremental: skip low-churn checks for unchanged targets
                    if since is not None:
                        try:
                            from . import incremental as _inc
                            if _inc.should_skip_check(cid, target, since):
                                results.append(CheckResult(
                                    check_id=cid, check_name=cname,
                                    error="Skipped: incremental mode — no target change since baseline.",
                                ))
                                continue
                        except ImportError:
                            pass
                    # B4: skip remaining aggressive checks if WAF blocked 3 in a row
                    if cid in AGGRESSIVE_IDS and waf_block_streak >= WAF_SKIP_THRESHOLD:
                        skipped_due_to_waf.append(cid)
                        results.append(CheckResult(
                            check_id=cid, check_name=cname,
                            error=f"Skipped: previous {waf_block_streak} aggressive checks were WAF-blocked.",
                        ))
                        continue
                    current_check_id["id"] = cid
                    current_check_id["name"] = cname
                    r = await _run_check(cid, cname, fn, client, ctx, on_progress)
                    results.append(r)
                    _save_checkpoint(results)
                    if cid in AGGRESSIVE_IDS and (ctx.get("shared", {}).get("waf") or []):
                        if _looks_like_waf_block(r):
                            waf_block_streak += 1
                        else:
                            waf_block_streak = 0
        else:
            tasks = [
                _run_check(cid, cname, fn, client, ctx, on_progress)
                for cid, cname, fn in checks
            ]
            # return_exceptions=True: a single check raising shouldn't kill all the others.
            # _run_check is supposed to catch and return a CheckResult with .error set, but
            # belt-and-braces here in case future refactors miss something.
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            results = []
            for (cid, cname, _fn), r in zip(checks, raw_results):
                if isinstance(r, BaseException):
                    results.append(CheckResult(check_id=cid, check_name=cname,
                                               error=f"{type(r).__name__}: {r}"))
                else:
                    results.append(r)

        # Detection-quality pass: if a WAF was detected, downgrade aggressive
        # findings' confidence — they may have been mangled by the WAF and
        # represent a false picture of the underlying app.
        waf_list = ctx.get("shared", {}).get("waf") or []
        if waf_list:
            aggressive_ids = {"sqli", "xss_reflected", "open_redirect", "ssrf",
                              "path_traversal", "file_upload", "default_creds",
                              "ajax_surface", "sendmail_injection"}
            for r in results:
                if r.check_id in aggressive_ids:
                    for f in r.findings:
                        if f.severity in ("info",):
                            continue
                        # Annotate with WAF context; downgrade non-confirmed by one tier
                        is_confirmed = (f.extra or {}).get("proof") or "[CONFIRMED]" in f.title
                        if not is_confirmed:
                            f.extra = {**(f.extra or {}), "waf_interfered": waf_list,
                                       "confidence": "low — WAF may have mangled the probe"}
                            # Downgrade by one tier
                            downgrades = {"critical": "high", "high": "medium", "medium": "low", "low": "info"}
                            f.severity = downgrades.get(f.severity, f.severity)

        # Post-pass: read-only proof extraction for any provable finding.
        # Works for both sequential and concurrent modes.
        if prove:
            for r in results:
                if r.error:
                    continue
                for finding in r.findings:
                    if not (finding.extra and finding.extra.get("provable")):
                        continue
                    prover_name = finding.extra.get("prover")
                    prover = PROVERS.get(prover_name) if prover_name else None
                    if not prover:
                        continue
                    try:
                        current_check_id["id"] = r.check_id
                        current_check_id["name"] = r.check_name
                        _emit_step(f"extracting read-only proof for: {finding.title[:60]}...")
                        proof = await prover(client, finding.extra)
                        finding.extra["proof"] = proof
                    except Exception as e:  # noqa: BLE001
                        finding.extra["proof_error"] = f"{type(e).__name__}: {e}"
    finally:
        # E2: dump HAR before closing the client (so har_entries is still accessible).
        if har and har_path is not None:
            try:
                import json as _json
                from pathlib import Path as _Path
                _Path(har_path).write_text(_json.dumps(client.har_export(), indent=2), encoding="utf-8")
            except Exception:  # noqa: BLE001
                pass
        await client.aclose()

    # B1: if we got this far (no exception, not cancelled), the scan completed
    # successfully — clear the checkpoint so the next run starts fresh.
    if checkpoint and checkpoint_path is not None and not (is_cancelled and is_cancelled()):
        try:
            checkpoint_path.unlink()
        except OSError:
            pass

    return ScanReport(
        target=target,
        scanned_at=started_wall,
        duration_ms=int((time.perf_counter() - started) * 1000),
        results=list(results),
    )
