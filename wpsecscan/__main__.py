from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# Windows consoles still default to cp1252 / cp437; force UTF-8 so unicode
# glyphs in evidence strings and scanned-site response bodies don't crash render.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from rich.console import Console

from . import __version__
from . import db as vulndb
from . import diff as diff_mod
from . import log as logmod
from . import password_audit as pwaudit
from . import ssh_audit as sshaudit
from .reporters import console as console_reporter
from .reporters import csv_out as csv_reporter
from .reporters import dashboard as dashboard_reporter
from .reporters import html as html_reporter
from .reporters import json_out as json_reporter
from .reporters import markdown as md_reporter
from .reporters import sarif as sarif_reporter
from .reporters import xlsx_out as xlsx_reporter
from .scanner import scan


def _safe_host(target: str) -> str:
    host = urlparse(target).hostname or "site"
    return re.sub(r"[^a-z0-9.-]+", "_", host.lower())


def _read_auth_pass_from_stdin() -> str:
    """Prompt for the admin password via getpass. Exits 130 on Ctrl+C/EOF.

    Extracted from main() so the stdin path is directly testable without
    needing to drive the full argparse pipeline.
    """
    import getpass
    try:
        return getpass.getpass("WordPress admin password: ")
    except (EOFError, KeyboardInterrupt):
        print("aborted: no password provided", file=sys.stderr)
        sys.exit(130)


def _outdir(arg: str | None) -> Path:
    if not arg:
        return Path.cwd()
    # Canonicalize so `--out ../../foo` shows up resolved in output messages
    # and prevents subtle directory-confusion bugs downstream.
    p = Path(arg).expanduser()
    resolved = p.resolve() if not p.suffix else p.parent.resolve()
    # Safety: refuse to mkdir outside cwd / home (defence against
    # `--out ../../etc/cron.d/...` and similar misuse, esp. when a caller
    # builds the --out value from config or another scan). Honour an
    # explicit opt-out via WPSECSCAN_ALLOW_ANY_OUT=1 for the rare
    # legitimate case (e.g. /var/log/wpsecscan/).
    allow_any = os.environ.get("WPSECSCAN_ALLOW_ANY_OUT") == "1"
    if not allow_any:
        cwd = Path.cwd().resolve()
        home = Path.home().resolve()
        if not (str(resolved).startswith(str(cwd)) or str(resolved).startswith(str(home))):
            raise SystemExit(
                f"--out {arg} resolves outside cwd ({cwd}) and home ({home}). "
                "Set WPSECSCAN_ALLOW_ANY_OUT=1 to override."
            )
    if p.suffix:
        # Filename-shaped arg: ensure parent directory exists before writes.
        parent = p.parent if str(p.parent) else Path.cwd()
        if str(parent) and parent != Path("."):
            parent.mkdir(parents=True, exist_ok=True)
        return parent.resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


def _stem(target: str, out_arg: str | None) -> str:
    if out_arg:
        p = Path(out_arg)
        if p.suffix:
            return p.with_suffix("").name
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"wpsecscan-{_safe_host(target)}-{ts}"


def _parse_since(s: str):
    """K26: parse `--since YYYY-MM-DD` (or full ISO timestamp) to datetime.
    Returns None on invalid input rather than crashing the scan."""
    from datetime import datetime
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00").split("+", 1)[0])
    except (ValueError, AttributeError):
        return None


async def _scan_one(target: str, args, console: Console):
    # Item #72 — hwkey gate. Runs first so we never start an aggressive
    # check before authorisation is confirmed; passthrough for passive scans.
    _check_aggressive_hwkey_gate(args)
    # Round-56: wrap the scan in a live multi-panel dashboard when stdout
    # is a TTY and the user hasn't asked for plain output.
    use_live = (not args.no_console
                and not getattr(args, "no_live", False)
                and bool(getattr(console, "is_terminal", False)))
    dash = None
    on_progress = None
    if use_live:
        try:
            from .console_live import LiveDashboard
            from .checks import select_checks
            total = len(select_checks(args.aggressive,
                                       authenticated_enabled=bool(
                                           (args.auth_user and (args.auth_pass or args.auth_app_password))
                                           or args.companion_token)))
            dash = LiveDashboard(console, target, total)
            dash.__enter__()
            on_progress = dash.on_progress_callback()
        except Exception:  # noqa: BLE001
            dash = None
            on_progress = None

    try:
        report = await scan(
            target,
            timeout=args.timeout,
            user_agent=args.user_agent,
            concurrency=args.concurrency,
            verify_tls=not args.insecure,
            wpscan_token=args.wpscan_token,
            hibp_token=args.hibp_token,
            aggressive=args.aggressive,
            prove=args.prove,
            deep_throttle=args.deep_throttle,
            deep_throttle_attempts=args.deep_throttle_attempts,
            deep_throttle_pacing_s=args.deep_throttle_pacing,
            auth_user=args.auth_user,
            auth_pass=args.auth_pass,
            auth_app_password=args.auth_app_password,
            auth_totp=args.auth_totp,
            companion_token=args.companion_token,
            proxy=args.proxy,
            proxy_auth=args.proxy_auth,
            har=bool(args.har),
            har_path=Path(args.har) if args.har else None,
            parallel_groups=args.parallel_groups,
            checkpoint=args.checkpoint,
            abuseipdb_token=args.abuseipdb_token,
            vt_token=args.vt_token,
            github_search_token=args.github_search_token,
            since=_parse_since(args.since) if getattr(args, "since", None) else None,
            on_progress=on_progress,
        )
    finally:
        if dash is not None:
            try:
                dash.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass

    # Item #39 — fan-out to PagerDuty + Opsgenie via env vars (no CLI flags;
    # only fires when WPSECSCAN_PAGERDUTY_KEY / WPSECSCAN_OPSGENIE_KEY are set).
    try:
        from . import notify as _n_post
        pd_key = os.environ.get("WPSECSCAN_PAGERDUTY_KEY", "")
        if pd_key:
            ok_pd, _ = _n_post.notify_pagerduty(report, routing_key=pd_key)
            if ok_pd and not args.no_console:
                console.print("[green]✓[/green] PagerDuty incident triggered.")
        og_key = os.environ.get("WPSECSCAN_OPSGENIE_KEY", "")
        if og_key:
            og_region = os.environ.get("WPSECSCAN_OPSGENIE_REGION", "us")
            ok_og, _ = _n_post.notify_opsgenie(report, api_key=og_key, region=og_region)
            if ok_og and not args.no_console:
                console.print("[green]✓[/green] Opsgenie alert created.")
    except Exception:  # noqa: BLE001
        pass

    # #61 — redact JWTs / session cookies / bearer tokens / PII from
    # evidence + remediation BEFORE any reporter runs.
    if getattr(args, "redact_evidence", False):
        try:
            from . import ai_safety as _safety
            n = _safety.redact_report_in_place(report)
            if n and not args.no_console:
                console.print(f"[yellow]Redacted {n} string(s) in evidence/remediation.[/yellow]")
        except Exception:  # noqa: BLE001
            pass

    # Items #40 + #41 — apply per-site policy (severity overrides + suppressions)
    # BEFORE the console render so what the user sees matches what the
    # reporters write.
    try:
        from . import policy as _policy
        pol = _policy.load()
        if pol and not pol.get("_error"):
            n_overrides = _policy.apply_severity_overrides(report, pol)
            n_rules = _policy.apply_severity_rules(report, pol)
            n_suppressed = _policy.apply_suppressions(report, pol)
            if (n_overrides or n_rules or n_suppressed) and not args.no_console:
                console.print(
                    f"[yellow]Policy applied: "
                    f"{n_overrides} severity override(s), "
                    f"{n_rules} boolean-rule mutation(s), "
                    f"{n_suppressed} finding(s) suppressed.[/yellow]"
                )
        elif pol.get("_error") and not args.no_console:
            console.print(f"[yellow]policy.yml: {pol['_error']}[/yellow]")
    except Exception:  # noqa: BLE001 — policy failures must not break the scan
        pass

    if not args.no_console:
        console_reporter.render(report, console)

    # FEAT-010: --ai-explain-for {client,dev,exec} attaches plain-English
    # rewrites to high+critical findings before any reporter renders.
    if getattr(args, "ai_explain_for", None):
        try:
            from . import ai_assist as _ai
            n = _ai.client_summarize_report(report, audience=args.ai_explain_for)
            if not args.no_console:
                if n:
                    console.print(f"[green]✓[/green] AI explainer ({args.ai_explain_for}): "
                                   f"rewrote {n} finding(s) into plain English")
                else:
                    console.print("[yellow]Note: --ai-explain-for produced no summaries "
                                   "(no LLM backend configured, or no high-severity findings).[/yellow]")
        except Exception:  # noqa: BLE001 — AI is opt-in, must never break a scan
            pass

    out_dir = _outdir(args.out)
    stem = _stem(target, args.out)
    html_path: str | None = None

    # --dashboard needs per-site HTML files to link to. If the user also
    # passed --json-only, prefer the dashboard link over the JSON-only intent.
    if args.json_only and args.dashboard and not args.no_console:
        console.print("[yellow]Note: --dashboard requires per-site HTML files; --json-only is being overridden for HTML output.[/yellow]")
    want_html = (not args.json_only) or args.dashboard
    if want_html:
        html_p = out_dir / f"{stem}.html"
        html_reporter.write(report, html_p)
        html_path = html_p.name
        if not args.no_console:
            console.print(f"[green]✓[/green] HTML report: [bold]{html_p}[/bold]")

    if not args.html_only:
        json_p = out_dir / f"{stem}.json"
        json_reporter.write(report, json_p)
        if not args.no_console:
            console.print(f"[green]✓[/green] JSON report: [bold]{json_p}[/bold]")

    # Persist a timestamped snapshot under ~/.wpsecscan/reports/ so
    # `wpsecscan compare URL` and the GUI trend window can find prior scans.
    # Previously only the GUI called this — CLI users found `compare` always
    # reported "0 saved snapshots".
    try:
        from . import history as _history_mod
        _history_mod.save_report_snapshot(target, json_reporter.render(report))
    except Exception:  # noqa: BLE001  — snapshot persistence must never break the scan
        pass

    if args.csv:
        csv_p = out_dir / f"{stem}.csv"
        csv_reporter.write(report, csv_p)
        if not args.no_console:
            console.print(f"[green]✓[/green] CSV report: [bold]{csv_p}[/bold]")

    if args.sarif:
        sf = out_dir / f"{stem}.sarif"
        sarif_reporter.write(report, sf)
        if not args.no_console:
            console.print(f"[green]✓[/green] SARIF report: [bold]{sf}[/bold]")

    if args.md:
        md_p = out_dir / f"{stem}.md"
        md_reporter.write(report, md_p, top_n=args.md_top)
        if not args.no_console:
            console.print(f"[green]✓[/green] Markdown report: [bold]{md_p}[/bold]")

    if args.xlsx:
        xlsx_p = out_dir / f"{stem}.xlsx"
        xlsx_reporter.write(report, xlsx_p)
        if not args.no_console:
            console.print(f"[green]✓[/green] Excel report: [bold]{xlsx_p}[/bold]")

    if getattr(args, "burp_export", False):
        from .reporters import burp_export as _burp
        burp_p = out_dir / f"{stem}-burp-scope.xml"
        _burp.write(report, burp_p)
        if not args.no_console:
            console.print(f"[green]✓[/green] Burp Suite scope: [bold]{burp_p}[/bold]")

    if getattr(args, "exec_pdf", False):
        from .reporters import exec_pdf as _epdf
        pdf_p = out_dir / f"{stem}-exec.pdf"
        _epdf.write(report, pdf_p)
        # If reportlab wasn't available, exec_pdf falls back to .html
        actual = pdf_p if pdf_p.exists() else pdf_p.with_suffix(".html")
        if not args.no_console:
            console.print(f"[green]✓[/green] Executive summary: [bold]{actual}[/bold]")

    if getattr(args, "docx", False):
        from .reporters import docx_report as _dx
        docx_p = out_dir / f"{stem}.docx"
        _dx.write(report, docx_p)
        actual = docx_p if docx_p.exists() else docx_p.with_suffix(".rtf")
        if not args.no_console:
            console.print(f"[green]✓[/green] Word-compatible report: [bold]{actual}[/bold]")

    # #50 — auditor PDF with full evidence chains
    if getattr(args, "auditor_pdf", False):
        from .reporters import auditor_pdf as _ap
        ap_p = out_dir / f"{stem}-auditor.pdf"
        _ap.write(report, ap_p)
        actual = ap_p if ap_p.exists() else ap_p.with_suffix(".html")
        if not args.no_console:
            console.print(f"[green]✓[/green] Auditor report (full evidence): [bold]{actual}[/bold]")

    # #51 — SOC2 / ISO compliance-attestation matrix
    if getattr(args, "soc2_attestation", False):
        from .reporters import compliance_attestation as _ca
        ca_p = out_dir / f"{stem}-compliance-attestation.html"
        _ca.write(report, ca_p)
        if not args.no_console:
            console.print(f"[green]✓[/green] Compliance attestation matrix: [bold]{ca_p}[/bold]")

    # #52 — board-room 1-page dashboard
    if getattr(args, "board_1pager", False):
        from .reporters import board_one_pager as _bp
        bp_p = out_dir / f"{stem}-board.html"
        _bp.write(report, bp_p)
        if not args.no_console:
            console.print(f"[green]✓[/green] Board 1-pager: [bold]{bp_p}[/bold]")

    # #61 — live SIEM forwarders (Splunk HEC / Datadog Logs / Loki / Beats)
    if (getattr(args, "siem_splunk", None) or getattr(args, "siem_datadog", None)
            or getattr(args, "siem_loki", None) or getattr(args, "siem_beats", None)
            or os.environ.get("WPSECSCAN_SPLUNK_HEC")
            or os.environ.get("WPSECSCAN_DATADOG_API_KEY")
            or os.environ.get("WPSECSCAN_LOKI_URL")
            or os.environ.get("WPSECSCAN_BEATS_URL")):
        try:
            from . import siem as _siem
            for msg in _siem.forward_all(report, args):
                if not args.no_console:
                    console.print(f"[cyan]SIEM[/cyan] {msg}")
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]SIEM forward failed: {e}[/yellow]")

    # #54 — user-supplied Jinja2 template
    if getattr(args, "report_template", None):
        try:
            from .reporters import user_template as _ut
            tpl_path = Path(args.report_template).expanduser()
            ut_p = out_dir / f"{stem}-branded.html"
            _ut.write(report, tpl_path, ut_p)
            if not args.no_console:
                console.print(f"[green]✓[/green] Branded report (custom template): [bold]{ut_p}[/bold]")
        except (FileNotFoundError, OSError, Exception) as e:  # noqa: BLE001
            console.print(f"[yellow]--report-template failed: {e}[/yellow]")

    # N40 attestation
    if getattr(args, "attestation", None):
        from .reporters import attestation as _att
        att_p = out_dir / args.attestation if not Path(args.attestation).is_absolute() else Path(args.attestation)
        _att.write(report, att_p,
                    vendor=args.attestation_vendor or "WPSecScan",
                    customer=args.attestation_customer)
        actual = att_p if att_p.exists() else att_p.with_suffix(".html")
        if not args.no_console:
            console.print(f"[green]✓[/green] Attestation: [bold]{actual}[/bold]")

    # N41 auto-PR
    if getattr(args, "auto_pr", False) and getattr(args, "auto_pr_repo", None):
        from . import auto_pr as _ap
        pr_p = out_dir / f"{stem}-auto-pr.sh"
        _ap.write_script(report, pr_p, repo=args.auto_pr_repo)
        if not args.no_console:
            console.print(f"[green]✓[/green] Auto-PR script (review before running): [bold]{pr_p}[/bold]")

    # #35 — direct issue-tracker push with idempotency cache.
    push_results: list[tuple[str, list[dict]]] = []
    if getattr(args, "push_jira", None):
        try:
            base, project, email = [s.strip() for s in args.push_jira.split(",", 2)]
            from . import issue_push as _ip
            from .reporters.issue_export import jira_payloads
            payloads = jira_payloads(report, project, getattr(args, "push_min_sev", "high"))
            push_results.append(("jira", _ip.push_jira(target, payloads,
                                                          base_url=base, email=email)))
        except (ValueError, Exception) as e:  # noqa: BLE001
            console.print(f"[yellow]--push-jira failed: {e}[/yellow]")
    if getattr(args, "push_linear", None):
        try:
            from . import issue_push as _ip
            from .reporters.issue_export import linear_payloads
            payloads = linear_payloads(report, args.push_linear, getattr(args, "push_min_sev", "high"))
            push_results.append(("linear", _ip.push_linear(target, payloads)))
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]--push-linear failed: {e}[/yellow]")
    if getattr(args, "push_servicenow", None):
        try:
            from . import issue_push as _ip
            payloads = _ip.servicenow_payloads(report, getattr(args, "push_min_sev", "high"))
            push_results.append(("servicenow", _ip.push_servicenow(target, payloads,
                                                                       instance=args.push_servicenow)))
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]--push-servicenow failed: {e}[/yellow]")
    if getattr(args, "push_github", None):
        try:
            from . import issue_push as _ip
            from .reporters.issue_export import github_payloads
            payloads = github_payloads(report, getattr(args, "push_min_sev", "high"))
            push_results.append(("github", _ip.push_github(target, payloads,
                                                              repo=args.push_github)))
        except Exception as e:  # noqa: BLE001
            console.print(f"[yellow]--push-github failed: {e}[/yellow]")
    # Item #67 — Redmine / Bugzilla / Trac (all re-use the github_payloads
    # shape — title + body — so the title/body templates stay consistent
    # across trackers.)
    if getattr(args, "push_redmine", None):
        try:
            base, project_id = [s.strip() for s in args.push_redmine.split(",", 1)]
            from . import issue_push as _ip
            from .reporters.issue_export import github_payloads
            payloads = github_payloads(report, getattr(args, "push_min_sev", "high"))
            push_results.append(("redmine", _ip.push_redmine(target, payloads,
                                                                base_url=base,
                                                                project_id=project_id)))
        except (ValueError, Exception) as e:  # noqa: BLE001
            console.print(f"[yellow]--push-redmine failed: {e}[/yellow]")
    if getattr(args, "push_bugzilla", None):
        try:
            base, product, component = [s.strip() for s in args.push_bugzilla.split(",", 2)]
            from . import issue_push as _ip
            from .reporters.issue_export import github_payloads
            payloads = github_payloads(report, getattr(args, "push_min_sev", "high"))
            push_results.append(("bugzilla", _ip.push_bugzilla(target, payloads,
                                                                  base_url=base,
                                                                  product=product,
                                                                  component=component)))
        except (ValueError, Exception) as e:  # noqa: BLE001
            console.print(f"[yellow]--push-bugzilla failed: {e}[/yellow]")
    if getattr(args, "push_trac", None):
        try:
            base, username = [s.strip() for s in args.push_trac.split(",", 1)]
            from . import issue_push as _ip
            from .reporters.issue_export import github_payloads
            payloads = github_payloads(report, getattr(args, "push_min_sev", "high"))
            push_results.append(("trac", _ip.push_trac(target, payloads,
                                                          base_url=base,
                                                          username=username)))
        except (ValueError, Exception) as e:  # noqa: BLE001
            console.print(f"[yellow]--push-trac failed: {e}[/yellow]")
    for system, results in push_results:
        ok = sum(1 for r in results if r.get("ok"))
        skipped = sum(1 for r in results if r.get("skipped"))
        if not args.no_console:
            console.print(f"[green]✓[/green] Pushed to {system}: "
                           f"{ok - skipped} new / {skipped} cached-dedupe / "
                           f"{len(results) - ok} failed")
        # Log first failure body for diagnosis
        for r in results:
            if not r.get("ok"):
                console.print(f"  [yellow]{system} error:[/yellow] {r.get('error', r)}")
                break

    # FEAT-003: --notion-database emits a Notion-API curl script
    if getattr(args, "notion_database", None):
        from .reporters import issue_export as _ix
        notion_p = out_dir / f"{stem}-notion.sh"
        notion_p.write_text(
            "#!/usr/bin/env bash\n"
            f"# WPSecScan → Notion DB ({args.notion_database}). Review before running.\n"
            f"# Required env: NOTION_TOKEN (from notion.so/my-integrations)\n"
            "#\n"
            "# The Notion database must have a title property; default name is 'Name'.\n"
            "# Override with --notion-title-prop if your DB uses a different title column.\n"
            "set -euo pipefail\n\n"
            + "\n\n".join(_ix.notion_curl_commands(
                report,
                args.notion_database,
                title_property=getattr(args, "notion_title_prop", "Name"),
                min_sev=getattr(args, "notion_min_sev", "medium"),
            ))
            + "\n",
            encoding="utf-8",
        )
        if not args.no_console:
            console.print(f"[green]✓[/green] Notion export script (review before running): [bold]{notion_p}[/bold]")

    return console_reporter.exit_code(report, fail_on=args.fail_on), report, html_path


async def _amain(args) -> int:
    console = Console(no_color=args.no_color, legacy_windows=False)

    # J19: opportunistic update check (silent on no-update / on failure)
    if not getattr(args, "no_update_check", False):
        try:
            from . import auto_update as _au
            note = _au.notice(__version__)
            if note and not args.no_console:
                console.print(f"[yellow]Update available:[/yellow] {note}")
        except Exception:  # noqa: BLE001
            pass

    # N39: region-egress warning when WPSECSCAN_REGION is set but no proxy is wired
    try:
        from . import region_egress as _re
        if getattr(args, "region", None):
            import os as _os
            _os.environ["WPSECSCAN_REGION"] = args.region
        warn = _re.warn_if_unenforced()
        if warn and not args.no_console:
            console.print(f"[yellow]Region warning:[/yellow] {warn}")
    except Exception:  # noqa: BLE001
        pass

    # Validate --prove flags before any file I/O
    if args.prove:
        if args.file:
            console.print("[red]--prove is single-target only (refuses to batch). Drop --file.[/red]")
            return 64
        if not args.aggressive:
            console.print("[red]--prove requires --aggressive (proof needs a confirmed finding to act on).[/red]")
            target_hint = args.target or "<URL>"
            console.print(f"[yellow]Hint: try  wpsecscan {target_hint} --aggressive --prove[/yellow]")
            return 64

    targets: list[str] = []
    if args.target:
        targets.append(args.target)
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    if not targets:
        console.print("[red]No target provided. Pass a URL or --file <list.txt>.[/red]")
        return 64

    worst = 0
    all_reports: list = []  # list of (report, html_filename)
    site_concurrency = max(1, int(getattr(args, "site_concurrency", 1) or 1))
    if len(targets) > 1 and site_concurrency > 1:
        # Parallel batch mode. Use a Semaphore so we don't accidentally
        # DDoS a CDN by scanning dozens of sites at once.
        import asyncio as _asyncio
        sem = _asyncio.Semaphore(site_concurrency)
        async def _run_one(tgt: str):
            async with sem:
                try:
                    from . import check_health as _ch
                    _ch.reset_run()
                except ImportError:
                    pass
                return await _scan_one(tgt, args, console)
        if not args.no_console:
            console.print(f"[dim]Batch mode: scanning {len(targets)} sites with concurrency {site_concurrency}[/dim]")
        results = await _asyncio.gather(*[_run_one(t) for t in targets])
        for code, report, html_filename in results:
            worst = max(worst, code)
            if report and html_filename:
                all_reports.append((report, html_filename))
    else:
        for t in targets:
            if len(targets) > 1:
                console.rule(f"[bold cyan]{t}")
            # C2: clear J20/J21 per-scan state so a check auto-disabled on
            # target N doesn't stay disabled for target N+1 in a batch.
            try:
                from . import check_health as _ch
                _ch.reset_run()
            except ImportError:
                pass
            code, report, html_filename = await _scan_one(t, args, console)
            worst = max(worst, code)
            if report and html_filename:
                all_reports.append((report, html_filename))

    if (args.dashboard or args.agency_dashboard) and all_reports:
        out_dir = _outdir(args.out)
        agency_mode = bool(args.agency_dashboard)
        fname = "wpsecscan-agency-dashboard.html" if agency_mode else "wpsecscan-dashboard.html"
        dpath = out_dir / fname
        dashboard_reporter.write(all_reports, dpath, agency=agency_mode)
        if not args.no_console:
            label = "Agency dashboard" if agency_mode else "Batch dashboard"
            console.print(f"[green]✓[/green] {label}: [bold]{dpath}[/bold]")

    # FEAT-019: --diff-since 7d — automatically pick the right historical
    # snapshot from ~/.wpsecscan/reports/{safe}-*.json and use it as the
    # baseline. Composes with normal scan flow.
    if getattr(args, "diff_since", None) and all_reports:
        try:
            from . import history as _hmod
            from .diff import diff_dicts as _diff_dicts2
            import re as _re_dur, json as _j_dur
            from datetime import datetime as _dt_dur, timedelta as _td_dur, timezone as _tz_dur
            m = _re_dur.match(r"^(\d+)([hdw])$", args.diff_since.strip())
            if not m:
                console.print(f"[red]--diff-since: invalid WINDOW '{args.diff_since}' (use e.g. 7d, 24h, 2w)[/red]")
            else:
                qty, unit = int(m.group(1)), m.group(2)
                hours = qty * (1 if unit == "h" else 24 if unit == "d" else 24 * 7)
                cutoff = _dt_dur.now(_tz_dur.utc) - _td_dur(hours=hours)
                # Pick the most recent snapshot OLDER than the cutoff
                target_url = all_reports[-1][0].target
                snaps = _hmod.snapshot_history(target_url)
                older = [p for p in snaps if _dt_dur.fromtimestamp(
                    p.stat().st_mtime, tz=_tz_dur.utc) < cutoff]
                if not older:
                    console.print(f"[yellow]--diff-since {args.diff_since}: no snapshots older than that window for {target_url}[/yellow]")
                else:
                    baseline_path = older[-1]
                    baseline = _j_dur.loads(baseline_path.read_text(encoding="utf-8"))
                    current = json_reporter._enrich(all_reports[-1][0])
                    delta = _diff_dicts2(baseline, current)
                    console.print(f"\n[bold cyan]--- DIFF vs {baseline_path.name} ({args.diff_since} window) ---[/bold cyan]")
                    console.print(f"[red]NEW    ({len(delta['new'])}):[/red]")
                    for f in delta["new"][:30]:
                        console.print(f"  + [{f.get('severity','?').upper()}] {f.get('title','?')[:100]}")
                    console.print(f"[green]RESOLVED ({len(delta['resolved'])}):[/green]")
                    for f in delta["resolved"][:30]:
                        console.print(f"  - [{f.get('severity','?').upper()}] {f.get('title','?')[:100]}")
        except (OSError, ValueError, TypeError) as e:
            console.print(f"[red]--diff-since failed: {e}[/red]")

    # D4: --diff-against — compare the most recent scan against a saved baseline.
    if args.diff_against and all_reports:
        try:
            import json as _j
            from .diff import diff_dicts as _diff_dicts
            baseline = _j.loads(Path(args.diff_against).read_text(encoding="utf-8"))
            current = json_reporter._enrich(all_reports[-1][0])
            delta = _diff_dicts(baseline, current)
            console.print("\n[bold cyan]--- DIFF vs baseline ---[/bold cyan]")
            console.print(f"[red]NEW    ({len(delta['new'])}):[/red]")
            for f in delta["new"][:30]:
                console.print(f"  + [{f.get('severity','?').upper()}] {f.get('title','?')[:100]}")
            if len(delta["new"]) > 30:
                console.print(f"  [dim]... and {len(delta['new']) - 30} more[/dim]")
            console.print(f"[green]RESOLVED ({len(delta['resolved'])}):[/green]")
            for f in delta["resolved"][:30]:
                console.print(f"  - [{f.get('severity','?').upper()}] {f.get('title','?')[:100]}")
            if len(delta["resolved"]) > 30:
                console.print(f"  [dim]... and {len(delta['resolved']) - 30} more[/dim]")
        except (OSError, ValueError, TypeError) as e:
            console.print(f"[red]--diff-against failed: {e}[/red]")

    # L30: --query — print findings matching the filter expression
    if getattr(args, "query", None) and all_reports:
        try:
            from . import report_query as _rq
            results = _rq.query(all_reports[-1][0], args.query)
            console.print(f"\n[bold cyan]--- QUERY '{args.query}' ({len(results)} match) ---[/bold cyan]")
            for r in results[:100]:
                console.print(f"  [{r.get('severity','?').upper()}] {r.get('check_id','?')}: {r.get('title','?')[:100]}")
            if len(results) > 100:
                console.print(f"  [dim]... and {len(results) - 100} more match(es)[/dim]")
        except (ValueError, Exception) as e:  # noqa: BLE001
            console.print(f"[red]--query failed: {e}[/red]")

    # F1: --shell — drop into a Python REPL with the last scan loaded.
    if args.shell and all_reports:
        import code
        report = all_reports[-1][0]
        banner = (
            "\n=== WPSecScan interactive shell ===\n"
            f"report = ScanReport for {report.target}, {len(report.results)} check results\n"
            "Try: report.summary  |  report.risk_score  |  "
            "[f for r in report.results for f in r.findings if f.severity=='high']\n"
        )
        code.interact(banner=banner, local={"report": report, "wpsecscan": __import__("wpsecscan")})

    return worst


def _apply_config_and_profile(parser, args) -> None:
    """#33 + #34 — merge values from --config FILE and --profile NAME into
    args. CLI-explicit values always win: we only set attributes that are
    still at the argparse default.

    Precedence (lowest → highest):
      1. argparse defaults
      2. --profile NAME values (from ~/.wpsecscan/profiles.json)
      3. --config FILE values (YAML / TOML / JSON)
      4. CLI-explicit flags
    """
    # Build a default-args namespace to compare against.
    defaults = parser.parse_args([])  # all defaults
    merged: dict = {}

    if getattr(args, "profile", None):
        try:
            from . import history as _h
            profiles = _h.load_profiles()
            p = profiles.get(args.profile)
            if not p:
                print(f"profile not found: {args.profile!r}", file=sys.stderr)
                print(f"available: {', '.join(sorted(profiles.keys())) or '(none)'}", file=sys.stderr)
                sys.exit(2)
            merged.update(p)
        except Exception as e:  # noqa: BLE001
            print(f"--profile load failed: {e}", file=sys.stderr)
            sys.exit(2)

    if getattr(args, "config", None):
        try:
            from pathlib import Path
            cfg_path = Path(args.config)
            if not cfg_path.exists():
                print(f"--config: file not found: {cfg_path}", file=sys.stderr)
                sys.exit(2)
            text = cfg_path.read_text(encoding="utf-8")
            data: dict = {}
            ext = cfg_path.suffix.lower()
            if ext in (".yml", ".yaml"):
                try:
                    import yaml  # type: ignore[import-not-found]
                    data = yaml.safe_load(text) or {}
                except ImportError:
                    print("--config: .yml needs pyyaml installed (pip install wpsecscan[yaml])",
                          file=sys.stderr)
                    sys.exit(2)
            elif ext == ".toml":
                try:
                    import tomllib  # type: ignore[import-not-found]
                except ImportError:
                    import tomli as tomllib  # type: ignore[import-not-found]
                data = tomllib.loads(text)
            elif ext == ".json":
                import json as _json
                data = _json.loads(text)
            else:
                print(f"--config: unsupported extension {ext} (use .yml/.yaml/.toml/.json)",
                      file=sys.stderr)
                sys.exit(2)
            if not isinstance(data, dict):
                print(f"--config: top-level must be a mapping/dict", file=sys.stderr)
                sys.exit(2)
            merged.update(data)
        except Exception as e:  # noqa: BLE001
            print(f"--config load failed: {e}", file=sys.stderr)
            sys.exit(2)

    if not merged:
        return

    # Apply merged values to args attributes — only when the current
    # attribute equals the argparse default (i.e. user didn't override
    # on the CLI).
    for key, value in merged.items():
        # argparse turns `--auth-user` into `auth_user`; accept both forms.
        attr = key.replace("-", "_")
        if not hasattr(args, attr):
            continue
        if getattr(args, attr, None) == getattr(defaults, attr, None):
            setattr(args, attr, value)


def main() -> None:
    # ---- Subcommand dispatch (round-60): keep before argparse so existing
    # `wpsecscan <url>` invocations stay backward-compatible.
    if len(sys.argv) >= 2 and sys.argv[1] in (
        "sites", "schedule", "digest", "ai-cost", "db", "ai-options", "analytics",
        "compare", "badge", "paths", "report", "annotate", "check", "config",
        "verify-release", "watch", "portfolio", "refix", "snooze", "diff-tree",
        "pr-comment", "publish", "only", "doctor",
    ):
        _dispatch_subcommand(sys.argv[1], sys.argv[2:])
        return

    p = argparse.ArgumentParser(
        prog="wpsecscan",
        description=(
            "WPSecScan — defensive WordPress security scanner. "
            "Use only on sites you own or have written permission to test."
        ),
        epilog=(
            "Subcommands (use as: wpsecscan <subcommand> <args>):\n"
            "  sites          manage a list of sites (add | list | scan | remove)\n"
            "  schedule       install/uninstall scheduled scans (Windows Task Scheduler etc.)\n"
            "  digest         configure SMTP / webhook digest of new findings\n"
            "  ai-cost        print AI-triage cost summary\n"
            "  ai-options     read/set Advanced AI-triage toggles\n"
            "  analytics      manage opt-in usage analytics\n"
            "  db             vuln DB management (status | update | signatures | source-stats | subscribe | alert-check)\n"
            "  compare URL    diff the two most-recent saved snapshots of URL\n"
            "  badge URL      emit a shields.io-style status-badge SVG\n"
            "\nRun  wpsecscan <subcommand> --help  for per-subcommand usage.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="URL to scan (e.g. https://example.com)")
    p.add_argument("--file", help="File containing URLs, one per line (# comments OK)")
    p.add_argument("--out", help="Output directory or filename stem")
    # #33: load every flag from a YAML/TOML config file. Operator can keep
    # site-specific arg sets on disk instead of repeating long command lines.
    p.add_argument("--config", default=None, metavar="FILE",
                   help="#33: load flags from a YAML or TOML config file. CLI args still override.")
    # #34: load a named profile from ~/.wpsecscan/profiles.json (same
    # storage the GUI uses for File → Save current settings as profile).
    p.add_argument("--profile", default=None, metavar="NAME",
                   help="#34: load a named profile saved via the GUI or wpsecscan profile save.")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout seconds (default 15)")
    p.add_argument("--concurrency", type=int, default=10, help="Concurrent requests per host (default 10)")
    p.add_argument("--user-agent", default=f"WPSecScan/{__version__} (+defensive-recon)", help="HTTP User-Agent")

    p.add_argument("--wpscan-token", default=os.environ.get("WPSECSCAN_WPSCAN_TOKEN"),
                   help="WPScan API token (env: WPSECSCAN_WPSCAN_TOKEN)")
    p.add_argument("--patchstack-token", default=os.environ.get("WPSECSCAN_PATCHSTACK_TOKEN"),
                   help="Patchstack API token (env: WPSECSCAN_PATCHSTACK_TOKEN) — merges Patchstack CVE data into the vuln DB on --update-db")
    p.add_argument("--hibp-token", default=os.environ.get("WPSECSCAN_HIBP_TOKEN"),
                   help="HaveIBeenPwned API key (env: WPSECSCAN_HIBP_TOKEN). Otherwise we emit manual-check links.")
    p.add_argument("--deep-throttle", action="store_true", help="Run the deep throttle mapping (N wrong-password attempts for a synthetic non-existent user). Reports the actual rate-limit threshold.")
    p.add_argument("--deep-throttle-attempts", type=int, default=120, metavar="N", help="How many wrong-login attempts the deep throttle test sends (10-500, default 120). Multiply by --deep-throttle-pacing for total runtime.")
    p.add_argument("--deep-throttle-pacing", type=float, default=10.0, metavar="SECONDS", help="Seconds between deep-throttle attempts (5-60, default 10). Below 5s tends to trip network-layer fail2ban before HTTP-layer throttling shows.")
    p.add_argument("--aggressive", "-A", action="store_true", help="Enable active checks: SQLi, XSS, SSRF, path traversal, open redirect, upload probes, default-credentials probe (≤10 attempts).")
    p.add_argument("--prove", "-P", action="store_true", help="For each confirmed aggressive finding, run a read-only proof helper (single-target only; requires --aggressive). Never writes to the target.")
    # Sensitive flags read from env vars when not given on the command line —
    # use env to avoid leaking secrets via `ps aux` / shell history.
    p.add_argument("--auth-user", default=os.environ.get("WPSECSCAN_AUTH_USER"),
                    help="Admin username (env: WPSECSCAN_AUTH_USER)")
    p.add_argument("--auth-pass", default=os.environ.get("WPSECSCAN_AUTH_PASS"),
                    help="Admin password (env: WPSECSCAN_AUTH_PASS). Use `-` to read from stdin via getpass.")
    p.add_argument("--auth-app-password", default=os.environ.get("WPSECSCAN_AUTH_APP_PASSWORD"),
                    help="WP Application Password (env: WPSECSCAN_AUTH_APP_PASSWORD). Spaces are stripped.")
    p.add_argument("--auth-totp", default=os.environ.get("WPSECSCAN_AUTH_TOTP"),
                    help="6-digit TOTP code (env: WPSECSCAN_AUTH_TOTP).")
    p.add_argument("--companion-token", default=os.environ.get("WPSECSCAN_COMPANION_TOKEN"),
                    help="One-time companion plugin token (env: WPSECSCAN_COMPANION_TOKEN).")
    p.add_argument("--proxy", default=None,
                    help="Proxy URL — http://, https://, or socks5:// (also reads WPSECSCAN_PROXY_URL / HTTP_PROXY env vars).")
    p.add_argument("--proxy-auth", default=os.environ.get("WPSECSCAN_PROXY_AUTH"),
                    help="Optional 'user:pass' for the proxy (env: WPSECSCAN_PROXY_AUTH). Injected into the URL; password is URL-encoded.")
    p.add_argument("--ssh-audit", default=None, metavar="user@host", help="Connect via ssh and run a read-only wp-cli audit (uses system ssh client, BatchMode=yes).")
    p.add_argument("--password-audit", default=None, metavar="WP_USERS.csv", help="Offline: read a CSV or SQL dump of wp_users and emit a hashcat-ready file. NO network calls.")

    p.add_argument("--insecure", action="store_true", help="Don't verify TLS certs")
    # --quiet / -q is the conventional name; --no-console is kept for back-compat.
    p.add_argument("--quiet", "-q", "--no-console", dest="no_console", action="store_true",
                   help="Suppress console output (still writes report files)")
    p.add_argument("-v", "--verbose", action="count", default=0,
                   help="Increase console verbosity (-v shows per-check progress, -vv shows HTTP-level detail). "
                        "Independent of --debug (which writes a log file).")
    p.add_argument("--no-color", action="store_true", help="Disable colored console output")

    p.add_argument("--csv", action="store_true", help="Also write CSV report (formula-injection neutralised)")
    p.add_argument("--sarif", action="store_true", help="Also write SARIF 2.1.0 report")
    p.add_argument("--md", action="store_true", help="Also write a Markdown report (handy for tickets / PRs / Slack)")
    p.add_argument("--md-top", type=int, default=None, metavar="N",
                   help="Truncate the Markdown report to the top-N findings by severity "
                        "(useful for Slack/Discord's 4000-char message limit).")
    p.add_argument("--xlsx", action="store_true", help="Also write an Excel workbook with per-OWASP-category sheets")
    p.add_argument("--har", default=None, metavar="HAR_FILE", help="Record every HTTP request/response into a HAR file for debugging or replay")
    p.add_argument("--parallel-groups", action="store_true",
                   help="Run within-group checks concurrently (~30%% faster on typical scans; default sequential). "
                        "Warning: concurrent same-host requests may trigger WAF rate-limits on strict hosts.")
    p.add_argument("--site-concurrency", type=int, default=1, metavar="N",
                   help="When scanning multiple sites via --file, run up to N in parallel (default 1 = serial). "
                        "Each site still uses --concurrency per-host. Trade off throughput against being a polite neighbour.")
    p.add_argument("--dry-run", action="store_true",
                   help="Validate config + print the list of checks that would run against the target, then exit. "
                        "Does not perform any HTTP requests; safe to run against any URL.")
    p.add_argument("--continuous", action="store_true",
                   help="FEAT-036: poll the companion plugin's /file-monitor endpoint and "
                        "report any file changes on plugin/theme directories. Requires "
                        "--companion-token. Use --interval N to control polling cadence.")
    p.add_argument("--interval", type=int, default=300, metavar="SECONDS",
                   help="Polling interval for --continuous mode (default 300 = 5 minutes).")
    p.add_argument("--checkpoint", action="store_true", help="Save progress to ~/.wpsecscan/checkpoints/ so a Ctrl+C scan can resume on next run")
    p.add_argument("--fail-on", "-F", default=None, metavar="LEVEL[,LEVEL]",
                   help="Exit with code 2 if any finding is at or above this severity. "
                        "Accepts a single value (critical|high|medium|low) or comma-separated list, "
                        "e.g. `critical,high`. Overrides the default exit-code logic.")
    # #36: --format consolidation. Repeatable; replaces (and supplements)
    # the separate --json-only / --csv / --md / etc. flags.
    p.add_argument("--format", default=None, action="append", metavar="FORMAT",
                   help="#36: emit specific report format(s). Repeat or "
                        "comma-separate: --format json,html,sarif. Supported: "
                        "json,html,csv,md,xlsx,sarif,burp,docx,exec-pdf. "
                        "Aliases the legacy --json-only / --csv / etc. flags.")
    p.add_argument("--abuseipdb-token", default=os.environ.get("WPSECSCAN_ABUSEIPDB_TOKEN"),
                   help="AbuseIPDB API token (env: WPSECSCAN_ABUSEIPDB_TOKEN). Free tier: 1000/day.")
    p.add_argument("--vt-token", default=os.environ.get("WPSECSCAN_VT_TOKEN"),
                   help="VirusTotal API key (env: WPSECSCAN_VT_TOKEN). Free tier: 4 req/min.")
    p.add_argument("--github-search-token", default=os.environ.get("WPSECSCAN_GITHUB_SEARCH_TOKEN"),
                   help="GitHub PAT (env: WPSECSCAN_GITHUB_SEARCH_TOKEN, public_repo scope) for the leaked-token search check")
    # --baseline is the clearer name; --diff-against kept for back-compat
    # (and to distinguish from --diff which compares two arbitrary files).
    p.add_argument("--baseline", "--diff-against", dest="diff_against", default=None, metavar="BASELINE.json",
                   help="After scan, compute diff vs a saved JSON baseline and emit NEW/RESOLVED to stdout")
    p.add_argument("--shell", action="store_true", help="After scan, drop into an interactive Python REPL with `report`, `client`, `ctx` pre-bound (for power users)")
    p.add_argument("--replay-har", default=None, metavar="HAR_FILE", help="F2: replay every request from a previously-recorded HAR file (use --target to override the origin). Prints per-request status + body-size delta.")
    # ---- Round-55 CLI additions ----
    p.add_argument("--api-server", default=None, metavar="HOST:PORT", help="M34: run the HTTP API server instead of a scan, e.g. 127.0.0.1:8765. Requires --api-token or WPSECSCAN_API_TOKEN.")
    p.add_argument("--api-token",  default=None, help="M34: bearer token for the --api-server endpoints. Or set WPSECSCAN_API_TOKEN env.")
    p.add_argument("--region",     default=None, help="N39: region tag for compliance-aware egress (resolved via WPSECSCAN_PROXY_<REGION> env).")
    p.add_argument("--sbom",       default=None, metavar="OUT.json", help="J23: write a CycloneDX 1.5 SBOM and exit (no scan).")
    p.add_argument("--attestation", default=None, metavar="OUT.pdf", help="N40: write a customer-facing attestation PDF after the scan.")
    p.add_argument("--attestation-vendor",   default="WPSecScan", help="Vendor name in the attestation header.")
    p.add_argument("--attestation-customer", default=None, help="Customer name in the attestation header.")
    p.add_argument("--auto-pr", action="store_true", help="N41: after scan, write a shell script of `gh pr create` commands with conservative fixes.")
    p.add_argument("--auto-pr-repo", default=None, metavar="OWNER/NAME", help="Target repo for --auto-pr commands.")
    # FEAT-003: Notion export
    # #35 — direct REST push to issue trackers with idempotency keys.
    p.add_argument("--push-jira", default=None, metavar="BASE_URL,PROJECT,EMAIL",
                   help="#35: POST findings to Jira REST. Comma-separated 'https://you.atlassian.net,SEC,you@example.com'. Token via $JIRA_API_TOKEN.")
    p.add_argument("--push-linear", default=None, metavar="TEAM_ID",
                   help="#35: POST findings to Linear GraphQL. Token via $LINEAR_API_KEY.")
    p.add_argument("--push-servicenow", default=None, metavar="INSTANCE_HOST",
                   help="#35: POST findings to ServiceNow incident table. Auth via $SERVICENOW_USERNAME / $SERVICENOW_PASSWORD.")
    p.add_argument("--push-github", default=None, metavar="OWNER/REPO",
                   help="#35: POST findings to a GitHub Issues repo. Token via $GITHUB_TOKEN.")
    # Item #67 — Redmine / Bugzilla / Trac push
    p.add_argument("--push-redmine", default=None, metavar="BASE_URL,PROJECT_ID",
                   help="#67: POST findings to Redmine. Token via $REDMINE_API_KEY.")
    p.add_argument("--push-bugzilla", default=None, metavar="BASE_URL,PRODUCT,COMPONENT",
                   help="#67: POST findings to Bugzilla via REST 5.0. Token via $BUGZILLA_API_KEY.")
    p.add_argument("--push-trac", default=None, metavar="BASE_URL,USERNAME",
                   help="#67: POST findings to Trac via XML-RPC plugin. Password via $TRAC_PASSWORD.")
    p.add_argument("--push-min-sev", default="high", metavar="SEV",
                   help="Lowest severity to push to issue trackers (default: high).")
    p.add_argument("--notion-database", default=None, metavar="DATABASE_ID",
                   help="FEAT-003: also write a Notion-API curl script that creates one page per "
                        "above-threshold finding in the given Notion database. Token via $NOTION_TOKEN.")
    p.add_argument("--notion-title-prop", default="Name", metavar="NAME",
                   help="Title column name in the Notion DB (default: 'Name'; Notion's default).")
    p.add_argument("--notion-min-sev", default="medium", metavar="SEV",
                   help="Lowest severity to export to Notion (default: medium).")
    p.add_argument("--query", default=None, metavar="EXPR", help="L30: after scan, print only findings matching the GraphQL-style filter expression.")
    p.add_argument("--since", default=None, metavar="YYYY-MM-DD", help="K26: incremental mode; skip low-churn checks for targets whose snapshot is newer than this date.")
    p.add_argument("--completion", default=None, choices=["bash", "zsh", "powershell"], help="O47: print a shell completion script and exit.")
    p.add_argument("--no-update-check", action="store_true", help="J19: skip the GitHub-releases update check at startup.")
    # Round-56 visibility upgrade
    p.add_argument("--demo", action="store_true", help="Round-56: synthetic scan against a fake target so you can see every feature working without scanning a real site. Writes all artifacts to ~/.wpsecscan/demo/.")
    p.add_argument("--no-live", action="store_true", help="Disable the live multi-panel dashboard during scans (falls back to the static console reporter).")
    p.add_argument("--burp-export", action="store_true", help="Also write a Burp Suite scope XML for handoff to manual deep-testing")
    p.add_argument("--exec-pdf", action="store_true", help="Also write a one-page executive summary PDF (uses reportlab if installed; otherwise an HTML print-to-PDF fallback)")
    p.add_argument("--docx", action="store_true", help="#48: also write a Word-compatible report. Uses python-docx when installed; falls back to .rtf otherwise.")
    # #50 + #51 — full-evidence auditor PDF + SOC2/ISO attestation matrix
    p.add_argument("--auditor-pdf", action="store_true",
                   help="#50: also write a verbose 'auditor' PDF with every finding's "
                        "raw evidence + remediation + extra fields. Useful as legal/contractual "
                        "evidence. Uses reportlab when installed; HTML fallback otherwise.")
    p.add_argument("--soc2-attestation", action="store_true",
                   help="#51: write a printable compliance-attestation matrix mapping every "
                        "check that ran to its controls across 8 frameworks (PCI/NIST/ISO/NIST-CSF/"
                        "CIS/HITRUST/CMMC).")
    p.add_argument("--board-1pager", action="store_true",
                   help="#52: write a single-landscape-page board-room risk dashboard "
                        "(three big numbers, three sentences, three actions to ratify).")
    p.add_argument("--print-openapi", action="store_true",
                   help="#53: print the OpenAPI 3.1 schema for the WPSecScan JSON output to "
                        "stdout, then exit. Pipe to openapi-typescript / openapi-generator to "
                        "build typed SDKs.")
    p.add_argument("--report-template", default=None, metavar="TEMPLATE.html.j2",
                   help="#54: render a user-supplied Jinja2 template (lets agencies fully "
                        "white-label the output). Receives `report`, `summary`, `findings`, "
                        "`results`, `target`, `scanned_at`, `risk_score`, `worst`, `now`.")
    # #61 — live SIEM forwarders
    p.add_argument("--siem-splunk", default=None, metavar="HEC_URL",
                   help="#61: Splunk HEC URL (e.g. https://splunk.example.com:8088). "
                        "Pair with --siem-splunk-token; or set WPSECSCAN_SPLUNK_HEC + "
                        "WPSECSCAN_SPLUNK_TOKEN.")
    p.add_argument("--siem-splunk-token", default=None, metavar="TOKEN",
                   help="#61: HEC token for --siem-splunk (or WPSECSCAN_SPLUNK_TOKEN).")
    p.add_argument("--siem-datadog", default=None, metavar="API_KEY",
                   help="#61: Datadog API key for Logs HTTP intake (or WPSECSCAN_DATADOG_API_KEY).")
    p.add_argument("--siem-loki", default=None, metavar="PUSH_URL",
                   help="#61: Grafana Loki /loki/api/v1/push URL (or WPSECSCAN_LOKI_URL).")
    p.add_argument("--siem-beats", default=None, metavar="HTTP_INPUT_URL",
                   help="#61: Logstash HTTP input URL (or WPSECSCAN_BEATS_URL).")
    p.add_argument("--redact-evidence", action="store_true",
                   help="#61: mask JWTs / session cookies / bearer tokens / PII in finding evidence before any reporter writes. Recommended when sharing reports externally.")
    p.add_argument("--diff-html", nargs=2, metavar=("OLD.json", "NEW.json"),
                   help="#46: render a side-by-side HTML comparison of two snapshots of the SAME site, then exit.")
    p.add_argument("--daemon", default=None, metavar="CONFIG.yml", help="Run as a daemon: schedule scans via cron-style config (see SDK.md)")
    p.add_argument("--dashboard", action="store_true", help="When scanning multiple sites, also write a batch dashboard")
    p.add_argument("--agency-dashboard", action="store_true",
                   help="FEAT-015: write an agency-style dashboard with per-site risk-score sparklines + "
                        "Δ-vs-prior + brand.json header. Designed to be printed to PDF and handed to a "
                        "non-technical client as a monthly posture summary. Implies --dashboard.")
    p.add_argument("--ai-explain-for", default=None, choices=["client", "dev", "exec"],
                   metavar="AUDIENCE",
                   help="FEAT-010: after the scan, ask the configured LLM (OpenAI/Anthropic/Ollama) "
                        "to rewrite each high+critical finding into plain-English text for the given "
                        "audience and store it under finding.extra.client_summary. Costs ~25 LLM "
                        "calls per scan. Requires WPSECSCAN_OPENAI_API_KEY / ANTHROPIC_API_KEY / "
                        "WPSECSCAN_OLLAMA_URL.")
    format_group = p.add_mutually_exclusive_group()
    format_group.add_argument("--json-only", action="store_true", help="Write JSON only (no HTML)")
    format_group.add_argument("--html-only", action="store_true", help="Write HTML only (no JSON)")

    p.add_argument("--update-db", action="store_true", help="Download the Wordfence Intelligence vulnerability database and exit")
    p.add_argument("--diff", nargs=2, metavar=("OLD.json", "NEW.json"), help="Compare two report JSONs and print the diff, then exit")
    p.add_argument("--diff-since", default=None, metavar="WINDOW",
                   help="Diff scan-in-progress against the most recent saved snapshot older than WINDOW "
                        "(e.g. `7d`, `24h`, `2w`). Composes with the scan; outputs the delta after the scan completes.")
    p.add_argument("--debug", action="store_true", help="Verbose logging to ~/.wpsecscan/logs/")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args()

    # #33 / #34 — merge config file + named profile into args BEFORE any
    # downstream code reads them. CLI args always win over file / profile
    # values: argparse defaults are kept verbatim, and we only inject
    # values into args attributes that are still at their default.
    _apply_config_and_profile(p, args)

    # #36 — expand --format into the legacy single-purpose flags.
    if getattr(args, "format", None):
        # Accept --format json,html OR repeated --format json --format html.
        wanted: set[str] = set()
        for f in args.format:
            for piece in str(f).split(","):
                piece = piece.strip().lower()
                if piece:
                    wanted.add(piece)
        _FORMAT_ALIASES = {
            "json":     ("json_only", True),
            "html":     ("html_only", True),
            "csv":      ("csv",       True),
            "md":       ("md",        True),
            "markdown": ("md",        True),
            "xlsx":     ("xlsx",      True),
            "sarif":    ("sarif",     True),
            "burp":     ("burp_export", True),
            "docx":     ("docx",      True),
            "exec-pdf": ("exec_pdf",  True),
            "pdf":      ("exec_pdf",  True),
        }
        unknown = wanted - set(_FORMAT_ALIASES)
        if unknown:
            print(f"--format: unknown value(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            print(f"valid: {', '.join(sorted(_FORMAT_ALIASES))}", file=sys.stderr)
            sys.exit(2)
        # json + html together = neither --json-only nor --html-only (default).
        if "json" in wanted and "html" in wanted:
            args.json_only = False
            args.html_only = False
            wanted -= {"json", "html"}
        for fmt in wanted:
            attr, val = _FORMAT_ALIASES[fmt]
            setattr(args, attr, val)

    # O47 --completion is checked FIRST — before logging setup, before any
    # I/O — so the stdout output isn't contaminated by debug-log notices
    # when the user pipes it (`wpsecscan --completion bash > completions/`).
    if getattr(args, "completion", None):
        from .completion import generate
        print(generate(args.completion))
        sys.exit(0)

    # #53 — dump OpenAPI schema and exit. Early, before I/O setup, so the
    # operator can `wpsecscan --print-openapi > spec.json` cleanly.
    if getattr(args, "print_openapi", False):
        spec = Path(__file__).parent / "data" / "openapi-scan-report.json"
        sys.stdout.write(spec.read_text(encoding="utf-8"))
        sys.exit(0)

    # Read --auth-pass from stdin when the user passes `-`. Stops the
    # password showing up in `ps aux` / shell history. Extracted to a
    # helper so it's directly unit-testable.
    if args.auth_pass == "-":
        args.auth_pass = _read_auth_pass_from_stdin()

    # --timeout below 5s reliably causes false-positive timeout findings
    # (TLS handshake alone can take 1-2s; a slow plugin can take 3s).
    if args.timeout < 5 and not args.no_console:
        print(f"[warn] --timeout {args.timeout:.1f}s is very short; "
              "expect false-positive timeout findings on real sites.",
              file=sys.stderr)

    # Validate --since at startup so a typo doesn't silently disable
    # incremental mode and leave the user wondering why their scan ran
    # every check. (_parse_since() returns None on invalid input; we
    # now distinguish "not provided" from "provided but unparseable".)
    if getattr(args, "since", None) and _parse_since(args.since) is None:
        print(f"[warn] --since {args.since!r} could not be parsed as YYYY-MM-DD "
              "or ISO 8601 — incremental mode is OFF for this scan.",
              file=sys.stderr)

    log_path = logmod.configure(args.debug)
    if log_path:
        print(f"[debug] log: {log_path}", file=sys.stderr)

    # One-shot modes
    if args.update_db:
        try:
            n, path = vulndb.update_db(verbose=True, patchstack_token=args.patchstack_token or "")
            print(f"OK: {n} vulnerabilities cached at {path}")
            sys.exit(0)
        except Exception as e:  # noqa: BLE001
            print(
                f"\n[!] Could not refresh remote DB: {e}\n"
                f"    The scanner will continue using the embedded fallback CVE database "
                f"(26 well-known WP plugin CVEs).\n"
                f"    As of 2026, the public Wordfence Intelligence endpoint may require an "
                f"account. You can supply --wpscan-token for per-plugin lookups instead.",
                file=sys.stderr,
            )
            # Exit 75 (EX_TEMPFAIL) so CI / update scripts can detect the
            # network-fetch failure. Previously returned 0, hiding the error.
            sys.exit(75)

    if args.diff:
        old, new = args.diff
        d = diff_mod.diff(Path(old), Path(new))
        print(diff_mod.render_text(d))
        sys.exit(0 if not d["new"] else 1)

    if getattr(args, "diff_html", None):
        old, new = args.diff_html
        from .reporters import snapshot_compare as _sc
        out_path = Path(args.out or ".") / "wpsecscan-snapshot-diff.html"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        _sc.write(Path(old), Path(new), out_path)
        print(f"snapshot diff: {out_path}")
        sys.exit(0)

    if args.password_audit:
        try:
            result = pwaudit.audit(Path(args.password_audit))
            print(result["instructions"])
            sys.exit(0)
        except (FileNotFoundError, ValueError) as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    if args.ssh_audit:
        try:
            report = sshaudit.audit(args.ssh_audit)
        except ValueError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(64)
        # Render to console + write reports under cwd or --out
        console = Console(no_color=args.no_color, legacy_windows=False)
        if not args.no_console:
            console_reporter.render(report, console)
        out_dir = _outdir(args.out)
        stem = _stem(f"ssh-{args.ssh_audit.replace('@', '_at_')}", args.out)
        if not args.json_only:
            html_reporter.write(report, out_dir / f"{stem}.html")
        if not args.html_only:
            json_reporter.write(report, out_dir / f"{stem}.json")
        sys.exit(console_reporter.exit_code(report))

    # (O47 --completion is handled earlier, before logging setup)

    # J23 --sbom short-circuit
    if getattr(args, "sbom", None):
        from . import sbom as _sbom
        _sbom.write(Path(args.sbom), scanner_version=__version__)
        print(f"SBOM written to {args.sbom}")
        sys.exit(0)

    # M34 --api-server short-circuit
    if getattr(args, "api_server", None):
        from .api_server import serve
        try:
            host, port_s = args.api_server.split(":", 1)
            port = int(port_s)
        except ValueError:
            print(f"FATAL: --api-server expects HOST:PORT, got {args.api_server!r}", file=sys.stderr)
            sys.exit(64)
        serve(host=host, port=port, token=getattr(args, "api_token", None))
        sys.exit(0)

    # --continuous monitor mode — long-running poll loop, no scan.
    if getattr(args, "continuous", False):
        if not args.target:
            print("--continuous requires a target URL.", file=sys.stderr)
            sys.exit(64)
        if not args.companion_token:
            print("--continuous requires --companion-token (or WPSECSCAN_COMPANION_TOKEN env var) "
                  "to authenticate against the companion plugin's /file-monitor endpoint.",
                  file=sys.stderr)
            sys.exit(64)
        from . import continuous_monitor as _cm
        try:
            sys.exit(asyncio.run(_cm.run(args.target,
                                          companion_token=args.companion_token,
                                          interval_s=args.interval)))
        except KeyboardInterrupt:
            print("\nContinuous monitor stopped.", file=sys.stderr)
            sys.exit(130)

    # --dry-run short-circuit: print what would happen, exit without HTTP.
    if getattr(args, "dry_run", False):
        target = args.target or (args.file and "<first URL in --file>") or "<URL>"
        from .checks import ALL_CHECKS
        passive = [c for c in ALL_CHECKS if not c[3]]
        aggressive = [c for c in ALL_CHECKS if c[3]]
        print(f"WPSecScan dry-run — would scan: {target}")
        print(f"Output dir:         {_outdir(args.out)}")
        print(f"Timeout:            {args.timeout}s")
        print(f"Per-host concurrency: {args.concurrency}")
        print(f"Site concurrency:   {getattr(args, 'site_concurrency', 1)}")
        print(f"Aggressive payloads: {'ON' if args.aggressive else 'OFF'}")
        print(f"Prove-mode:         {'ON' if args.prove else 'OFF'}")
        auth_summary = "anonymous"
        if args.companion_token: auth_summary = "companion plugin token"
        elif args.auth_user and (args.auth_pass or args.auth_app_password):
            auth_summary = f"as {args.auth_user}"
        print(f"Auth:               {auth_summary}")
        print(f"Proxy:              {args.proxy or '(direct)'}")
        print(f"Reports:            " + ", ".join(filter(None, [
            "HTML" if not args.json_only else None,
            "JSON" if not args.html_only else None,
            "CSV" if args.csv else None,
            "SARIF" if args.sarif else None,
            "Markdown" if args.md else None,
            "XLSX" if args.xlsx else None,
            "exec-PDF" if args.exec_pdf else None,
            "Burp scope" if args.burp_export else None,
            "Attestation" if args.attestation else None,
            "SBOM" if args.sbom else None,
        ])))
        print(f"\nPassive checks ({len(passive)}) would all run:")
        for cid, cname, _fn, _agg in passive[:20]:
            print(f"  {cid:30s} {cname}")
        if len(passive) > 20:
            print(f"  ... and {len(passive) - 20} more")
        if args.aggressive:
            print(f"\nAggressive checks ({len(aggressive)}) would run:")
            for cid, cname, _fn, _agg in aggressive:
                print(f"  {cid:30s} {cname}")
        else:
            print(f"\nAggressive checks ({len(aggressive)}) WOULD NOT run (no --aggressive).")
        print("\nNo HTTP requests have been made. Run without --dry-run to actually scan.")
        sys.exit(0)

    # Round-56 --demo short-circuit: synthetic scan, no HTTP, all artifacts.
    if getattr(args, "demo", False):
        from . import demo as _demo
        from .reporters import console as console_reporter
        console = Console(no_color=args.no_color, legacy_windows=False)
        use_live = (not args.no_console
                    and not getattr(args, "no_live", False)
                    and bool(getattr(console, "is_terminal", False)))
        dash = None
        if use_live:
            try:
                from .console_live import LiveDashboard
                dash = LiveDashboard(console, _demo.DEMO_TARGET, total_checks=len(_demo.DEMO_RESULTS))
                dash.__enter__()
                # Drive a fake on_progress so the live dashboard's findings + counter fill in
                on_prog = dash.on_progress_callback()
                report = _demo.build_demo_report()
                import asyncio as _asyncio
                async def _drive():
                    for cr in report.results:
                        on_prog("start", cr.check_id, cr.check_name, None)
                        await _asyncio.sleep(0.05)
                        on_prog("done", cr.check_id, cr.check_name, cr)
                    # Now drip the activity events
                    for cat, msg in _demo.DEMO_ACTIVITY:
                        from . import activity as _act
                        _act.emit(cat, msg)
                        await _asyncio.sleep(0.05)
                _asyncio.run(_drive())
            finally:
                if dash is not None:
                    try:
                        dash.__exit__(None, None, None)
                    except Exception:  # noqa: BLE001
                        pass
        else:
            report = _demo.run_demo(paced=False)

        # Write every reporter's artifact to ~/.wpsecscan/demo/
        from .history import _home as _h_home
        out_dir = Path(_h_home()) / "demo"
        written = _demo.write_artifacts(report, out_dir)
        if not args.no_console:
            console_reporter.render(report, console)
            console.print()
            console.print(f"[green]✓[/green] Demo artifacts written to: [bold]{out_dir}[/bold]")
            for fmt, p in written.items():
                console.print(f"   · {fmt:12} {p}")
        sys.exit(0)

    # F2: --replay-har short-circuits — replay a HAR file and exit.
    if args.replay_har:
        from .har_replay import replay as _replay
        try:
            results = asyncio.run(_replay(Path(args.replay_har), target_origin=args.target))
        except (OSError, ValueError) as e:
            print(f"FATAL (replay-har): {e}", file=sys.stderr)
            sys.exit(1)
        print(f"Replayed {len(results)} request(s) from {args.replay_har}")
        ok = sum(1 for r in results if r.get("ok"))
        errs = len(results) - ok
        print(f"  {ok} OK, {errs} errors")
        # Print top-line per-request results
        for r in results[:50]:
            req = r.get("request", {})
            line = f"  {req.get('method', '?'):6} {req.get('url', '?')[:80]}"
            if r.get("ok"):
                line += f" -> {r.get('status'):3} ({r.get('body_len', 0)} bytes)"
            else:
                line += f" -> ERROR: {r.get('error', '?')[:60]}"
            print(line)
        if len(results) > 50:
            print(f"  ... and {len(results) - 50} more")
        sys.exit(0 if errs == 0 else 1)

    # D6: daemon mode short-circuits the normal scan flow
    if args.daemon:
        from .daemon import run_daemon
        try:
            asyncio.run(run_daemon(Path(args.daemon)))
            sys.exit(0)
        except KeyboardInterrupt:
            print("\nDaemon stopped.", file=sys.stderr)
            sys.exit(0)
        except Exception as e:  # noqa: BLE001
            print(f"FATAL (daemon): {e}", file=sys.stderr)
            sys.exit(1)

    try:
        code = asyncio.run(_amain(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        code = 130
    except Exception as e:  # noqa: BLE001
        cp = logmod.write_crash_report(e)
        print(f"FATAL: {e}\nCrash report: {cp}", file=sys.stderr)
        code = 1
    sys.exit(code)


def _dispatch_subcommand(cmd: str, args: list[str]) -> None:
    """Subcommand router (round-60 + round-61)."""
    if cmd == "sites":
        _cmd_sites(args)
    elif cmd == "schedule":
        _cmd_schedule(args)
    elif cmd == "digest":
        _cmd_digest(args)
    elif cmd == "ai-cost":
        _cmd_ai_cost(args)
    elif cmd == "db":
        _cmd_db(args)
    elif cmd == "ai-options":
        _cmd_ai_options(args)
    elif cmd == "analytics":
        _cmd_analytics(args)
    elif cmd == "compare":
        _cmd_compare(args)
    elif cmd == "badge":
        _cmd_badge(args)
    elif cmd == "paths":
        _cmd_paths(args)
    elif cmd == "report":
        _cmd_report(args)
    elif cmd == "annotate":
        _cmd_annotate(args)
    elif cmd == "check":
        _cmd_check(args)
    elif cmd == "config":
        _cmd_config(args)
    elif cmd == "verify-release":
        _cmd_verify_release(args)
    elif cmd == "watch":
        _cmd_watch(args)
    elif cmd == "portfolio":
        _cmd_portfolio(args)
    elif cmd == "refix":
        _cmd_refix(args)
    elif cmd == "snooze":
        _cmd_snooze(args)
    elif cmd == "diff-tree":
        _cmd_diff_tree(args)
    elif cmd == "pr-comment":
        _cmd_pr_comment(args)
    elif cmd == "publish":
        _cmd_publish(args)
    elif cmd == "only":
        _cmd_only(args)
    elif cmd == "doctor":
        _cmd_doctor(args)
    elif cmd == "diff-agency":
        _cmd_diff_agency(args)
    elif cmd == "playbook":
        _cmd_playbook(args)
    elif cmd == "slack-app":
        _cmd_slack_app(args)
    elif cmd == "pr-status":
        _cmd_pr_status(args)
    elif cmd == "dashboard-templates":
        _cmd_dashboard_templates(args)
    elif cmd == "creds":
        _cmd_creds(args)
    elif cmd == "sso":
        _cmd_sso(args)
    elif cmd == "hwkey":
        _cmd_hwkey(args)
    else:
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        sys.exit(2)


def _cmd_report(args: list[str]) -> None:
    """`wpsecscan report open <URL>` — open the most-recent HTML report for
    URL in the default browser. Also: `wpsecscan report path <URL>` to
    just print the path."""
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan report {open|path} <URL>")
        return
    if args[0] not in ("open", "path") or len(args) < 2:
        print("usage: wpsecscan report {open|path} <URL>", file=sys.stderr)
        sys.exit(64)
    mode = args[0]
    url = args[1]
    if "://" not in url:
        url = "https://" + url
    from . import history as _h
    reports_dir = _h._reports_dir()
    safe = _h._safe_filename(url)
    # Look for the most-recently modified HTML for this host. CLI writes
    # JSON snapshots automatically; HTML reports stay where --out put them.
    # We try the home reports dir + cwd as fallbacks.
    candidates: list[Path] = []
    for d in (reports_dir, Path.cwd()):
        if d.exists():
            candidates.extend(d.glob(f"*{safe}*.html"))
    if not candidates:
        print(f"No HTML report found for {url}. Looked in:\n  {reports_dir}\n  {Path.cwd()}",
              file=sys.stderr)
        sys.exit(64)
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    if mode == "path":
        print(latest)
        return
    # Open in default browser, cross-platform.
    import webbrowser
    if not webbrowser.open(latest.resolve().as_uri()):
        print(f"Could not open browser; path: {latest}", file=sys.stderr)
        sys.exit(1)


def _cmd_annotate(args: list[str]) -> None:
    """Bulk-accept findings from a CSV, or set a single annotation.

    Usage:
        wpsecscan annotate --bulk-accept FILE.csv
        wpsecscan annotate URL CHECK_ID TITLE --status STATUS [--note NOTE] [--snooze YYYY-MM-DD]
    CSV columns: url,check_id,title[,reason]
    """
    if not args or args[0] in ("-h", "--help"):
        print(
            "usage:\n"
            "  wpsecscan annotate --bulk-accept FILE.csv\n"
            "  wpsecscan annotate URL CHECK_ID TITLE --status accepted-risk [--note NOTE] [--snooze YYYY-MM-DD]\n"
            "CSV columns for --bulk-accept: url,check_id,title[,reason]"
        )
        return
    from . import history as _h
    if args[0] == "--bulk-accept":
        if len(args) < 2:
            print("usage: wpsecscan annotate --bulk-accept FILE.csv", file=sys.stderr)
            sys.exit(64)
        import csv as _csv
        applied = 0
        skipped = 0
        with open(args[1], "r", encoding="utf-8") as f:
            reader = _csv.DictReader(f)
            for row in reader:
                url = (row.get("url") or "").strip()
                cid = (row.get("check_id") or "").strip()
                title = (row.get("title") or "").strip()
                reason = (row.get("reason") or "").strip()
                if not (url and cid and title):
                    skipped += 1
                    continue
                _h.set_annotation(url, cid, title, "accepted-risk",
                                  note=reason or "bulk-accepted")
                applied += 1
        print(f"Applied {applied} annotation(s); skipped {skipped} incomplete row(s).")
        return
    # Single-annotation form
    if len(args) < 3:
        print("usage: wpsecscan annotate URL CHECK_ID TITLE --status STATUS [--note NOTE] [--snooze YYYY-MM-DD]",
              file=sys.stderr)
        sys.exit(64)
    url, cid, title = args[0], args[1], args[2]
    status = ""
    note = ""
    snooze = ""
    i = 3
    while i < len(args):
        if args[i] == "--status" and i + 1 < len(args):
            status = args[i + 1]; i += 2
        elif args[i] == "--note" and i + 1 < len(args):
            note = args[i + 1]; i += 2
        elif args[i] == "--snooze" and i + 1 < len(args):
            snooze = args[i + 1]; i += 2
        else:
            i += 1
    if not status:
        print("--status is required (e.g. accepted-risk, false-positive, '')", file=sys.stderr)
        sys.exit(64)
    _h.set_annotation(url, cid, title, status, note=note, snooze_until=snooze)
    msg = f"annotated {cid}::{title!r} on {url} as {status!r}"
    if snooze:
        msg += f" until {snooze}"
    print(msg)


_USER_CHECK_TEMPLATE = '''"""User-supplied wpsecscan check.

Drop this file into ~/.wpsecscan/checks/ and it will be auto-loaded the
next time wpsecscan starts. The framework injects an httpx.AsyncClient and
a context dict (ctx) into your check function.

Required attributes:
  CHECK_ID:     str (unique among all checks)
  CHECK_NAME:   str (one-line human label)
  IS_AGGRESSIVE: bool (default False — set True if it sends destructive payloads)

Required function (async):
  async def check(client, ctx) -> list[Finding]

Convention:
  - One Finding per concrete weakness, with severity ∈ info|low|medium|high|critical.
  - Include `evidence` (raw bytes you observed) and `remediation` (the fix) for every finding.
"""
from __future__ import annotations

from wpsecscan.models import Finding

CHECK_ID = "{slug}"
CHECK_NAME = "{name}"
IS_AGGRESSIVE = False


async def check(client, ctx) -> list[Finding]:
    target = ctx["target"]
    findings: list[Finding] = []

    # EXAMPLE: probe a path and flag it if reachable.
    # try:
    #     r = await client.get(target.rstrip("/") + "/example-path")
    #     if r.status_code == 200:
    #         findings.append(Finding(
    #             severity="medium",
    #             title="Example finding from {slug}",
    #             evidence=f"HTTP {{r.status_code}} from /example-path",
    #             remediation="Block public access to /example-path.",
    #             url=str(r.url),
    #         ))
    # except Exception:  # noqa: BLE001
    #     pass

    return findings
'''


def _cmd_check(args: list[str]) -> None:
    """`wpsecscan check list [--category CAT]`   — print the full check inventory.
    `wpsecscan check new SLUG [--name "Label"]` — scaffold a user check (#56).
    `wpsecscan check list-custom`               — list only user-supplied checks.
    `wpsecscan check publish SLUG`              — append a custom check to
                                                  ~/.wpsecscan/marketplace.json
                                                  for sharing (e.g. via Gist).
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan check {list|list-custom|new SLUG|publish SLUG} [options]")
        return
    if args[0] == "new":
        if len(args) < 2:
            print("usage: wpsecscan check new SLUG [--name \"Human label\"]", file=sys.stderr)
            sys.exit(64)
        slug = args[1].strip().lower().replace(" ", "_")
        if not re.match(r"^[a-z][a-z0-9_]{2,40}$", slug):
            print(f"invalid slug {slug!r}: must be [a-z][a-z0-9_]{{2,40}}", file=sys.stderr)
            sys.exit(64)
        name = slug.replace("_", " ").title()
        for i, a in enumerate(args[2:]):
            if a == "--name" and i + 3 < len(args) + 2:
                name = args[i + 3]
        home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
        out_dir = home / "checks"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{slug}.py"
        if out_file.exists():
            print(f"refusing to overwrite existing {out_file}", file=sys.stderr); sys.exit(2)
        out_file.write_text(_USER_CHECK_TEMPLATE.format(slug=slug, name=name), encoding="utf-8")
        print(f"scaffolded user check: {out_file}")
        print(f"next: edit the file, then run `wpsecscan only {slug} https://your-site.test`")
        return
    if args[0] == "list-custom":
        from .checks import ALL_CHECKS
        home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
        custom_dirs = [home / "plugins", home / "checks", home / "marketplace" / "checks"]
        custom_ids: set[str] = set()
        for d in custom_dirs:
            if d.exists():
                custom_ids.update(p.stem for p in d.glob("*.py"))
        rows = [(cid, cname, agg) for cid, cname, _fn, agg in ALL_CHECKS if cid in custom_ids]
        print(f"{len(rows)} user-supplied check(s):")
        for cid, cname, agg in rows:
            mode = "aggressive" if agg else "passive"
            print(f"  {cid:35s}  ({mode:11s})  {cname}")
        return
    if args[0] == "publish":
        import json
        if len(args) < 2:
            print("usage: wpsecscan check publish SLUG", file=sys.stderr); sys.exit(64)
        slug = args[1].strip()
        home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
        candidates = [home / "checks" / f"{slug}.py",
                       home / "plugins" / f"{slug}.py"]
        src = next((p for p in candidates if p.exists()), None)
        if src is None:
            print(f"no custom check found for slug {slug!r}", file=sys.stderr); sys.exit(2)
        manifest_path = home / "marketplace.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.exists() else {"version": 1, "checks": []}
        except (OSError, json.JSONDecodeError):
            manifest = {"version": 1, "checks": []}
        manifest.setdefault("checks", [])
        manifest["checks"] = [c for c in manifest["checks"] if c.get("slug") != slug]
        manifest["checks"].append({
            "slug": slug,
            "path": str(src),
            "source": src.read_text(encoding="utf-8"),
            "published_at": __import__("datetime").datetime.utcnow().isoformat(timespec="seconds") + "Z",
        })
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"appended {slug} to {manifest_path}")
        print("upload this JSON to a Gist / GitHub repo to share with others.")
        return
    if args[0] != "list":
        print("usage: wpsecscan check {list|list-custom|new SLUG|publish SLUG} [options]", file=sys.stderr)
        sys.exit(64)
    cat_filter = ""
    i = 1
    while i < len(args):
        if args[i] == "--category" and i + 1 < len(args):
            cat_filter = args[i + 1].lower()
            i += 2
        else:
            i += 1
    from .checks import ALL_CHECKS
    from . import tags as _tags
    rows = []
    for cid, cname, _fn, agg in ALL_CHECKS:
        t = _tags.get_tags(cid) or {}
        owasp = t.get("owasp", "") or ""
        owasp_label = t.get("owasp_label", "") or ""
        if cat_filter and cat_filter not in owasp.lower() and cat_filter not in owasp_label.lower():
            continue
        rows.append((cid, cname, owasp, owasp_label, "aggressive" if agg else "passive"))
    rows.sort(key=lambda r: (r[2], r[0]))
    print(f"{len(rows)} check(s)" + (f" (filtered: {cat_filter})" if cat_filter else ""))
    print()
    for cid, cname, owasp, owasp_label, mode in rows:
        print(f"  [{owasp:8s}]  {cid:35s}  ({mode:11s})  {cname}")


def _cmd_verify_release(args: list[str]) -> None:
    """`wpsecscan verify-release [--exe PATH]` — verify the running binary's
    Sigstore signature against the WPSecScan project's OIDC identity.

    The release-attestation workflow publishes a detached signature (.sig)
    and a Sigstore certificate (.pem) alongside every release artifact;
    this command verifies both against the expected OIDC identity and
    prints the Rekor transparency-log entry URL.

    Tries `cosign verify-blob` first (binary on PATH), then sigstore-python
    if importable, otherwise prints the manual cosign command for the user
    to run.
    """
    if args and args[0] in ("-h", "--help"):
        print(
            "usage: wpsecscan verify-release [--exe PATH] [--sig PATH] [--cert PATH]\n"
            "  --exe   path to the .exe / .py to verify (default: this binary)\n"
            "  --sig   signature file (default: <exe>.sig next to it)\n"
            "  --cert  Sigstore certificate (default: <exe>.pem next to it)\n"
            "\nVerifies against the project's OIDC identity:\n"
            "  certificate-identity-regexp: https://github.com/bryanflowers/wpsecscan\n"
            "  oidc-issuer:                 https://token.actions.githubusercontent.com"
        )
        return

    # Defaults: resolve from the running executable. PyInstaller sets
    # sys._MEIPASS, but the actual .exe lives at sys.executable.
    default_exe = Path(sys.executable)
    if getattr(sys, "frozen", False):  # PyInstaller-bundled
        default_exe = Path(sys.executable).resolve()
    else:
        # Source checkout — verify the wpsecscan module's installation root.
        default_exe = Path(__file__).parent.parent

    exe_path: Path | None = None
    sig_path: Path | None = None
    cert_path: Path | None = None
    i = 0
    while i < len(args):
        if args[i] == "--exe" and i + 1 < len(args):
            exe_path = Path(args[i + 1]); i += 2
        elif args[i] == "--sig" and i + 1 < len(args):
            sig_path = Path(args[i + 1]); i += 2
        elif args[i] == "--cert" and i + 1 < len(args):
            cert_path = Path(args[i + 1]); i += 2
        else:
            i += 1
    exe_path = exe_path or default_exe
    sig_path = sig_path or exe_path.with_suffix(exe_path.suffix + ".sig")
    cert_path = cert_path or exe_path.with_suffix(exe_path.suffix + ".pem")

    print(f"Verifying release artifact:")
    print(f"  exe:  {exe_path}")
    print(f"  sig:  {sig_path}")
    print(f"  cert: {cert_path}")
    print()

    if not exe_path.exists():
        print(f"FAIL: artifact not found at {exe_path}", file=sys.stderr)
        sys.exit(1)
    if not sig_path.exists() or not cert_path.exists():
        print(
            f"FAIL: signature or certificate missing.\n"
            f"  Expected: {sig_path}\n"
            f"            {cert_path}\n"
            "Download both from the GitHub release for this version "
            "(https://github.com/bryanflowers/wpsecscan/releases/latest), "
            "place them next to the .exe, and re-run.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Try the `cosign` binary first — it's the canonical tool.
    import shutil as _shutil
    import subprocess as _subprocess
    cosign = _shutil.which("cosign")
    if cosign:
        print("Using cosign on PATH.")
        cmd = [
            cosign, "verify-blob",
            "--signature", str(sig_path),
            "--certificate", str(cert_path),
            "--certificate-identity-regexp", "https://github.com/bryanflowers/wpsecscan",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            str(exe_path),
        ]
        try:
            r = _subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (_subprocess.TimeoutExpired, OSError) as e:
            print(f"FAIL: cosign invocation failed: {e}", file=sys.stderr)
            sys.exit(1)
        if r.returncode == 0:
            print("✓ Sigstore signature VERIFIED for", exe_path.name)
            if r.stdout.strip():
                print(r.stdout.strip())
            print()
            print("Rekor transparency log: search https://search.sigstore.dev/ for "
                  "the certificate fingerprint to view the public log entry.")
            sys.exit(0)
        print(f"FAIL: cosign exited {r.returncode}", file=sys.stderr)
        if r.stderr.strip():
            print(r.stderr.strip(), file=sys.stderr)
        sys.exit(1)

    # Cosign not available — try sigstore-python.
    try:
        import sigstore  # noqa: F401  - optional dep
        from sigstore.verify import Verifier, models  # type: ignore
        print("Using sigstore-python (`cosign` not on PATH).")
        verifier = Verifier.production()
        with open(sig_path, "rb") as sf:
            sig = sf.read()
        with open(cert_path, "rb") as cf:
            cert = cf.read()
        with open(exe_path, "rb") as xf:
            blob = xf.read()
        # The exact API of sigstore-python evolves; if it changes shape, fall
        # back to the printed-instructions path rather than crashing.
        try:
            result = verifier.verify(
                input_=blob,
                signature=sig,
                certificate=cert,
            )
            ok = bool(getattr(result, "success", True))
        except Exception as e:  # noqa: BLE001
            print(f"sigstore-python verify() failed: {e}", file=sys.stderr)
            ok = False
        if ok:
            print("✓ Sigstore signature VERIFIED for", exe_path.name)
            sys.exit(0)
        print("FAIL: signature did not verify.", file=sys.stderr)
        sys.exit(1)
    except ImportError:
        pass

    # No verifier available — print the manual command and exit non-zero
    # so CI scripts can detect the no-tools state.
    print(
        "No verifier available. Install one of:\n"
        "  - cosign  (https://github.com/sigstore/cosign/releases)\n"
        "  - sigstore-python:  pip install sigstore\n\n"
        "Then run manually:\n\n"
        f"  cosign verify-blob \\\n"
        f"    --signature '{sig_path}' \\\n"
        f"    --certificate '{cert_path}' \\\n"
        f"    --certificate-identity-regexp 'https://github.com/bryanflowers/wpsecscan' \\\n"
        f"    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \\\n"
        f"    '{exe_path}'\n",
        file=sys.stderr,
    )
    sys.exit(2)


def _cmd_watch(args: list[str]) -> None:
    """`wpsecscan watch URL [--interval N] [--webhook URL] [--exit-on-new]`

    Polling daemon that re-scans URL every N seconds (default 1800 = 30 min),
    diffs against the previous run's saved snapshot, and posts ONLY on
    finding-deltas. Quiet by default — no per-run noise. POST a Slack-shaped
    JSON payload when --webhook is set.

    Use --exit-on-new to break the loop the first time a new finding appears
    (useful from CI as a tripwire).
    """
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_watch.__doc__.strip())
        sys.exit(0)

    target = args[0]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    interval = 1800
    webhook: str | None = None
    exit_on_new = False
    skip = {0}
    for i, a in enumerate(args):
        if i in skip:
            continue
        if a == "--interval" and i + 1 < len(args):
            try:
                interval = max(60, int(args[i + 1]))
            except ValueError:
                pass
            skip.add(i + 1)
        elif a == "--webhook" and i + 1 < len(args):
            webhook = args[i + 1]
            skip.add(i + 1)
        elif a == "--exit-on-new":
            exit_on_new = True

    from . import history as _h
    from . import json_io as _ji  # type: ignore[unused-import]  # may be json_out
    import asyncio as _asyncio
    import json as _json
    import time as _time
    import urllib.request as _ur
    from datetime import datetime, timezone

    console = Console(no_color=False, legacy_windows=False)
    console.print(f"[bold]wpsecscan watch[/bold] {target} every {interval}s "
                   f"(webhook={'set' if webhook else 'none'}, "
                   f"exit-on-new={exit_on_new})")

    async def _one_pass() -> tuple[set[str], set[str], int, int]:
        # Run a passive scan, return (new_titles, fixed_titles, total, score)
        from .scanner import scan
        from .reporters import json_out as _jo
        report = await scan(target, timeout=15.0, aggressive=False, sequential=True)
        # Persist
        _h.save_report_snapshot(target, _jo.render(report))
        # Compare with prior
        snaps = _h.snapshot_history(target)
        prev_titles: set[str] = set()
        if len(snaps) >= 2:
            try:
                prev = _json.loads(Path(snaps[-2]).read_text(encoding="utf-8"))
                for r in prev.get("results", []):
                    for f in r.get("findings", []):
                        if f.get("severity") in ("critical", "high", "medium"):
                            prev_titles.add(f.get("title", ""))
            except (OSError, ValueError):
                prev_titles = set()
        cur_titles: set[str] = set()
        for r in report.results:
            for f in r.findings:
                if f.severity in ("critical", "high", "medium"):
                    cur_titles.add(f.title)
        return (cur_titles - prev_titles), (prev_titles - cur_titles), len(cur_titles), report.risk_score

    def _post(text: str) -> None:
        if not webhook:
            return
        try:
            body = _json.dumps({"text": text}).encode("utf-8")
            req = _ur.Request(webhook, data=body, method="POST",
                                headers={"Content-Type": "application/json",
                                          "User-Agent": "WPSecScan/watch"})
            _ur.urlopen(req, timeout=10.0).close()
        except Exception as e:  # noqa: BLE001 — webhook must never break the loop
            console.print(f"[yellow]webhook post failed:[/yellow] {e}")

    while True:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            new, fixed, total, score = _asyncio.run(_one_pass())
        except Exception as e:  # noqa: BLE001
            console.print(f"[{ts}] scan failed: {e}")
            _time.sleep(interval)
            continue
        if new or fixed:
            console.print(
                f"[{ts}] {target} — [red]+{len(new)} new[/red] "
                f"[green]-{len(fixed)} fixed[/green] "
                f"(total {total}, score {score}/100)"
            )
            for title in sorted(new)[:10]:
                console.print(f"  [red]+[/red] {title}")
            for title in sorted(fixed)[:10]:
                console.print(f"  [green]-[/green] {title}")
            if webhook:
                lines = [f"*WPSecScan watch*: {target}",
                          f"+{len(new)} new, -{len(fixed)} fixed, total {total}, score {score}/100"]
                for title in sorted(new)[:5]:
                    lines.append(f"• NEW: {title}")
                for title in sorted(fixed)[:5]:
                    lines.append(f"• FIXED: {title}")
                _post("\n".join(lines))
            if exit_on_new and new:
                console.print(f"[red]exit-on-new tripwire fired[/red] — exiting")
                sys.exit(3)
        else:
            console.print(f"[{ts}] {target}: no change (total {total}, score {score}/100)")
        _time.sleep(interval)


def _cmd_portfolio(args: list[str]) -> None:
    """`wpsecscan portfolio [--tag FOO] [--out DIR] [--no-pdf]`

    Bulk-scan every site in ~/.wpsecscan/sites.json (filtered by --tag if
    given) and write a single agency-style dashboard + one exec-PDF per
    site. Combines `sites scan` + `--dashboard --agency-dashboard` +
    `--exec-pdf` in one verb.
    """
    if args and args[0] in ("-h", "--help"):
        print(_cmd_portfolio.__doc__.strip())
        sys.exit(0)
    tag_filter: str | None = None
    out_dir = "wpsecscan-portfolio"
    want_pdf = True
    for i, a in enumerate(args):
        if a == "--tag" and i + 1 < len(args):
            tag_filter = args[i + 1].lower()
        elif a == "--out" and i + 1 < len(args):
            out_dir = args[i + 1]
        elif a == "--no-pdf":
            want_pdf = False
    from . import sites as sites_mod
    all_sites = sites_mod.list_sites()
    if tag_filter:
        sel = [s for s in all_sites if tag_filter in (s.get("tags") or [])]
    else:
        sel = all_sites
    if not sel:
        msg = "no sites match" + (f" tag {tag_filter!r}" if tag_filter else "")
        print(msg); sys.exit(2)
    print(f"portfolio scan: {len(sel)} site(s) → {out_dir}/")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    for s in sel:
        url = s["url"]
        print(f"  -> {url}")
        cmd = [sys.executable, "-m", "wpsecscan", url,
               "--out", out_dir, "--agency-dashboard"]
        if want_pdf:
            cmd.append("--exec-pdf")
        child_env = dict(os.environ)
        if s.get("auth_user"):
            child_env["WPSECSCAN_AUTH_USER"] = s["auth_user"]
        if s.get("proxy_url"):
            cmd.extend(["--proxy", s["proxy_url"]])
        for sealed_key, env_name in (
            ("proxy_auth_sealed", "WPSECSCAN_PROXY_AUTH"),
            ("auth_app_password_sealed", "WPSECSCAN_AUTH_APP_PASSWORD"),
            ("companion_token_sealed", "WPSECSCAN_COMPANION_TOKEN"),
        ):
            if s.get(sealed_key):
                try:
                    child_env[env_name] = sites_mod._unseal(s[sealed_key])
                except Exception:  # noqa: BLE001
                    pass
        import subprocess as _sp
        _sp.run(cmd, env=child_env, check=False)
    print(f"\nportfolio complete: open {out_dir}/wpsecscan-agency-dashboard.html")


def _cmd_refix(args: list[str]) -> None:
    """`wpsecscan refix CHECK_ID URL` — re-run only one check and write a
    fix-attested receipt to ~/.wpsecscan/refix/<host>-<check>-<ts>.json.

    Useful after fixing a specific finding: instead of running a full
    20-minute scan, this re-executes the single check that flagged the
    issue and tells you whether it's now clean.
    """
    if len(args) < 2 or args[0] in ("-h", "--help"):
        print("usage: wpsecscan refix CHECK_ID URL\n"
              "  CHECK_ID is the `check_id` from a JSON report.")
        sys.exit(0 if args and args[0] in ("-h", "--help") else 2)
    check_id, target = args[0], args[1]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    import asyncio as _asyncio
    import json as _json
    from datetime import datetime, timezone
    from urllib.parse import urlparse
    from . import scanner as _sc

    async def _refix_one() -> tuple[bool, list[dict]]:
        # Find the check function from the registry.
        from .checks import ALL_CHECKS
        ours = [c for c in ALL_CHECKS if c[0] == check_id]
        if not ours:
            print(f"unknown check_id: {check_id}\n"
                  "see `wpsecscan check list` for valid IDs", file=sys.stderr)
            return False, []
        cid, name, fn, aggressive = ours[0]
        # Build a minimal client + ctx and run the check function directly.
        from .http import Client
        client = Client(target, timeout=15.0, user_agent="WPSecScan/refix")
        try:
            ctx = {"target": target, "shared": {}, "step": lambda _s: None,
                   "aggressive": False}
            findings = await fn(client, ctx)
            return True, [f.to_dict() for f in (findings or [])]
        finally:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass

    ok, findings_out = _asyncio.run(_refix_one())
    if not ok:
        sys.exit(2)

    # Classify pass/fail: any finding above 'info' = still failing.
    fail_findings = [f for f in findings_out
                      if f.get("severity") in ("low", "medium", "high", "critical")]
    passed = not fail_findings

    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    out_dir = home / "refix"
    out_dir.mkdir(parents=True, exist_ok=True)
    host = (urlparse(target).hostname or "site").replace(".", "-")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    receipt = {
        "check_id": check_id,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "passed": passed,
        "findings": findings_out,
    }
    out_path = out_dir / f"{host}-{check_id}-{ts}.json"
    out_path.write_text(_json.dumps(receipt, indent=2), encoding="utf-8")

    if passed:
        print(f"PASS: {check_id} on {target} — no actionable findings.")
        print(f"Receipt: {out_path}")
        sys.exit(0)
    else:
        print(f"FAIL: {check_id} on {target} — {len(fail_findings)} finding(s) still present.")
        for f in fail_findings[:5]:
            print(f"  [{f.get('severity').upper()}] {f.get('title')}")
        print(f"Receipt: {out_path}")
        sys.exit(64)


def _cmd_only(args: list[str]) -> None:
    """`wpsecscan only CHECK_ID URL [--aggressive] [--auth-user U] [...]`

    Run ONE named check against URL and print the findings. Faster than
    `refix` (which writes a fix-attested receipt to disk); intended for
    ad-hoc testing of a single check during development or debugging.
    """
    if len(args) < 2 or args[0] in ("-h", "--help"):
        print("usage: wpsecscan only CHECK_ID URL [--aggressive] [--auth-user U] [...]\n"
              "  CHECK_ID: see `wpsecscan check list` for valid IDs.\n"
              "  URL:      target site, e.g. https://example.com")
        sys.exit(0 if args and args[0] in ("-h", "--help") else 2)
    check_id, target = args[0], args[1]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    aggressive = "--aggressive" in args
    auth_user = None
    auth_pass = None
    for i, a in enumerate(args):
        if a == "--auth-user" and i + 1 < len(args):
            auth_user = args[i + 1]
        elif a == "--auth-pass" and i + 1 < len(args):
            auth_pass = args[i + 1]

    import asyncio as _asyncio
    from .checks import ALL_CHECKS
    from .http import Client
    ours = [c for c in ALL_CHECKS if c[0] == check_id]
    if not ours:
        print(f"unknown check_id: {check_id}", file=sys.stderr)
        print("see `wpsecscan check list` for valid IDs", file=sys.stderr)
        sys.exit(2)
    cid, name, fn = ours[0][:3]

    async def _run():
        client = Client(target, timeout=15.0, user_agent="WPSecScan/only")
        try:
            ctx = {
                "target": target,
                "shared": {},
                "step": lambda _s: None,
                "aggressive": aggressive,
                "auth_user": auth_user,
                "auth_pass": auth_pass,
                "is_cancelled": lambda: False,
                "is_paused":    lambda: False,
            }
            return await fn(client, ctx)
        finally:
            try:
                await client.aclose()
            except Exception:  # noqa: BLE001
                pass

    findings = _asyncio.run(_run()) or []
    if not findings:
        print(f"{cid} on {target}: no findings.")
        sys.exit(0)
    print(f"{cid} on {target}: {len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f.severity.upper()}] {f.title}")
        if f.url:
            print(f"      url: {f.url}")
        if f.evidence:
            ev = (f.evidence or "")[:200].replace("\n", " ")
            print(f"      evidence: {ev}")
    has_actionable = any(
        f.severity in ("low", "medium", "high", "critical") for f in findings
    )
    sys.exit(1 if has_actionable else 0)


def _cmd_doctor(args: list[str]) -> None:
    """`wpsecscan doctor` — one-shot environment audit.

    Checks every optional component that wpsecscan can leverage and
    prints a green / yellow / red verdict so the user knows at a glance
    what's available and what's not.
    """
    if args and args[0] in ("-h", "--help"):
        print(_cmd_doctor.__doc__.strip()); sys.exit(0)
    import importlib
    import shutil as _shutil
    rows: list[tuple[str, str, str]] = []  # (status, name, hint)

    def _check_import(mod: str, hint: str) -> None:
        try:
            importlib.import_module(mod)
            rows.append(("✓", mod, "installed"))
        except ImportError:
            rows.append(("•", mod, hint))

    def _check_bin(name: str, hint: str) -> None:
        if _shutil.which(name):
            rows.append(("✓", name, "on PATH"))
        else:
            rows.append(("•", name, hint))

    def _check_env(var: str, hint: str) -> None:
        if os.environ.get(var):
            rows.append(("✓", var, "set"))
        else:
            rows.append(("•", var, hint))

    # Core
    rows.append(("✓", f"wpsecscan v{__version__}", "running"))
    rows.append(("✓", f"Python {sys.version.split()[0]}", "running"))

    # Optional Python deps
    _check_import("httpx",          "required — should always be installed")
    _check_import("jinja2",         "required — HTML reports")
    _check_import("dnspython",      "[yaml]/[all] extra — DNSSEC + MX checks need it")
    _check_import("PIL",            "[ui] extra — DPI-aware GUI + tray icon + score-trend chart")
    _check_import("pystray",        "[ui] extra — minimize-to-tray for the GUI")
    _check_import("reportlab",      "[pdf] extra — true PDF executive reports (else HTML fallback)")
    _check_import("docx",           "python-docx — true DOCX reports (else RTF fallback)")
    _check_import("yaml",           "[yaml] extra — daemon config + policy.yml + --config .yml")
    _check_import("keyring",        "[ui] extra — store creds in OS keychain")
    _check_import("playwright",     "[browser] extra — headless DOM-XSS + screenshots")
    _check_import("redis",          "[ops] extra — distributed CVE-DB cache")
    _check_import("sigstore",       "verify-release subcommand")

    # External binaries the scanner shells out to
    _check_bin("openssl",  "tls_modern check uses openssl s_client for 0-RTT + OCSP stapling")
    _check_bin("dig",      "dns_security falls back to dig when dnspython is missing")
    _check_bin("nslookup", "ditto — alt fallback")
    _check_bin("git",      "release-attestation verification")
    _check_bin("gh",       "pypi-publish workflow trigger + verify-release")

    # Tokens
    _check_env("WPSECSCAN_WPSCAN_TOKEN",        "wpscan.com plugin-CVE enrichment (25 req/day free)")
    _check_env("WPSECSCAN_PATCHSTACK_TOKEN",    "patchstack.com WP-specific CVE feed")
    _check_env("WPSECSCAN_HIBP_TOKEN",          "HaveIBeenPwned email-breach check ($4/mo)")
    _check_env("WPSECSCAN_VT_TOKEN",            "VirusTotal URL+IP reputation (4 req/min free)")
    _check_env("WPSECSCAN_ABUSEIPDB_TOKEN",     "AbuseIPDB IP-reputation (1000/day free)")
    _check_env("WPSECSCAN_GITHUB_SEARCH_TOKEN", "GitHub code-search for leaked secrets")
    _check_env("WPSECSCAN_OPENAI_API_KEY",      "AI-assisted features (else --ai-explain-for is a no-op)")
    _check_env("WPSECSCAN_ANTHROPIC_API_KEY",   "alt AI backend")
    _check_env("WPSECSCAN_OLLAMA_URL",          "alt local AI backend (no token, just URL)")

    # Files / dirs
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    rows.append(("✓" if home.exists() else "•", f"~/.wpsecscan/", str(home)))
    rows.append(("✓" if (home / "reports").exists() else "•",
                  "~/.wpsecscan/reports/", "report snapshots"))
    rows.append(("✓" if (home / "policy.yml").exists() or (home / "policy.json").exists() else "•",
                  "~/.wpsecscan/policy.{yml,json}", "per-site policy overrides"))

    # Output
    print()
    print(f"{'':2}  {'COMPONENT':40}  HINT")
    print(f"{'':2}  {'-' * 40}  {'-' * 40}")
    for status, name, hint in rows:
        print(f"{status:2}  {name[:40]:40}  {hint}")
    print()
    missing = sum(1 for s, _n, _h in rows if s == "•")
    if missing:
        print(f"{missing} optional component(s) not detected. Wpsecscan will still run; "
               "install the listed extras / set the env vars to enable the relevant features.")
    else:
        print("All optional components detected.")
    sys.exit(0)


def _cmd_sso(args: list[str]) -> None:
    """Item #70 — SAML / OIDC configure flow for the daemon REST API.

      wpsecscan sso configure --type oidc --issuer URL --audience NAME
                              [--jwks-url URL] [--cache-ttl 3600]
      wpsecscan sso configure --type saml --metadata-url URL --acs-url URL
                              [--audience NAME]
      wpsecscan sso status
      wpsecscan sso clear

    Writes ~/.wpsecscan/sso.json which auth/sso_oidc.py + auth/sso_saml.py
    read at daemon startup. The daemon was already wired (round-64); this
    just makes config a one-liner instead of editing JSON by hand.
    """
    import json
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_sso.__doc__.strip()); return
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    home.mkdir(parents=True, exist_ok=True)
    cfg_path = home / "sso.json"
    sub = args[0]

    if sub == "status":
        if not cfg_path.exists():
            print("no SSO configured. Run `wpsecscan sso configure --type oidc ...`")
            return
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            for k, v in cfg.items():
                print(f"  {k:14s} = {v}")
        except (OSError, json.JSONDecodeError) as e:
            print(f"error reading {cfg_path}: {e}", file=sys.stderr); sys.exit(2)
        return

    if sub == "clear":
        if cfg_path.exists():
            cfg_path.unlink()
            print(f"removed {cfg_path}")
        else:
            print("no SSO config to remove")
        return

    if sub != "configure":
        print("usage: wpsecscan sso {configure|status|clear} [opts]", file=sys.stderr)
        sys.exit(64)

    kv: dict[str, str] = {}
    i = 1
    while i < len(args):
        a = args[i]
        if a.startswith("--") and i + 1 < len(args):
            kv[a[2:].replace("-", "_")] = args[i + 1]
            i += 2
        else:
            i += 1
    sso_type = kv.get("type", "").lower()
    if sso_type not in ("oidc", "saml"):
        print("must pass --type oidc or --type saml", file=sys.stderr); sys.exit(64)
    if sso_type == "oidc":
        if not kv.get("issuer") or not kv.get("audience"):
            print("--issuer and --audience are required for OIDC", file=sys.stderr); sys.exit(64)
        out = {"type": "oidc", "issuer": kv["issuer"], "audience": kv["audience"]}
        if kv.get("jwks_url"):
            out["jwks_url"] = kv["jwks_url"]
        if kv.get("cache_ttl"):
            out["cache_ttl"] = int(kv["cache_ttl"])
    else:
        if not kv.get("metadata_url") or not kv.get("acs_url"):
            print("--metadata-url and --acs-url are required for SAML", file=sys.stderr); sys.exit(64)
        out = {"type": "saml", "metadata_url": kv["metadata_url"],
                "acs_url": kv["acs_url"]}
        if kv.get("audience"):
            out["audience"] = kv["audience"]
    cfg_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"SSO configured → {cfg_path}")
    print("Restart the wpsecscan daemon for it to pick up the change.")


def _cmd_hwkey(args: list[str]) -> None:
    """Item #72 — hardware-key gating for --aggressive.

      wpsecscan hwkey enable           # require a touch before any --aggressive scan
      wpsecscan hwkey disable          # remove the gate
      wpsecscan hwkey status           # report whether the gate is active
      wpsecscan hwkey grant [--ttl 3600]   # mint a one-shot authorization token

    When the gate is enabled, the scanner refuses --aggressive scans
    unless either:
      • $WPSECSCAN_AGGRESSIVE_HWKEY_TOKEN matches a current grant token, or
      • the operator types the literal word YES at an interactive prompt
        (so a manual touch + acknowledgement still works without scripting).

    This is the practical hardening; full FIDO2/WebAuthn CTAP integration
    is out of scope for v2.5.0 — the `fido2` library wiring lands later.
    """
    import json
    import secrets
    import time
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_hwkey.__doc__.strip()); return
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    home.mkdir(parents=True, exist_ok=True)
    gate_path = home / "hwkey-gate.json"
    sub = args[0]

    if sub == "enable":
        gate_path.write_text(json.dumps({"enabled": True,
                                           "enabled_at": int(time.time())}, indent=2),
                              encoding="utf-8")
        print(f"hwkey gate ENABLED. --aggressive scans now require either "
               f"$WPSECSCAN_AGGRESSIVE_HWKEY_TOKEN (mint via `wpsecscan hwkey grant`) "
               f"or interactive YES confirmation.")
        return
    if sub == "disable":
        if gate_path.exists():
            gate_path.unlink()
        print("hwkey gate disabled.")
        return
    if sub == "status":
        if not gate_path.exists():
            print("hwkey gate: disabled")
        else:
            try:
                cfg = json.loads(gate_path.read_text(encoding="utf-8"))
                print(f"hwkey gate: ENABLED at {cfg.get('enabled_at')}")
            except (OSError, json.JSONDecodeError):
                print("hwkey gate: ENABLED (config unreadable)")
        return
    if sub == "grant":
        ttl = 3600
        for i, a in enumerate(args[1:]):
            if a == "--ttl" and i + 2 <= len(args[1:]):
                ttl = int(args[i + 2])
        token = secrets.token_urlsafe(24)
        grants_path = home / "hwkey-grants.json"
        try:
            grants = json.loads(grants_path.read_text(encoding="utf-8")) if grants_path.exists() else {}
        except (OSError, json.JSONDecodeError):
            grants = {}
        expires_at = int(time.time()) + ttl
        grants[token] = {"expires_at": expires_at, "used": False}
        grants_path.write_text(json.dumps(grants, indent=2), encoding="utf-8")
        print(f"export WPSECSCAN_AGGRESSIVE_HWKEY_TOKEN={token}")
        print(f"# valid for {ttl}s (until epoch {expires_at})", file=sys.stderr)
        return
    print(f"unknown hwkey subcommand: {sub}", file=sys.stderr); sys.exit(64)


def _check_aggressive_hwkey_gate(args) -> None:
    """Item #72 — called from the main scan path BEFORE any aggressive
    check runs. If the gate is enabled, demands authorisation."""
    if not getattr(args, "aggressive", False):
        return
    import json
    import time
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    gate_path = home / "hwkey-gate.json"
    if not gate_path.exists():
        return  # gate disabled — passthrough
    token_env = os.environ.get("WPSECSCAN_AGGRESSIVE_HWKEY_TOKEN", "").strip()
    if token_env:
        grants_path = home / "hwkey-grants.json"
        try:
            grants = json.loads(grants_path.read_text(encoding="utf-8")) if grants_path.exists() else {}
        except (OSError, json.JSONDecodeError):
            grants = {}
        entry = grants.get(token_env)
        if entry and not entry.get("used") and entry.get("expires_at", 0) > int(time.time()):
            entry["used"] = True  # one-shot
            grants_path.write_text(json.dumps(grants, indent=2), encoding="utf-8")
            return
        # Token bad / expired / replayed — fall through to interactive prompt.
    # Interactive YES prompt — operator must be at the terminal.
    if not sys.stdin.isatty():
        print("hwkey gate is enabled and no valid $WPSECSCAN_AGGRESSIVE_HWKEY_TOKEN "
               "was supplied (and stdin is not a TTY for interactive confirmation). "
               "Run `wpsecscan hwkey grant` to mint one, or disable the gate with "
               "`wpsecscan hwkey disable`.", file=sys.stderr)
        sys.exit(3)
    answer = input("--aggressive scan: hwkey gate is enabled. Type YES to proceed: ").strip()
    if answer != "YES":
        print("aborted by hwkey gate.", file=sys.stderr); sys.exit(3)


def _cmd_creds(args: list[str]) -> None:
    """Items #68, #69, #71 — credential vault CRUD.

      wpsecscan creds add    SITE_URL  [--account NAME] [--field FIELD ...]
      wpsecscan creds get    SITE_URL  [--account NAME] [--field FIELD]
      wpsecscan creds list   [--values]
      wpsecscan creds rm     SITE_URL  [--account NAME] [--field FIELD]
      wpsecscan creds rotate SITE_URL  [--account NAME] [--field FIELD]
      wpsecscan creds use    SITE_URL  [--account NAME]
          (prints `export WPSECSCAN_AUTH_USER=... WPSECSCAN_AUTH_PASS=...`
           so a wrapper script can `eval $(wpsecscan creds use SITE)`)

    --account NAME       multi-account on one site (#71). The account name
                          becomes a suffix on every field (e.g. \"admin1\" →
                          \"username@admin1\", \"password@admin1\").
    --field FIELD VALUE  store an arbitrary key/value; default fields
                          prompted for are \"username\" + \"password\".

    Backend is keyring when available, else a 0600 fallback file at
    ~/.wpsecscan/creds-vault.json.
    """
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_creds.__doc__.strip()); return
    from . import creds_vault as _cv
    sub = args[0]

    # Helper: combine field + account into the on-disk field name.
    def _f(field: str, account: str | None) -> str:
        return f"{field}@{account}" if account else field

    # Helper: parse trailing --account / --field KEY VAL flags.
    def _parse(extra: list[str]) -> tuple[str | None, dict[str, str]]:
        account: str | None = None
        kv: dict[str, str] = {}
        i = 0
        while i < len(extra):
            a = extra[i]
            if a == "--account" and i + 1 < len(extra):
                account = extra[i + 1]; i += 2
            elif a == "--field" and i + 2 < len(extra):
                kv[extra[i + 1]] = extra[i + 2]; i += 3
            else:
                i += 1
        return account, kv

    if sub == "list":
        show_values = "--values" in args[1:]
        backend = _cv.backend_in_use()
        sites = _cv.list_sites()
        print(f"creds vault ({backend} backend):")
        if not sites:
            print("  (empty — use `wpsecscan creds add SITE_URL` to populate)")
            return
        for site, fields in sites:
            print(f"  {site}")
            for f in fields:
                if show_values:
                    v = _cv.get_secret(site, f) or ""
                    masked = v if f.startswith(("username", "user", "account")) else "*" * len(v)
                    print(f"    {f:30s} = {masked}")
                else:
                    print(f"    {f}")
        return

    if len(args) < 2:
        print("usage: wpsecscan creds {add|get|rm|rotate|use} SITE_URL [--account NAME] [--field FIELD VALUE]",
              file=sys.stderr)
        sys.exit(64)
    site = args[1].rstrip("/")
    account, kv = _parse(args[2:])

    if sub == "add":
        # Interactive fill if no --field overrides were supplied.
        if not kv:
            import getpass as _gp
            user = input(f"username for {site}{' @' + account if account else ''}: ").strip()
            pw = _gp.getpass(f"password for {site}{' @' + account if account else ''}: ")
            if user:
                _cv.set_secret(site, _f("username", account), user)
            if pw:
                _cv.set_secret(site, _f("password", account), pw)
        else:
            for k, v in kv.items():
                _cv.set_secret(site, _f(k, account), v)
        print(f"saved credentials for {site}"
               + (f" account={account}" if account else "") +
               f" (backend={_cv.backend_in_use()})")
        return

    if sub == "get":
        # If --field was given as a flag, look up that single one.
        if "--field" in args[2:]:
            i = args.index("--field", 2)
            if i + 1 < len(args):
                v = _cv.get_secret(site, _f(args[i + 1], account))
                print(v or "")
                return
        # Default: print user + masked-pw line.
        u = _cv.get_secret(site, _f("username", account)) or ""
        p = _cv.get_secret(site, _f("password", account)) or ""
        print(f"username = {u}")
        print(f"password = {'*' * len(p) if p else ''} ({len(p)} chars)")
        return

    if sub == "rm":
        n = 0
        if not kv and "--field" not in args[2:]:
            # Remove all fields for this site (+ account).
            for f in _cv.list_fields_for(site):
                if account and not f.endswith(f"@{account}"):
                    continue
                if not account and "@" in f:
                    continue
                if _cv.delete_secret(site, f):
                    n += 1
        else:
            target_fields = list(kv.keys()) or []
            if "--field" in args[2:]:
                i = args.index("--field", 2)
                if i + 1 < len(args):
                    target_fields.append(args[i + 1])
            for k in target_fields:
                if _cv.delete_secret(site, _f(k, account)):
                    n += 1
        print(f"removed {n} secret(s) for {site}" + (f" account={account}" if account else ""))
        return

    if sub == "rotate":
        import getpass as _gp
        # Identify which field to rotate; default = password.
        field = "password"
        if "--field" in args[2:]:
            i = args.index("--field", 2)
            if i + 1 < len(args):
                field = args[i + 1]
        new_v = _gp.getpass(f"new value for {field}@{site}"
                              + (f" account={account}" if account else "") + ": ")
        if not new_v:
            print("aborted (empty input)", file=sys.stderr); sys.exit(2)
        _cv.rotate_secret(site, _f(field, account), new_v)
        print(f"rotated {field} for {site}" + (f" account={account}" if account else ""))
        return

    if sub == "use":
        u = _cv.get_secret(site, _f("username", account)) or ""
        p = _cv.get_secret(site, _f("password", account)) or ""
        if not (u and p):
            print(f"no creds stored for {site}"
                   + (f" account={account}" if account else "") +
                   " — run `wpsecscan creds add` first", file=sys.stderr)
            sys.exit(2)
        # Print POSIX-friendly export lines so `eval $(...)` works.
        u_esc = u.replace("'", "'\"'\"'")
        p_esc = p.replace("'", "'\"'\"'")
        print(f"export WPSECSCAN_AUTH_USER='{u_esc}'")
        print(f"export WPSECSCAN_AUTH_PASS='{p_esc}'")
        return

    print(f"unknown creds subcommand: {sub}", file=sys.stderr); sys.exit(64)


def _cmd_dashboard_templates(args: list[str]) -> None:
    """Item #66 — print bundled Datadog / New Relic dashboard templates.

      wpsecscan dashboard-templates datadog
      wpsecscan dashboard-templates newrelic
      wpsecscan dashboard-templates list

    Pipe into a file then import in the respective product. Useful when
    you've wired up the SIEM forwarders (`--siem-datadog` / Logstash) and
    want a starting-point dashboard instead of building it by hand.
    """
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_dashboard_templates.__doc__.strip()); return
    data_dir = Path(__file__).parent / "data"
    mapping = {
        "datadog":  data_dir / "datadog-dashboard.json",
        "newrelic": data_dir / "newrelic-dashboard.json",
    }
    if args[0] == "list":
        for name, p in mapping.items():
            mark = "✓" if p.exists() else "•"
            print(f"  {mark} {name:10s}  {p}")
        return
    target = args[0].lower()
    if target not in mapping:
        print(f"unknown template: {target}; try 'datadog' or 'newrelic'", file=sys.stderr)
        sys.exit(64)
    sys.stdout.write(mapping[target].read_text(encoding="utf-8"))


def _cmd_slack_app(args: list[str]) -> None:
    """Item #63 — start the Slack slash-command listener.

      wpsecscan slack-app [--port 5000] [--host 0.0.0.0]

    Set $WPSECSCAN_SLACK_SIGNING_SECRET first. Put it behind a TLS reverse
    proxy; Slack requires HTTPS for the slash-command Request URL.
    """
    if args and args[0] in ("-h", "--help"):
        print(_cmd_slack_app.__doc__.strip()); sys.exit(0)
    host = "0.0.0.0"
    port = 5000
    for i, a in enumerate(args):
        if a == "--port" and i + 1 < len(args):
            port = int(args[i + 1])
        elif a == "--host" and i + 1 < len(args):
            host = args[i + 1]
    from . import slack_app as _sa
    _sa.serve(host=host, port=port)


def _cmd_pr_status(args: list[str]) -> None:
    """Item #62 — post a GitHub Check Run for the most-recent scan.

      wpsecscan pr-status OWNER/REPO SHA URL [--fail-on high]

    Different from `pr-comment`: this is a Check Run that branch-
    protection rules can REQUIRE before merge. Uses $GITHUB_TOKEN with
    `checks:write` scope. The verdict is derived from the saved JSON
    snapshot of the most-recent scan of URL.
    """
    import json
    if not args or args[0] in ("-h", "--help") or len(args) < 3:
        print("usage: wpsecscan pr-status OWNER/REPO SHA URL [--fail-on high]",
              file=sys.stderr)
        sys.exit(64)
    if "/" not in args[0]:
        print(f"OWNER/REPO must be slash-separated; got {args[0]!r}", file=sys.stderr)
        sys.exit(64)
    owner, repo = args[0].split("/", 1)
    sha = args[1]
    url = args[2]
    fail_on = "high"
    for i, a in enumerate(args[3:]):
        if a == "--fail-on" and i + 4 < len(args) + 3:
            fail_on = args[i + 4]
    from . import history as _h
    snaps = _h.snapshot_history(url)
    if not snaps:
        print(f"no saved scan found for {url} — run a scan first", file=sys.stderr)
        sys.exit(2)
    data = json.loads(snaps[-1].read_text(encoding="utf-8"))
    # Rehydrate just enough into a ScanReport-shaped object for gh_check_run.
    from .models import ScanReport, CheckResult, Finding
    results = [
        CheckResult(
            check_id=r["check_id"],
            check_name=r.get("check_name", ""),
            findings=[Finding(
                severity=f["severity"], title=f.get("title", ""),
                evidence=f.get("evidence", ""), remediation=f.get("remediation", ""),
                url=f.get("url", ""), extra=f.get("extra") or {},
            ) for f in r.get("findings", [])],
            error=r.get("error"),
            duration_ms=int(r.get("duration_ms", 0)),
        ) for r in data.get("results", [])
    ]
    report = ScanReport(
        target=data.get("target", url),
        scanned_at=data.get("scanned_at", ""),
        duration_ms=int(data.get("duration_ms", 0)),
        results=results,
    )
    from . import gh_check_run as _gh
    try:
        resp = _gh.post_check_run(report, owner, repo, sha, fail_on=fail_on)
        print(f"check-run created: id={resp.get('id')} conclusion={resp.get('conclusion')} "
               f"url={resp.get('html_url')}")
    except RuntimeError as e:
        print(f"check-run failed: {e}", file=sys.stderr); sys.exit(2)


def _cmd_playbook(args: list[str]) -> None:
    """Item #59 — playbook authoring CLI.

      wpsecscan playbook add CHECK_ID --how "<prose>" \\
                           [--curl "<cmd>" ...] [--sqlmap "<cmd>"] \\
                           [--nuclei-tag "<tag>"] [--wpscan "<cmd>"] \\
                           [--reference "<URL>" ...]
      wpsecscan playbook show CHECK_ID
      wpsecscan playbook rm   CHECK_ID
      wpsecscan playbook list

    Writes to ~/.wpsecscan/playbook.json; merged on top of the bundled
    defaults at scan time (see playbook.py).
    """
    import json
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan playbook {add|show|rm|list} CHECK_ID [opts]")
        return
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    home.mkdir(parents=True, exist_ok=True)
    user_path = home / "playbook.json"
    try:
        user_data = json.loads(user_path.read_text(encoding="utf-8")) if user_path.exists() else {}
    except (OSError, json.JSONDecodeError):
        user_data = {}

    sub = args[0]
    if sub == "list":
        from . import playbook as _pb
        merged = _pb._load()
        bundled_ids = set()
        try:
            import wpsecscan
            bundled_path = Path(wpsecscan.__file__).parent / "data" / "exploit_playbook.json"
            if bundled_path.exists():
                bundled = json.loads(bundled_path.read_text(encoding="utf-8"))
                bundled_ids = {k for k in bundled if not k.startswith("_")}
        except Exception:  # noqa: BLE001
            pass
        print(f"{len(merged)} playbook entries (bundled + user):")
        for cid in sorted(merged):
            tag = "user" if cid in user_data else "bundled" if cid in bundled_ids else "?"
            print(f"  [{tag:8s}]  {cid}")
        return

    if len(args) < 2:
        print("usage: wpsecscan playbook {add|show|rm} CHECK_ID [opts]", file=sys.stderr)
        sys.exit(64)
    check_id = args[1].strip()

    if sub == "show":
        entry = user_data.get(check_id)
        if entry:
            print(f"(user) {check_id}:")
            print(json.dumps(entry, indent=2))
        else:
            from . import playbook as _pb
            entry = _pb.get_playbook(check_id)
            if entry:
                print(f"(bundled) {check_id}:")
                print(json.dumps(entry, indent=2))
            else:
                print(f"no playbook for check_id {check_id!r}", file=sys.stderr)
                sys.exit(2)
        return

    if sub == "rm":
        if check_id not in user_data:
            print(f"no user playbook for {check_id!r}", file=sys.stderr); sys.exit(2)
        del user_data[check_id]
        user_path.write_text(json.dumps(user_data, indent=2), encoding="utf-8")
        print(f"removed {check_id} from {user_path}")
        return

    if sub == "add":
        entry: dict[str, object] = dict(user_data.get(check_id) or {})
        i = 2
        # Multi-value buckets get appended; single-value buckets replace.
        list_buckets = {
            "--curl": "manual_curl_pocs",
            "--sqlmap": "sqlmap",
            "--metasploit": "metasploit",
            "--nuclei": "nuclei",
            "--wpscan": "wpscan",
            "--ffuf": "ffuf_gobuster",
            "--reference": "references",
        }
        while i < len(args):
            flag = args[i]
            if flag == "--how" and i + 1 < len(args):
                entry["how_an_attacker_uses_this"] = args[i + 1]
                i += 2
                continue
            if flag == "--nuclei-tag" and i + 1 < len(args):
                tags = entry.setdefault("nuclei_tags", [])
                if isinstance(tags, list):
                    tags.append(args[i + 1])
                i += 2
                continue
            if flag in list_buckets and i + 1 < len(args):
                bucket = list_buckets[flag]
                cur = entry.setdefault(bucket, [])
                if isinstance(cur, list):
                    cur.append(args[i + 1])
                i += 2
                continue
            print(f"unknown flag: {flag}", file=sys.stderr); sys.exit(64)
        user_data[check_id] = entry
        user_path.write_text(json.dumps(user_data, indent=2), encoding="utf-8")
        print(f"saved playbook for {check_id} → {user_path}")
        # Invalidate the in-process cache so a subsequent scan picks it up.
        try:
            from . import playbook as _pb
            _pb.reset_cache()
        except ImportError:
            pass
        return

    print(f"unknown playbook subcommand: {sub}", file=sys.stderr)
    sys.exit(64)


def _cmd_diff_agency(args: list[str]) -> None:
    """`wpsecscan diff-agency OLD.html NEW.html [--out diff.html]` —
    item #55: compare two agency dashboards side by side. Reads the
    embedded JSON manifest from each dashboard; falls back to scraping
    the rendered table for pre-#55 dashboards. Useful for month-over-
    month portfolio review.
    """
    if not args or args[0] in ("-h", "--help") or len(args) < 2:
        print("usage: wpsecscan diff-agency OLD.html NEW.html [--out diff.html]",
              file=sys.stderr)
        sys.exit(64)
    old_p = Path(args[0]).expanduser()
    new_p = Path(args[1]).expanduser()
    out_p = Path("agency-diff.html")
    for i, a in enumerate(args[2:]):
        if a == "--out" and i + 3 < len(args) + 2:
            out_p = Path(args[i + 3]).expanduser()
    if not old_p.exists():
        print(f"OLD dashboard not found: {old_p}", file=sys.stderr); sys.exit(2)
    if not new_p.exists():
        print(f"NEW dashboard not found: {new_p}", file=sys.stderr); sys.exit(2)
    from .reporters import diff_agency as _da
    d = _da.write(old_p, new_p, out_p)
    print(f"Sites: {d['site_count_old']} → {d['site_count_new']} "
           f"({len(d['added'])} added, {len(d['removed'])} removed, "
           f"{len(d['changed'])} changed)")
    print(f"Diff written: {out_p}")
    # Exit 1 if anything regressed (any new critical/high or score drop), 0 otherwise.
    regressed = any((c.get("delta") or 0) < 0 for c in d["changed"])
    regressed = regressed or (d["totals_delta"].get("critical", 0) > 0
                              or d["totals_delta"].get("high", 0) > 0)
    sys.exit(1 if regressed else 0)


def _cmd_publish(args: list[str]) -> None:
    """`wpsecscan publish URL [--out DIR]`

    Generate a small static HTML page declaring "this site was scanned by
    WPSecScan on YYYY-MM-DD; current risk score is N/100". The page
    embeds a JSON-LD receipt (target, scanned_at, risk_score) signed
    with a per-install hardware-key (when available) or HMAC over the
    bundled ~/.wpsecscan/publish-secret.json otherwise.

    The site owner uploads the page somewhere on their site and links
    it from their footer. Visitors can manually compare the score on
    the page to a fresh wpsecscan run to confirm the page hasn't been
    tampered with.
    """
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_publish.__doc__.strip()); sys.exit(0 if args else 2)
    target = args[0]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    out_dir = "wpsecscan-publish"
    for i, a in enumerate(args):
        if a == "--out" and i + 1 < len(args):
            out_dir = args[i + 1]

    from . import history as _h
    import json as _json
    import hmac as _hmac
    import hashlib as _hash
    from datetime import datetime, timezone

    snaps = _h.snapshot_history(target)
    if not snaps:
        print(f"no saved snapshots for {target}; run `wpsecscan {target}` first.")
        sys.exit(64)
    latest_path = snaps[-1]
    latest = _json.loads(latest_path.read_text(encoding="utf-8"))
    risk_score = latest.get("risk_score", "?")
    scanned_at = latest.get("scanned_at", "")
    s = latest.get("summary", {})

    # Per-install secret for signing — generated on first publish.
    home = Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))
    secret_path = home / "publish-secret.json"
    if not secret_path.exists():
        home.mkdir(parents=True, exist_ok=True)
        import secrets as _secrets
        secret_path.write_text(_json.dumps({"secret": _secrets.token_hex(32)}),
                                encoding="utf-8")
    secret = _json.loads(secret_path.read_text(encoding="utf-8"))["secret"]

    receipt = {
        "@context": "https://schema.org",
        "@type": "ReviewAction",
        "target": target,
        "scanned_at": scanned_at,
        "risk_score": risk_score,
        "summary": {k: int(s.get(k, 0)) for k in ("critical", "high", "medium", "low", "info")},
        "scanner": "WPSecScan",
        "scanner_url": "https://github.com/bryanflowers/wpsecscan",
        "published": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    canonical = _json.dumps(receipt, sort_keys=True).encode("utf-8")
    sig = _hmac.new(secret.encode("utf-8"), canonical, _hash.sha256).hexdigest()
    receipt["signature"] = f"sha256={sig}"

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Build the HTML page.
    tier = "green" if isinstance(risk_score, int) and risk_score >= 80 else (
            "yellow" if isinstance(risk_score, int) and risk_score >= 60 else "orange")
    color = {"green": "#1f8a3c", "yellow": "#c47700", "orange": "#d35400"}[tier]
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security scan receipt — {target}</title>
<style>
  body{{font:14px/1.5 -apple-system,Segoe UI,sans-serif;color:#222;background:#fafafa;
        margin:0;padding:40px 20px;display:flex;justify-content:center}}
  main{{max-width:640px;background:#fff;border:1px solid #ddd;border-radius:10px;
        padding:32px 36px;box-shadow:0 1px 3px rgba(0,0,0,.04)}}
  h1{{margin:0 0 6px;font-size:20px}}
  .meta{{color:#666;font-size:13px;margin-bottom:18px}}
  .score{{font-size:60px;font-weight:800;color:{color};line-height:1;margin-top:18px}}
  .grade{{font-size:14px;color:#888;margin-bottom:14px}}
  table{{width:100%;border-collapse:collapse;margin:14px 0;font-size:13px}}
  th,td{{border:1px solid #ddd;padding:6px 10px;text-align:center}}
  th{{background:#f7f7f7;font-weight:600}}
  .verify{{margin-top:20px;font-size:12px;color:#666;background:#f7f7f7;
            border:1px solid #eee;border-radius:6px;padding:12px}}
  code{{background:#f0f0f0;padding:2px 5px;border-radius:3px;font:12px/1.4 ui-monospace,Consolas,monospace}}
  footer{{text-align:center;margin-top:24px;font-size:11px;color:#999}}
</style>
<script type="application/ld+json">{_json.dumps(receipt, indent=2)}</script>
</head>
<body>
<main>
  <h1>Security scan receipt</h1>
  <div class="meta">Target: <strong>{target}</strong><br>Scanned: {scanned_at}</div>
  <div class="score">{risk_score}/100</div>
  <div class="grade">WPSecScan risk score · scanner {receipt['scanner']}</div>
  <table>
    <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
    <tr><td>{s.get('critical',0)}</td><td>{s.get('high',0)}</td>
        <td>{s.get('medium',0)}</td><td>{s.get('low',0)}</td><td>{s.get('info',0)}</td></tr>
  </table>
  <div class="verify">
    <strong>Verify this receipt:</strong> the JSON-LD block in this page's
    <code>&lt;head&gt;</code> contains a HMAC-SHA256 signature. To verify,
    run <code>wpsecscan publish {target} --verify PATH/TO/THIS/FILE</code>
    on the host that originally signed it.
  </div>
  <footer>Generated by <a href="{receipt['scanner_url']}">WPSecScan</a>
    on {receipt['published']}.</footer>
</main>
</body>
</html>
"""
    page_path = out / "scan-receipt.html"
    page_path.write_text(html, encoding="utf-8")
    # Also drop the canonical JSON next to it so the signature can be
    # re-verified mechanically.
    (out / "scan-receipt.json").write_text(_json.dumps(receipt, indent=2),
                                              encoding="utf-8")
    print(f"published: {page_path}")
    print(f"           {out / 'scan-receipt.json'}")
    print(f"upload both files to your site; link the .html from your footer.")


def _cmd_pr_comment(args: list[str]) -> None:
    """`wpsecscan pr-comment PR_URL`

    Inspect a GitHub PR's file list and post (or update) a comment listing
    currently-open CVEs for any plugin/theme slug under `wp-content/`
    that the PR touches. The comment is keyed by an HTML marker so
    repeat runs update the same comment rather than spamming.

    Uses $GITHUB_TOKEN. Pass --dry-run to print the would-be-comment
    without contacting GitHub.
    """
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_pr_comment.__doc__.strip()); sys.exit(0 if args else 2)
    pr_url = args[0]
    dry = "--dry-run" in args[1:]

    from . import pr_inspector as _pi
    parsed = _pi._parse_pr_url(pr_url)
    if not parsed:
        print(f"not a recognized GitHub PR URL: {pr_url}", file=sys.stderr)
        sys.exit(2)
    owner, repo, pr_n = parsed
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("WPSECSCAN_GITHUB_TOKEN", "")
    if not token and not dry:
        print("set $GITHUB_TOKEN to post comments; or pass --dry-run", file=sys.stderr)
        sys.exit(2)

    touched = _pi.list_changed_slugs(owner, repo, pr_n, token) if token else {"plugins": [], "themes": []}
    findings = _pi.find_known_cves(touched.get("plugins", []), touched.get("themes", []))
    body = _pi.build_comment(touched, findings)

    if dry:
        print("--- DRY RUN ---")
        print(body)
        return
    ok, msg = _pi.post_or_update(owner, repo, pr_n, token, body)
    if ok:
        print(f"✓ {msg}")
    else:
        print(f"FAILED: {msg}", file=sys.stderr)
        sys.exit(1)


def _cmd_diff_tree(args: list[str]) -> None:
    """`wpsecscan diff-tree URL [--limit N]`

    Render a chronological ASCII tree of finding-deltas across the last N
    snapshots (default 10) for URL. Each snapshot row shows + new, - fixed,
    and the running risk-score.
    """
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_diff_tree.__doc__.strip()); sys.exit(0 if args else 2)
    target = args[0]
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    limit = 10
    for i, a in enumerate(args):
        if a == "--limit" and i + 1 < len(args):
            try:
                limit = max(2, int(args[i + 1]))
            except ValueError:
                pass

    from . import history as _h
    import json as _json
    snaps = _h.snapshot_history(target)
    if len(snaps) < 2:
        print(f"need at least 2 snapshots for {target}; found {len(snaps)}.")
        sys.exit(64)
    snaps = snaps[-limit:]

    def _key_set(report: dict, min_sev: tuple = ("low", "medium", "high", "critical")) -> set[str]:
        out = set()
        for r in report.get("results", []) or []:
            for f in r.get("findings", []) or []:
                if f.get("severity") in min_sev:
                    out.add(f"{r.get('check_id','')}::{f.get('title','')}")
        return out

    prev: set[str] = set()
    print(f"diff-tree for {target} (last {len(snaps)} snapshots):\n")
    for i, sp in enumerate(snaps):
        try:
            data = _json.loads(sp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        ts = data.get("scanned_at") or sp.stem.split("-")[-1]
        cur = _key_set(data)
        added = sorted(cur - prev)
        removed = sorted(prev - cur)
        score = data.get("risk_score", "?")
        prefix = "├──" if i < len(snaps) - 1 else "└──"
        print(f"{prefix} {ts}  score={score}  total={len(cur)}  +{len(added)} -{len(removed)}")
        bar = "│  " if i < len(snaps) - 1 else "   "
        for t in added[:5]:
            print(f"{bar}  + {t[:90]}")
        for t in removed[:5]:
            print(f"{bar}  - {t[:90]}")
        prev = cur


def _cmd_snooze(args: list[str]) -> None:
    """`wpsecscan snooze {list|import|clear} ...`

    list [--active-only]
        Print every (URL, check_id, finding_title, status, snooze_until)
        from ~/.wpsecscan/annotations.json. With --active-only, hide
        snoozes that have already expired.

    import FILE.csv
        Bulk-snooze (or bulk-accept-risk) from a CSV with header columns:
          url, check_id, finding_title, status, snooze_until, note
        Status is one of: accepted-risk, false-positive. snooze_until
        is an ISO date YYYY-MM-DD; leave blank for "indefinite".

    clear URL [CHECK_ID [TITLE]]
        Remove annotation(s). Without CHECK_ID, clears every annotation
        for the URL. With CHECK_ID, only that check's annotations.
    """
    if not args or args[0] in ("-h", "--help"):
        print(_cmd_snooze.__doc__.strip()); sys.exit(0)

    from . import history as _h
    action = args[0]
    rest = args[1:]

    if action == "list":
        active_only = "--active-only" in rest
        ann = _h.load_annotations()
        rows: list[tuple[str, str, str, str, str]] = []
        for url, bucket in sorted(ann.items()):
            for fp, entry in bucket.items():
                if active_only and not _h.is_active_annotation(entry):
                    continue
                rows.append((
                    url,
                    str(entry.get("check_id") or fp.split(":", 1)[0]),
                    str(entry.get("title") or fp.split(":", 1)[-1])[:40],
                    str(entry.get("status") or ""),
                    str(entry.get("snooze_until") or ""),
                ))
        if not rows:
            print("(no annotations)")
            return
        print(f"{'URL':50s} {'CHECK':16s} {'TITLE':40s} {'STATUS':16s} SNOOZE")
        for url, cid, title, status, snooze in rows:
            print(f"{url[:50]:50s} {cid[:16]:16s} {title:40s} {status[:16]:16s} {snooze}")
        return

    if action == "import":
        if not rest:
            print("usage: wpsecscan snooze import FILE.csv", file=sys.stderr)
            sys.exit(2)
        import csv as _csv
        path = Path(rest[0])
        if not path.exists():
            print(f"file not found: {path}", file=sys.stderr); sys.exit(2)
        count = 0
        with path.open(encoding="utf-8") as f:
            reader = _csv.DictReader(f)
            for row in reader:
                url = (row.get("url") or "").strip()
                cid = (row.get("check_id") or "").strip()
                title = (row.get("finding_title") or row.get("title") or "").strip()
                status = (row.get("status") or "accepted-risk").strip()
                snooze = (row.get("snooze_until") or "").strip()
                note = (row.get("note") or "").strip()
                if not (url and cid and title):
                    continue
                _h.set_annotation(url, cid, title, status,
                                    note=note, snooze_until=snooze)
                count += 1
        print(f"imported {count} annotation(s) from {path}")
        return

    if action == "clear":
        if not rest:
            print("usage: wpsecscan snooze clear URL [CHECK_ID [TITLE]]", file=sys.stderr)
            sys.exit(2)
        url = rest[0]
        cid_filter = rest[1] if len(rest) > 1 else None
        title_filter = rest[2] if len(rest) > 2 else None
        ann = _h.load_annotations()
        bucket = ann.get(url, {})
        before = len(bucket)
        if cid_filter and title_filter:
            _h.set_annotation(url, cid_filter, title_filter, "")  # empty status clears
            after = len(_h.load_annotations().get(url, {}))
            print(f"cleared 1 annotation ({cid_filter} / {title_filter})")
        elif cid_filter:
            # iterate by fingerprint prefix
            for fp in list(bucket.keys()):
                if fp.startswith(cid_filter + ":"):
                    title = bucket[fp].get("title") or fp.split(":", 1)[-1]
                    _h.set_annotation(url, cid_filter, title, "")
            after = len(_h.load_annotations().get(url, {}))
            print(f"cleared {before - after} annotation(s) for {cid_filter}")
        else:
            # nuke all for this URL
            ann.pop(url, None)
            _h._save_annotations(ann)
            print(f"cleared {before} annotation(s) for {url}")
        return

    print(f"unknown snooze action: {action}", file=sys.stderr)
    sys.exit(2)


def _cmd_config(args: list[str]) -> None:
    """`wpsecscan config validate <path>` — lint the daemon YAML config."""
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan config validate <path>")
        return
    if args[0] != "validate" or len(args) < 2:
        print("usage: wpsecscan config validate <path>", file=sys.stderr)
        sys.exit(64)
    issues = _validate_yaml_config(Path(args[1]))
    if not issues:
        print(f"OK — {args[1]} validated cleanly.")
        return
    print(f"FAIL — {len(issues)} issue(s) in {args[1]}:")
    for i in issues:
        print(f"  - {i}")
    sys.exit(1)


def _validate_yaml_config(path: Path) -> list[str]:
    """Lint the daemon YAML config; return a list of human-readable issues
    (empty list = valid). Used by the new `wpsecscan config validate` cmd."""
    issues: list[str] = []
    if not path.exists():
        return [f"file not found: {path}"]
    try:
        import yaml as _yaml  # type: ignore
    except ImportError:
        return ["PyYAML not installed (pip install pyyaml or pip install wpsecscan[yaml])"]
    try:
        doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    except _yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]
    if not isinstance(doc, dict):
        return ["top-level must be a mapping (key: value, ...)"]
    schedule = doc.get("schedule") or {}
    if not isinstance(schedule, dict):
        issues.append("`schedule` must be a mapping")
    targets = doc.get("targets") or doc.get("sites") or []
    if not isinstance(targets, list):
        issues.append("`targets` (or `sites`) must be a list")
    elif not targets:
        issues.append("`targets` is empty — daemon would do nothing")
    for i, t in enumerate(targets if isinstance(targets, list) else []):
        if isinstance(t, str):
            if not t.startswith(("http://", "https://")):
                issues.append(f"targets[{i}]: URL must start with http:// or https://")
        elif isinstance(t, dict):
            if not t.get("url"):
                issues.append(f"targets[{i}]: missing `url` key")
        else:
            issues.append(f"targets[{i}]: must be string URL or mapping with `url`")
    cron = doc.get("cron")
    if cron and not isinstance(cron, str):
        issues.append("`cron` must be a string in 5-field cron format")
    return issues


def _cmd_paths(args: list[str]) -> None:
    """`wpsecscan paths` — print the canonical ~/.wpsecscan/ layout with
    a short description and the current on-disk size of each entry.
    Useful for operators who want to know where to back up / clean up
    state without grepping the source."""
    if args and args[0] in ("-h", "--help"):
        print("usage: wpsecscan paths  (prints ~/.wpsecscan/ layout + current sizes)")
        return
    from . import history as _h
    home = _h._home()
    items = [
        ("history.json",                        "Last 20 scanned URLs (GUI dropdown)"),
        ("profiles.json",                       "Named scan profiles"),
        ("settings.json",                       "Tokens from the GUI onboarding wizard"),
        ("sites.json",                          "Managed sites list (`wpsecscan sites`)"),
        ("schedule_state.json",                 "Scheduled-scan cron state"),
        ("digest.json",                         "SMTP / webhook digest config"),
        ("annotations.json",                    "Per-finding annotations"),
        ("comments.json",                       "Per-finding free-text comments"),
        ("stars.json",                          "Starred findings"),
        ("disabled_checks.json",                "Persistently disabled check IDs"),
        ("reports/",                            "Saved JSON / HTML snapshots + timestamped history"),
        ("cache/wporg/",                        "24h-cached wp.org plugin metadata"),
        ("checkpoints/",                        "--checkpoint resumable scan state"),
        ("logs/",                               "--debug log files (rotating)"),
        ("demo/",                               "--demo synthetic-scan artifacts"),
        ("analytics/events.jsonl",              "Opt-in analytics (off by default)"),
        ("wordfence.json",                      "Aggregated CVE database cache"),
    ]
    def _size(p: Path) -> str:
        if not p.exists():
            return "(absent)"
        if p.is_dir():
            total = 0
            n = 0
            for f in p.rglob("*"):
                try:
                    if f.is_file():
                        total += f.stat().st_size
                        n += 1
                except OSError:
                    pass
            return f"{total/1024:>8.1f} KB  ({n} files)"
        try:
            return f"{p.stat().st_size/1024:>8.1f} KB"
        except OSError:
            return "(error)"
    print(f"WPSECSCAN_HOME = {home}\n")
    for name, desc in items:
        p = home / name
        print(f"  {name:36s}  {_size(p):>22s}  {desc}")
    print(f"\nOverride the base directory with the WPSECSCAN_HOME env var.")


def _cmd_compare(args: list[str]) -> None:
    """`wpsecscan compare URL` — diff the two most recent snapshots of URL.

    Snapshots are auto-saved under ~/.wpsecscan/reports/{safe}-{ts}.json by
    every scan. Exits 0 if no new findings, 1 if any added since prior scan.
    """
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan compare <URL>", file=sys.stderr)
        sys.exit(64)
    url = args[0]
    # Normalise scheme-less URLs (`example.com` → `https://example.com`) so the
    # snapshot lookup uses a real hostname instead of falling back to "site"
    # which would match every scheme-less scan.
    if "://" not in url:
        url = "https://" + url
    from . import history as _h
    snaps = _h.snapshot_history(url)
    if len(snaps) < 2:
        msg = ("Need at least 2 saved snapshots to compare; "
               f"found {len(snaps)} for {url}. "
               f"Run `wpsecscan {url}` a couple of times first.")
        print(msg, file=sys.stderr)
        sys.exit(64)
    old, new = snaps[-2], snaps[-1]
    print(f"Comparing:\n  before: {old.name}\n  after:  {new.name}\n", file=sys.stderr)
    d = diff_mod.diff(old, new)
    print(diff_mod.render_text(d))
    sys.exit(0 if not d.get("new") else 1)


def _cmd_badge(args: list[str]) -> None:
    """`wpsecscan badge URL [--out badge.svg]` — emit a shields.io-style SVG
    of the most recent scan's grade. Reads the canonical
    `~/.wpsecscan/reports/{safe}.json`."""
    if not args or args[0] in ("-h", "--help"):
        print("usage: wpsecscan badge <URL> [--out badge.svg]", file=sys.stderr)
        sys.exit(64)
    url = args[0]
    out_path: Path | None = None
    # Replaced the previous fragile enumerate(args[1:], 1) + args[i+1] dance
    # with a plain index walk over the remaining args.
    i = 1
    while i < len(args):
        if args[i] == "--out" and i + 1 < len(args):
            out_path = Path(args[i + 1])
            i += 2
        else:
            i += 1
    from . import history as _h
    from .reporters import badge_svg as _bs
    snap = _h.previous_report_path(url)
    if snap is None:
        print(f"No saved snapshot for {url}. Run `wpsecscan {url}` first.",
              file=sys.stderr)
        sys.exit(64)
    import json as _json
    try:
        data = _json.loads(snap.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"Could not read snapshot: {e}", file=sys.stderr)
        sys.exit(1)
    summary = data.get("summary") or {}
    svg = _bs.render_badge_svg(summary)
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(svg, encoding="utf-8")
        print(f"Wrote badge: {out_path}", file=sys.stderr)
    else:
        print(svg)


def _cmd_ai_options(args: list[str]) -> None:
    """Round-65 Group C — manage Advanced AI triage settings.

    Usage:
        wpsecscan ai-options list
        wpsecscan ai-options get <field>
        wpsecscan ai-options set <field> <value>
    """
    if args and args[0] in ("-h", "--help"):
        print("usage: wpsecscan ai-options {list | get <field> | set <field> <value>}")
        return
    from . import ai_triage_ui
    if not args or args[0] == "list":
        print(ai_triage_ui.cli_list())
        return
    if args[0] == "get" and len(args) >= 2:
        print(ai_triage_ui.cli_get(args[1]))
        return
    if args[0] == "set" and len(args) >= 3:
        print(ai_triage_ui.cli_set(args[1], args[2]))
        return
    print(_cmd_ai_options.__doc__)
    sys.exit(2)


def _cmd_analytics(args: list[str]) -> None:
    """Round-65 — manage opt-in local usage analytics.

    Usage:
        wpsecscan analytics status
        wpsecscan analytics enable
        wpsecscan analytics disable
        wpsecscan analytics show
        wpsecscan analytics export <path>
        wpsecscan analytics forget
    """
    if args and args[0] in ("-h", "--help"):
        print("usage: wpsecscan analytics {status | enable | disable | show | export <path> | forget}")
        return
    from . import analytics
    if not args or args[0] == "status":
        st = analytics.status()
        print(f"Enabled: {st['enabled']}")
        print(f"Anonymous ID: {st['anonymous_id']}")
        print(f"Events recorded: {st['event_count']}")
        print(f"Storage: {st['storage_path']}")
        print(f"Upload destination: {st['upload_destination'] or '(local only)'}")
        return
    if args[0] == "enable":
        print(analytics.enable())
        return
    if args[0] == "disable":
        print(analytics.disable())
        return
    if args[0] == "show":
        print(analytics.show_recent(limit=int(args[1]) if len(args) > 1 else 50))
        return
    if args[0] == "export" and len(args) >= 2:
        print(analytics.export(args[1]))
        return
    if args[0] == "forget":
        print(analytics.forget())
        return
    print(_cmd_analytics.__doc__)
    sys.exit(2)


def _cmd_sites(args: list[str]) -> None:
    from . import sites as sites_mod
    if not args or args[0] in ("-h", "--help", "help"):
        print("usage: wpsecscan sites {add|list|remove|scan} ...")
        return
    action = args[0]
    rest = args[1:]
    if action == "list":
        # #31: --tag FOO filter
        tag_filter = None
        for i, a in enumerate(rest):
            if a == "--tag" and i + 1 < len(rest):
                tag_filter = rest[i + 1].lower()
                break
        for s in sites_mod.list_sites():
            tags = s.get("tags") or []
            if tag_filter and tag_filter not in tags:
                continue
            ts = s.get("last_scan_ts") or 0
            when = "never" if not ts else __import__("time").strftime("%Y-%m-%d", __import__("time").localtime(ts))
            tag_str = (" [" + ",".join(tags) + "]") if tags else ""
            print(f"  {s['url']:60s} weekly={s.get('weekly', False)}  last={when}  risk={s.get('last_risk_score', '?')}{tag_str}")
        return
    if action == "remove":
        if not rest:
            print("usage: wpsecscan sites remove URL"); sys.exit(2)
        ok = sites_mod.remove(rest[0])
        print("removed" if ok else "not found")
        return
    if action == "add":
        url = None
        flags = {"weekly": False, "auth_user": None, "auth_app_password": None,
                  "companion_token": None, "proxy_url": None, "proxy_auth": None,
                  "notes": "", "tags": None}
        i = 0
        while i < len(rest):
            a = rest[i]
            if a == "--weekly":
                flags["weekly"] = True; i += 1
            elif a == "--auth-user" and i + 1 < len(rest):
                flags["auth_user"] = rest[i + 1]; i += 2
            elif a == "--auth-app-password" and i + 1 < len(rest):
                flags["auth_app_password"] = rest[i + 1]; i += 2
            elif a == "--companion-token" and i + 1 < len(rest):
                flags["companion_token"] = rest[i + 1]; i += 2
            elif a == "--proxy" and i + 1 < len(rest):
                flags["proxy_url"] = rest[i + 1]; i += 2
            elif a == "--proxy-auth" and i + 1 < len(rest):
                flags["proxy_auth"] = rest[i + 1]; i += 2
            elif a == "--notes" and i + 1 < len(rest):
                flags["notes"] = rest[i + 1]; i += 2
            elif a == "--tag" and i + 1 < len(rest):
                if flags["tags"] is None:
                    flags["tags"] = []
                flags["tags"].append(rest[i + 1])
                i += 2
            elif not a.startswith("--") and url is None:
                url = a; i += 1
            else:
                i += 1
        if not url:
            print("usage: wpsecscan sites add URL [--weekly] [--auth-user U] [--auth-app-password P] [--proxy URL] [--proxy-auth user:pass] [--tag client:foo]"); sys.exit(2)
        entry = sites_mod.add(url, **flags)
        tag_str = (" tags=" + ",".join(entry.get("tags", []))) if entry.get("tags") else ""
        print(f"added: {entry['url']} (weekly={entry['weekly']}{', proxied' if flags['proxy_url'] else ''}{tag_str})")
        return
    if action == "scan":
        from . import sites as sites_mod
        targets = [rest[0]] if rest else None
        sites_to_scan = [sites_mod.get(targets[0])] if targets else sites_mod.due_now()
        sites_to_scan = [s for s in sites_to_scan if s]
        if not sites_to_scan:
            print("nothing due. use `wpsecscan sites scan URL` to force one.")
            return
        print(f"scanning {len(sites_to_scan)} site(s)...")
        for s in sites_to_scan:
            url = s["url"]
            print(f"  -> {url}")
            # Shell out to a fresh wpsecscan invocation per site so a crash
            # in one doesn't kill the batch. Pass per-site secrets via env
            # vars rather than CLI args so they don't appear in `ps aux` or
            # shell history; the child process picks them up via argparse
            # defaults (see argparse setup above).
            cmd = [sys.executable, "-m", "wpsecscan", url, "--out", "wpsecscan-reports"]
            child_env = dict(os.environ)
            if s.get("auth_user"):
                child_env["WPSECSCAN_AUTH_USER"] = s["auth_user"]
            if s.get("proxy_url"):
                cmd.extend(["--proxy", s["proxy_url"]])  # not secret
            for sealed_key, env_name in (
                ("proxy_auth_sealed", "WPSECSCAN_PROXY_AUTH"),
                ("auth_app_password_sealed", "WPSECSCAN_AUTH_APP_PASSWORD"),
                ("companion_token_sealed", "WPSECSCAN_COMPANION_TOKEN"),
            ):
                if s.get(sealed_key):
                    try:
                        child_env[env_name] = sites_mod._unseal(s[sealed_key])
                    except Exception:  # noqa: BLE001
                        pass
            # Forward enrichment tokens too (UX-030), again via env not argv.
            for env_name in ("WPSECSCAN_WPSCAN_TOKEN", "WPSECSCAN_PATCHSTACK_TOKEN",
                             "WPSECSCAN_HIBP_TOKEN", "WPSECSCAN_VT_TOKEN",
                             "WPSECSCAN_ABUSEIPDB_TOKEN", "WPSECSCAN_GITHUB_SEARCH_TOKEN"):
                v = os.environ.get(env_name)
                if v:
                    child_env[env_name] = v
            __import__("subprocess").run(cmd, env=child_env, check=False)
        return
    print(f"unknown sites action: {action}", file=sys.stderr); sys.exit(2)


def _cmd_schedule(args: list[str]) -> None:
    from . import sites as sites_mod
    if not args or args[0] in ("-h", "--help", "help"):
        print("usage: wpsecscan schedule {install [--time HH:MM] [--weekly]|uninstall|pause|resume|status}")
        return
    action = args[0]
    if action == "install":
        time_hhmm = "03:00"
        for i, a in enumerate(args[1:]):
            if a == "--time" and i + 2 <= len(args[1:]):
                time_hhmm = args[i + 2]
        res = sites_mod.install_schedule(time_hhmm=time_hhmm)
        print(("OK: " if res["ok"] else "FAIL: ") + f"{res['method']} — {res['detail']}")
    elif action == "uninstall":
        res = sites_mod.uninstall_schedule()
        print(("OK: " if res["ok"] else "FAIL: ") + f"{res['method']} — {res['detail']}")
    elif action == "pause":
        sites_mod.pause(); print("scheduler paused")
    elif action == "resume":
        sites_mod.resume(); print("scheduler resumed")
    elif action == "status":
        print("paused" if sites_mod.is_paused() else "active")
    else:
        print(f"unknown schedule action: {action}", file=sys.stderr); sys.exit(2)


def _cmd_digest(args: list[str]) -> None:
    from . import sites as sites_mod
    if not args or args[0] in ("-h", "--help", "help"):
        print("usage: wpsecscan digest {configure --to ADDR [--smtp HOST] [--slack-webhook URL] | test | send}")
        return
    if args[0] == "configure":
        kv: dict[str, str] = {"to": "", "smtp": "", "smtp_user": "", "smtp_pass": "",
                                 "from_addr": "", "slack_webhook": ""}
        i = 1
        while i < len(args):
            a = args[i].lstrip("-").replace("-", "_")
            if a in kv and i + 1 < len(args):
                kv[a] = args[i + 1]; i += 2
            else:
                i += 1
        if not kv["to"]:
            print("usage: wpsecscan digest configure --to ops@example.com [--smtp host:port --smtp-user U --smtp-pass P --from-addr F]"); sys.exit(2)
        # Either SMTP host or a webhook (notify module reads SLACK_WEBHOOK
        # etc. from env) must be reachable; otherwise the digest silently
        # never sends. Warn at configure time, not at send time.
        import os as _os
        has_webhook = any(_os.environ.get(k) for k in
                          ("WPSECSCAN_SLACK_WEBHOOK", "WPSECSCAN_DISCORD_WEBHOOK",
                           "WPSECSCAN_TEAMS_WEBHOOK", "WPSECSCAN_WEBHOOK_URL"))
        if not kv.get("smtp") and not has_webhook:
            print(
                "[warn] no --smtp host given and no WPSECSCAN_*_WEBHOOK env var set. "
                "Digest will be configured but `digest send` will silently no-op until "
                "you set one. Continue? (Ctrl+C to abort)",
                file=sys.stderr,
            )
        sites_mod.configure_digest(**kv)
        print("digest configured")
    elif args[0] in ("send", "test"):
        cfg = sites_mod.load_digest()
        if not cfg:
            print("no digest configured. run `wpsecscan digest configure --to ...` first."); sys.exit(2)
        body = sites_mod.render_digest(sites_mod.list_sites())
        # Use the existing notify module for actual delivery.
        from . import notify
        try:
            notify.notify("WPSecScan weekly digest", body)
            print("digest sent")
        except Exception as e:  # noqa: BLE001
            print(f"send failed: {e}", file=sys.stderr); sys.exit(1)
    elif args[0] == "schedule":
        # Item #64 — wrap `digest send` in a recurring OS-level task.
        import shutil as _shutil
        import subprocess as _sp
        kw: dict[str, str] = {"time": "08:00", "cadence": "weekly"}
        i = 1
        while i < len(args):
            a = args[i]
            if a == "--time" and i + 1 < len(args):
                kw["time"] = args[i + 1]; i += 2
            elif a == "--weekly":
                kw["cadence"] = "weekly"; i += 1
            elif a == "--daily":
                kw["cadence"] = "daily"; i += 1
            elif a == "--monthly":
                kw["cadence"] = "monthly"; i += 1
            else:
                i += 1
        if not re.match(r"^\d{2}:\d{2}$", kw["time"]):
            print("--time must be HH:MM", file=sys.stderr); sys.exit(64)
        if sys.platform == "win32":
            exe = _shutil.which("wpsecscan") or sys.executable
            cmd_args = ["wpsecscan", "digest", "send"] if exe.endswith("wpsecscan.exe") else [sys.executable, "-m", "wpsecscan", "digest", "send"]
            quoted = '"' + '" "'.join(cmd_args) + '"'
            sc_args = ["schtasks", "/Create", "/TN", "WPSecScanDigest",
                        "/TR", quoted, "/ST", kw["time"], "/F"]
            if kw["cadence"] == "weekly":
                sc_args[6:6] = ["/SC", "WEEKLY", "/D", "MON"]
            elif kw["cadence"] == "daily":
                sc_args[6:6] = ["/SC", "DAILY"]
            else:
                sc_args[6:6] = ["/SC", "MONTHLY", "/D", "1"]
            try:
                r = _sp.run(sc_args, capture_output=True, text=True, timeout=15)
                if r.returncode == 0:
                    print(f"scheduled digest task 'WPSecScanDigest' — {kw['cadence']} {kw['time']}")
                else:
                    print(f"schtasks failed: {(r.stderr or r.stdout)[:200]}", file=sys.stderr)
                    sys.exit(2)
            except (OSError, _sp.TimeoutExpired) as e:
                print(f"schtasks error: {e}", file=sys.stderr); sys.exit(2)
        else:
            # Print the crontab line for the operator to paste.
            hh, mm = kw["time"].split(":")
            if kw["cadence"] == "weekly":
                spec = f"{mm} {hh} * * 1"
            elif kw["cadence"] == "monthly":
                spec = f"{mm} {hh} 1 * *"
            else:
                spec = f"{mm} {hh} * * *"
            cmd = f"{sys.executable} -m wpsecscan digest send"
            print(f"Add this line to your crontab (`crontab -e`):\n\n    {spec} {cmd}\n")
    elif args[0] == "schedule-uninstall":
        if sys.platform == "win32":
            import subprocess as _sp
            try:
                _sp.run(["schtasks", "/Delete", "/TN", "WPSecScanDigest", "/F"],
                         capture_output=True, timeout=10)
                print("removed WPSecScanDigest")
            except (OSError, _sp.TimeoutExpired) as e:
                print(f"schtasks error: {e}", file=sys.stderr); sys.exit(2)
        else:
            print("On Linux/macOS: remove the crontab line you added with `crontab -e`.")
    else:
        print(f"unknown digest action: {args[0]}", file=sys.stderr); sys.exit(2)


def _cmd_ai_cost(args: list[str]) -> None:
    if args and args[0] in ("-h", "--help"):
        print("usage: wpsecscan ai-cost  (prints AI-triage cost summary; no arguments)")
        return
    from . import ai_safety
    summary = ai_safety.cost_summary()
    if not summary:
        print("no AI cost recorded (or WPSECSCAN_NO_AI=1).")
        return
    total = 0.0
    for backend, entry in summary.items():
        usd = float(entry.get("usd", 0))
        total += usd
        print(f"  {backend:12s} {entry.get('calls', 0):5d} calls  "
              f"in={entry.get('in_tokens', 0):>10d}  "
              f"out={entry.get('out_tokens', 0):>10d}  "
              f"${usd:.4f}")
    print(f"  {'TOTAL':12s} ${total:.4f}")


def _cmd_db(args: list[str]) -> None:
    """Round-61: `wpsecscan db {status|update|subscribe|unsubscribe|signatures|alert-check}`."""
    if not args or args[0] in ("-h", "--help", "help"):
        print("usage: wpsecscan db {status|update|source-stats|subscribe|unsubscribe|signatures|alert-check}")
        return
    from . import db as _db

    action = args[0]
    rest = args[1:]

    if action == "status":
        s = _db.status()
        age_days = (s["age_seconds"] // 86400) if s["age_seconds"] >= 0 else -1
        print(f"  source:        {s['source']}")
        print(f"  cache path:    {s['cache_path']}")
        print(f"  cache exists:  {s['cache_exists']}")
        print(f"  entries:       {s['entry_count']:,}")
        print(f"  age:           {age_days} days" if age_days >= 0 else "  age:           n/a (embedded only)")
        print(f"  stale:         {s['stale']}  (threshold {s['stale_after_seconds'] // 86400} days)")
        if s.get("stale"):
            print()
            print("  → Run  `wpsecscan db update`  to refresh.")
        return

    if action == "update":
        try:
            n, p = _db.update_db(verbose=True,
                                   patchstack_token=os.environ.get("WPSECSCAN_PATCHSTACK_TOKEN", ""))
            print(f"OK — {n:,} entries cached at {p}")
        except Exception as e:  # noqa: BLE001
            print(f"FAIL: {e}", file=sys.stderr); sys.exit(1)
        return

    if action == "signatures":
        out = _db.refresh_exploit_signatures()
        if out.get("ok"):
            print(f"OK — {out.get('bytes', 0)} bytes cached at {out.get('path')}")
        else:
            print(f"FAIL: {out.get('error')}", file=sys.stderr); sys.exit(1)
        return

    if action == "subscribe":
        # usage: wpsecscan db subscribe WEBHOOK_URL [--site URL] [--label NAME]
        if not rest:
            print("usage: wpsecscan db subscribe WEBHOOK_URL [--site URL] [--label NAME]"); sys.exit(2)
        webhook = rest[0]
        site = ""
        label = "default"
        i = 1
        while i < len(rest):
            a = rest[i]
            if a == "--site" and i + 1 < len(rest):
                site = rest[i + 1]; i += 2
            elif a == "--label" and i + 1 < len(rest):
                label = rest[i + 1]; i += 2
            else:
                i += 1
        try:
            entry = _db.subscribe(webhook, site_url=site, label=label)
            print(f"subscribed: {entry['webhook_url']} for site={entry['site_url']} (label={entry['label']})")
        except ValueError as e:
            print(f"FAIL: {e}", file=sys.stderr); sys.exit(2)
        return

    if action == "unsubscribe":
        if not rest:
            print("usage: wpsecscan db unsubscribe WEBHOOK_URL [--site URL]"); sys.exit(2)
        webhook = rest[0]
        site = ""
        i = 1
        while i < len(rest):
            if rest[i] == "--site" and i + 1 < len(rest):
                site = rest[i + 1]; i += 2
            else:
                i += 1
        ok = _db.unsubscribe(webhook, site_url=site)
        print("removed" if ok else "not found")
        return

    if action == "alert-check":
        from . import watchers
        out = watchers.cve_alert_check()
        total = len(out["new_alerts"])
        shown = min(20, total)
        print(f"checked {out['checked_sites']} site(s), {total} new alert(s)"
              + (f" (showing first {shown})" if total > 20 else ""))
        for a in out["new_alerts"][:20]:
            print(f"  - {a['site_url']}: {a['plugin_slug']} {a['installed_version'] or '?'} "
                  f"[{a['severity']}] {a['cve']} {a['title']}")
        if total > 20:
            print(f"  ... and {total - 20} more")
        return

    if action == "source-stats":
        s = _db.status()
        sources = _db.cached_sources()
        if not sources:
            print("Cache has no per-source breakdown.")
            print("Either:")
            print("  - cache is empty (run `wpsecscan db update` first), OR")
            print("  - cache predates round-63 (the aggregator format)")
            print(f"Total entries in cache: {s['entry_count']:,}")
            return
        total = sum(sources.values())
        print(f"  {'source':<22s} {'count':>9s}   share")
        print(f"  {'-' * 22} {'-' * 9}   ------")
        for name, n in sorted(sources.items(), key=lambda kv: -kv[1]):
            pct = 100.0 * n / total if total else 0.0
            print(f"  {name:<22s} {n:>9,}   {pct:>5.1f}%")
        print(f"  {'-' * 22} {'-' * 9}")
        print(f"  {'TOTAL (after dedup)':<22s} {s['entry_count']:>9,}")
        age_days = (s["age_seconds"] // 86400) if s["age_seconds"] >= 0 else -1
        print(f"\n  cache age:    {age_days} days  "
              f"({'STALE' if s['stale'] else 'fresh'})")
        print(f"  cache path:   {s['cache_path']}")
        return

    print(f"unknown db action: {action}", file=sys.stderr); sys.exit(2)


if __name__ == "__main__":
    main()
