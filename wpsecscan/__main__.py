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


def _outdir(arg: str | None) -> Path:
    if not arg:
        return Path.cwd()
    # Canonicalize so `--out ../../foo` shows up resolved in output messages
    # and prevents subtle directory-confusion bugs downstream.
    p = Path(arg).expanduser()
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

    if not args.no_console:
        console_reporter.render(report, console)

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

    if args.dashboard and all_reports:
        out_dir = _outdir(args.out)
        dpath = out_dir / "wpsecscan-dashboard.html"
        dashboard_reporter.write(all_reports, dpath)
        if not args.no_console:
            console.print(f"[green]✓[/green] Batch dashboard: [bold]{dpath}[/bold]")

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


def main() -> None:
    # ---- Subcommand dispatch (round-60): keep before argparse so existing
    # `wpsecscan <url>` invocations stay backward-compatible.
    if len(sys.argv) >= 2 and sys.argv[1] in (
        "sites", "schedule", "digest", "ai-cost", "db", "ai-options", "analytics",
        "compare", "badge",
    ):
        _dispatch_subcommand(sys.argv[1], sys.argv[2:])
        return

    p = argparse.ArgumentParser(
        prog="wpsecscan",
        description=(
            "WPSecScan — defensive WordPress security scanner. "
            "Use only on sites you own or have written permission to test."
        ),
    )
    p.add_argument("target", nargs="?", help="URL to scan (e.g. https://example.com)")
    p.add_argument("--file", help="File containing URLs, one per line (# comments OK)")
    p.add_argument("--out", help="Output directory or filename stem")
    p.add_argument("--timeout", type=float, default=15.0, help="Per-request timeout seconds (default 15)")
    p.add_argument("--concurrency", type=int, default=10, help="Concurrent requests per host (default 10)")
    p.add_argument("--user-agent", default=f"WPSecScan/{__version__} (+defensive-recon)", help="HTTP User-Agent")

    p.add_argument("--wpscan-token", default=None, help="WPScan API token (optional)")
    p.add_argument("--patchstack-token", default=None, help="Patchstack API token (optional) — merges Patchstack CVE data into the vuln DB on --update-db")
    p.add_argument("--hibp-token", default=None, help="HaveIBeenPwned API key for automated breach lookups (otherwise we just emit manual-check links)")
    p.add_argument("--deep-throttle", action="store_true", help="Run the deep throttle mapping (N wrong-password attempts for a synthetic non-existent user). Reports the actual rate-limit threshold.")
    p.add_argument("--deep-throttle-attempts", type=int, default=120, metavar="N", help="How many wrong-login attempts the deep throttle test sends (10-500, default 120). Multiply by --deep-throttle-pacing for total runtime.")
    p.add_argument("--deep-throttle-pacing", type=float, default=10.0, metavar="SECONDS", help="Seconds between deep-throttle attempts (5-60, default 10). Below 5s tends to trip network-layer fail2ban before HTTP-layer throttling shows.")
    p.add_argument("--aggressive", action="store_true", help="Enable active checks: SQLi, XSS, SSRF, path traversal, open redirect, upload probes, default-credentials probe (≤10 attempts).")
    p.add_argument("--prove", action="store_true", help="For each confirmed aggressive finding, run a read-only proof helper (single-target only; requires --aggressive). Never writes to the target.")
    p.add_argument("--auth-user", default=None, help="Admin username for authenticated scanning")
    p.add_argument("--auth-pass", default=None, help="Admin password for authenticated scanning (cookie/wp-login.php flow)")
    p.add_argument("--auth-app-password", default=None,
                    help="WP Application Password (WP 5.6+, preferred over --auth-pass). Spaces are stripped.")
    p.add_argument("--auth-totp", default=None,
                    help="6-digit TOTP code if the admin account requires 2FA (Two-Factor / Wordfence / iThemes).")
    p.add_argument("--companion-token", default=None,
                    help="One-time token from the WPSecScan companion plugin (richest data, single round-trip).")
    p.add_argument("--proxy", default=None,
                    help="Proxy URL — http://, https://, or socks5:// (also reads WPSECSCAN_PROXY_URL / HTTP_PROXY env vars).")
    p.add_argument("--proxy-auth", default=None,
                    help="Optional 'user:pass' for the proxy. Injected into the URL; password is URL-encoded.")
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
    p.add_argument("--parallel-groups", action="store_true", help="Run within-group checks concurrently (~30%% faster on typical scans; default sequential)")
    p.add_argument("--checkpoint", action="store_true", help="Save progress to ~/.wpsecscan/checkpoints/ so a Ctrl+C scan can resume on next run")
    p.add_argument("--fail-on", default=None, metavar="SEVERITY", help="Exit with code 2 if ANY finding is at or above this severity (critical/high/medium/low). Overrides the default exit-code logic.")
    p.add_argument("--abuseipdb-token", default=None, help="AbuseIPDB API token for IP-reputation lookup (free tier: 1000/day at abuseipdb.com)")
    p.add_argument("--vt-token", default=None, help="VirusTotal API key (free tier: 4 req/min)")
    p.add_argument("--github-search-token", default=None, help="GitHub PAT (public_repo scope) for the leaked-token search check (--diff-against alternative)")
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
    p.add_argument("--query", default=None, metavar="EXPR", help="L30: after scan, print only findings matching the GraphQL-style filter expression.")
    p.add_argument("--since", default=None, metavar="YYYY-MM-DD", help="K26: incremental mode; skip low-churn checks for targets whose snapshot is newer than this date.")
    p.add_argument("--completion", default=None, choices=["bash", "zsh", "powershell"], help="O47: print a shell completion script and exit.")
    p.add_argument("--no-update-check", action="store_true", help="J19: skip the GitHub-releases update check at startup.")
    # Round-56 visibility upgrade
    p.add_argument("--demo", action="store_true", help="Round-56: synthetic scan against a fake target so you can see every feature working without scanning a real site. Writes all artifacts to ~/.wpsecscan/demo/.")
    p.add_argument("--no-live", action="store_true", help="Disable the live multi-panel dashboard during scans (falls back to the static console reporter).")
    p.add_argument("--burp-export", action="store_true", help="Also write a Burp Suite scope XML for handoff to manual deep-testing")
    p.add_argument("--exec-pdf", action="store_true", help="Also write a one-page executive summary PDF (uses reportlab if installed; otherwise an HTML print-to-PDF fallback)")
    p.add_argument("--daemon", default=None, metavar="CONFIG.yml", help="Run as a daemon: schedule scans via cron-style config (see SDK.md)")
    p.add_argument("--dashboard", action="store_true", help="When scanning multiple sites, also write a batch dashboard")
    format_group = p.add_mutually_exclusive_group()
    format_group.add_argument("--json-only", action="store_true", help="Write JSON only (no HTML)")
    format_group.add_argument("--html-only", action="store_true", help="Write HTML only (no JSON)")

    p.add_argument("--update-db", action="store_true", help="Download the Wordfence Intelligence vulnerability database and exit")
    p.add_argument("--diff", nargs=2, metavar=("OLD.json", "NEW.json"), help="Compare two report JSONs and print the diff, then exit")
    p.add_argument("--debug", action="store_true", help="Verbose logging to ~/.wpsecscan/logs/")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args()

    # O47 --completion is checked FIRST — before logging setup, before any
    # I/O — so the stdout output isn't contaminated by debug-log notices
    # when the user pipes it (`wpsecscan --completion bash > completions/`).
    if getattr(args, "completion", None):
        from .completion import generate
        print(generate(args.completion))
        sys.exit(0)

    # Read --auth-pass from stdin when the user passes `-`. Stops the
    # password showing up in `ps aux` / shell history.
    if args.auth_pass == "-":
        import getpass
        try:
            args.auth_pass = getpass.getpass("WordPress admin password: ")
        except (EOFError, KeyboardInterrupt):
            print("aborted: no password provided", file=sys.stderr)
            sys.exit(130)

    # --timeout below 5s reliably causes false-positive timeout findings
    # (TLS handshake alone can take 1-2s; a slow plugin can take 3s).
    if args.timeout < 5 and not args.no_console:
        print(f"[warn] --timeout {args.timeout:.1f}s is very short; "
              "expect false-positive timeout findings on real sites.",
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
    else:
        print(f"unknown subcommand: {cmd}", file=sys.stderr)
        sys.exit(2)


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
    for i, a in enumerate(args[1:], 1):
        if a == "--out" and i + 1 <= len(args) - 1:
            out_path = Path(args[i + 1])
            break
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
        for s in sites_mod.list_sites():
            ts = s.get("last_scan_ts") or 0
            when = "never" if not ts else __import__("time").strftime("%Y-%m-%d", __import__("time").localtime(ts))
            print(f"  {s['url']:60s} weekly={s.get('weekly', False)}  last={when}  risk={s.get('last_risk_score', '?')}")
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
                  "notes": ""}
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
            elif not a.startswith("--") and url is None:
                url = a; i += 1
            else:
                i += 1
        if not url:
            print("usage: wpsecscan sites add URL [--weekly] [--auth-user U] [--auth-app-password P] [--proxy URL] [--proxy-auth user:pass]"); sys.exit(2)
        entry = sites_mod.add(url, **flags)
        print(f"added: {entry['url']} (weekly={entry['weekly']}{', proxied' if flags['proxy_url'] else ''})")
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
            # Shell out to a fresh wpsecscan invocation per site so a crash in
            # one doesn't kill the batch. Pass through per-site proxy / auth.
            cmd = [sys.executable, "-m", "wpsecscan", url, "--out", "wpsecscan-reports"]
            if s.get("auth_user"):
                cmd.extend(["--auth-user", s["auth_user"]])
            # Unseal proxy + auth + app password if present
            if s.get("proxy_url"):
                cmd.extend(["--proxy", s["proxy_url"]])
            if s.get("proxy_auth_sealed"):
                try:
                    cmd.extend(["--proxy-auth", sites_mod._unseal(s["proxy_auth_sealed"])])
                except Exception:  # noqa: BLE001
                    pass
            if s.get("auth_app_password_sealed"):
                try:
                    cmd.extend(["--auth-app-password", sites_mod._unseal(s["auth_app_password_sealed"])])
                except Exception:  # noqa: BLE001
                    pass
            if s.get("companion_token_sealed"):
                try:
                    cmd.extend(["--companion-token", sites_mod._unseal(s["companion_token_sealed"])])
                except Exception:  # noqa: BLE001
                    pass
            __import__("subprocess").run(cmd, check=False)
        return
    print(f"unknown sites action: {action}", file=sys.stderr); sys.exit(2)


def _cmd_schedule(args: list[str]) -> None:
    from . import sites as sites_mod
    if not args:
        print("usage: wpsecscan schedule {install|uninstall|pause|resume|status}"); return
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
    if not args:
        print("usage: wpsecscan digest {configure|test|send}"); return
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
    else:
        print(f"unknown digest action: {args[0]}", file=sys.stderr); sys.exit(2)


def _cmd_ai_cost(args: list[str]) -> None:
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
        print(f"checked {out['checked_sites']} site(s), {len(out['new_alerts'])} new alert(s)")
        for a in out["new_alerts"][:20]:
            print(f"  - {a['site_url']}: {a['plugin_slug']} {a['installed_version'] or '?'} "
                  f"[{a['severity']}] {a['cve']} {a['title']}")
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
