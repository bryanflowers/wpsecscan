"""Wave 3 — tests for wpsecscan/reporters/board_one_pager.py."""
from wpsecscan.models import CheckResult, Finding, ScanReport
from wpsecscan.reporters import board_one_pager


def _make(*sevs):
    return ScanReport(
        target="https://example.com", scanned_at="2026-05-27T00:00:00",
        duration_ms=0,
        results=[CheckResult(check_id="x", check_name="X",
                              findings=[Finding(severity=s, title=f"{s} finding")
                                         for s in sevs])],
    )


def test_render_returns_html():
    rep = _make("high", "high", "medium")
    html = board_one_pager.render(rep)
    assert html.startswith("<!doctype html>")
    assert "</html>" in html.rstrip()


def test_render_includes_three_big_numbers():
    rep = _make("critical", "high")
    html = board_one_pager.render(rep)
    # The risk-score, delta, and open-crit+high blocks all appear
    assert "Risk score / 100" in html
    assert "vs prior scan" in html
    assert "Critical &amp; High open" in html


def test_render_includes_target_and_timestamp():
    rep = _make("low")
    html = board_one_pager.render(rep)
    assert "https://example.com" in html
    assert "2026-05-27T00:00:00" in html


def test_bucket_message_score_brackets():
    """The headline text changes per score band."""
    _, h_90, _ = board_one_pager._bucket_message(95)
    _, h_70, _ = board_one_pager._bucket_message(80)
    _, h_50, _ = board_one_pager._bucket_message(60)
    _, h_low, _ = board_one_pager._bucket_message(20)
    assert "strong" in h_90.lower()
    assert "acceptable" in h_70.lower()
    assert "material" in h_50.lower()
    assert "significant" in h_low.lower()


def test_render_three_action_bullets_present():
    rep = _make("critical")
    html = board_one_pager.render(rep)
    # The render emits <li> per action; bucketed message ships three actions.
    assert html.count("<li>") == 3


def test_render_handles_empty_report():
    rep = ScanReport(target="https://x", scanned_at="t", duration_ms=0, results=[])
    html = board_one_pager.render(rep)
    assert "0</div><div class=\"lab\">Critical &amp; High open" in html


def test_write_creates_file(tmp_path):
    rep = _make("high")
    p = tmp_path / "board.html"
    board_one_pager.write(rep, p)
    assert p.exists()
    assert "Board summary" in p.read_text(encoding="utf-8") or "board" in p.read_text(encoding="utf-8").lower()
