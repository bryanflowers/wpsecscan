"""Regression tests for v2.7.3 Wave 3 — PHP companion plugin (1.4.3).

N13 /php-error-log-tail — strip absolute log_path from response
N14 /file-monitor — return relative paths instead of WP_PLUGIN_DIR etc.
N19 /plugin-license-keys — drop length-bucket disclosure
Plus: companion plugin version bump to 1.4.3
"""
from pathlib import Path


def _php(rel: str) -> str:
    import wpsecscan
    root = Path(wpsecscan.__file__).parent.parent
    return (root / "wp-plugin" / "wpsecscan-companion" / rel).read_text(encoding="utf-8")


def test_companion_plugin_version_bumped_to_1_4_3():
    main = _php("wpsecscan-companion.php")
    assert "1.4.3" in main
    assert "1.4.2" not in main
    readme = _php("readme.txt")
    assert "Stable tag: 1.4.3" in readme


def test_php_error_log_tail_does_not_return_log_path():
    """N13 — `log_path` (absolute server filesystem path) must be gone
    from the /php-error-log-tail response."""
    rest = _php("includes/rest.php")
    # Find the function body
    import re
    m = re.search(
        r"function wpsecscan_companion_php_error_log_tail_callback.*?\n\}",
        rest, re.DOTALL)
    assert m, "/php-error-log-tail callback not found"
    body = m.group(0)
    assert "'log_path'" not in body, (
        "N13 — /php-error-log-tail must not return absolute log_path"
    )
    # The fix returns log_configured + log_basename instead.
    assert "log_configured" in body or "log_basename" in body


def test_file_monitor_uses_relative_paths():
    """N14 — /file-monitor `roots` must not expose WP_PLUGIN_DIR /
    get_theme_root() absolute paths."""
    rest = _php("includes/rest.php")
    # The roots assignment line in the file-monitor response.
    # Look for the specific antipattern.
    bad_lines = [
        line for line in rest.splitlines()
        if "'roots'" in line and ("WP_PLUGIN_DIR" in line or "get_theme_root()" in line)
    ]
    assert bad_lines == [], (
        "N14 — /file-monitor roots must not include WP_PLUGIN_DIR or "
        f"get_theme_root() absolute paths; found: {bad_lines!r}"
    )
    # The fix puts relative paths there.
    assert "'wp-content/plugins'" in rest
    assert "'wp-content/themes'" in rest


def test_plugin_license_keys_drops_length_bucket():
    """N19 — `length_bucket` field (short/medium/long) must be gone
    from the /plugin-license-keys response — it narrowed the brute-
    force search space for short keys."""
    rest = _php("includes/rest.php")
    # Find the function body
    import re
    m = re.search(
        r"function wpsecscan_companion_plugin_license_keys_callback.*?return rest_ensure_response",
        rest, re.DOTALL)
    assert m, "/plugin-license-keys callback not found"
    body = m.group(0)
    assert "'length_bucket'" not in body, (
        "N19 — length_bucket disclosure must be gone from license-keys response"
    )
    # The 2-char masked prefix lives on but the bucket pre-fix branching
    # `if ( $len === 0 )` chain must be gone.
    assert "$bucket = 'short'" not in body
