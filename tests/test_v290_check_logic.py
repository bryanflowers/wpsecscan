"""v2.9.0 check-logic gates (W2a http2, W2b jwt, W2c core_version, W2g backup fuzz, W0c slug squat).

All HTTP is mocked; the slug-squat cache lives in a tmp dir via WPSECSCAN_HOME.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import time

import pytest

from tests.conftest import FakeClient, FakeResponse


def _run(coro):
    return asyncio.run(coro)


def _ctx(**extra):
    c = {"target": "https://example.com", "shared": {}, "step": lambda _s: None}
    c.update(extra)
    return c


# ----- W2a http2_settings: parse banner, compare versions -----

def _h2(server: str):
    from wpsecscan.checks.http2_settings import check
    hdrs = {"server": server} if server else {}
    client = FakeClient(responses={"/": FakeResponse(text="ok", headers=hdrs)})
    return _run(check(client, _ctx()))


def _highs(findings):
    return [f for f in findings if f.severity == "high"]


def test_http2_current_apache_is_not_eol():
    assert not _highs(_h2("Apache/2.4.62"))
    assert not _highs(_h2("Apache/2.4.62 (Ubuntu)"))


def test_http2_apache_2_4_6_is_eol_high():
    f = _highs(_h2("Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips"))
    assert len(f) == 1
    assert f[0].title == "EOL HTTP backend detected: apache/2.4.6"


def test_http2_apache_2_4_60_and_2_4_7_not_eol():
    assert not _highs(_h2("Apache/2.4.60"))
    assert not _highs(_h2("Apache/2.4.7"))


def test_http2_apache_2_2_series_is_eol():
    assert [f.title for f in _highs(_h2("Apache/2.2.34"))] == ["EOL HTTP backend detected: apache/2.2"]


def test_http2_nginx_per_table():
    assert not _highs(_h2("nginx/1.18.0"))
    assert not _highs(_h2("nginx/1.25.3"))
    assert [f.title for f in _highs(_h2("nginx/1.16.1"))] == ["EOL HTTP backend detected: nginx/1.16"]
    # An older nginx produces ONE finding (closest covering entry), not one per table row.
    assert [f.title for f in _highs(_h2("nginx/1.10.3"))] == ["EOL HTTP backend detected: nginx/1.10"]


def test_http2_unversioned_banners_do_not_emit_high():
    for banner in ("cloudflare", "LiteSpeed", "", "nginx"):
        assert not _highs(_h2(banner)), banner


def test_http2_case_insensitive_and_iis_alias():
    assert len(_highs(_h2("APACHE/2.4.6"))) == 1
    assert len(_highs(_h2("Microsoft-IIS/8.5"))) == 1
    assert not _highs(_h2("Microsoft-IIS/10.0"))


def test_http2_capitalised_header_key():
    from wpsecscan.checks.http2_settings import check
    client = FakeClient(responses={"/": FakeResponse(text="ok", headers={"Server": "Apache/2.4.62"})})
    assert not _highs(_run(check(client, _ctx())))


# ----- W2b jwt_audit: alg=none acceptance needs a real user object -----

def _make_token() -> str:
    from wpsecscan.checks.jwt_audit import _b64url_encode
    hdr = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _b64url_encode(json.dumps({"sub": "1", "iss": "example"}).encode())
    return f"{hdr}.{claims}.{_b64url_encode(b'not-a-guessable-signature-bytes')}"


def _jwt(users_me: FakeResponse | None):
    from wpsecscan.checks.jwt_audit import check
    responses = {"/": FakeResponse(text=f"<html>{_make_token()}</html>")}
    if users_me is not None:
        responses["/wp-json/wp/v2/users/me"] = users_me
    client = FakeClient(responses=responses)
    return _run(check(client, _ctx(aggressive=True)))


def test_jwt_html_200_containing_id_is_not_critical():
    findings = _jwt(FakeResponse(status_code=200, text="<html><body><div id=\"main\">hello</div></body></html>"))
    assert not [f for f in findings if f.severity == "critical"]
    med = [f for f in findings if f.severity == "medium"]
    assert len(med) == 1
    assert "manual confirmation required" in med[0].title


def test_jwt_json_user_object_is_critical():
    body = json.dumps({"id": 1, "username": "admin", "email": "a@b"})
    findings = _jwt(FakeResponse(status_code=200, text=body))
    crit = [f for f in findings if f.severity == "critical"]
    assert len(crit) == 1
    assert crit[0].title == "Server accepts `alg=none` JWT — full auth bypass"


def test_jwt_json_with_single_user_field_is_not_critical():
    findings = _jwt(FakeResponse(status_code=200, text=json.dumps({"id": 5, "ok": True})))
    assert not [f for f in findings if f.severity == "critical"]
    assert [f for f in findings if f.severity == "medium"]


def test_jwt_json_list_is_not_critical():
    findings = _jwt(FakeResponse(status_code=200, text=json.dumps([{"id": 1, "slug": "a", "name": "A"}])))
    assert not [f for f in findings if f.severity == "critical"]


def test_jwt_401_emits_nothing_for_active_test():
    findings = _jwt(FakeResponse(status_code=401, text=json.dumps({"code": "rest_not_logged_in", "id": 1})))
    assert not [f for f in findings if f.severity in ("critical", "medium")]


def test_jwt_passive_scan_never_sends_tampered_token():
    from wpsecscan.checks.jwt_audit import check
    client = FakeClient(responses={"/": FakeResponse(text=_make_token())})
    _run(check(client, _ctx()))
    assert not any(p == "/wp-json/wp/v2/users/me" for _m, p, _k in client.requests)


# ----- W2c core_version: pre-release ordering -----

def test_ver_tuple_prerelease_ordering():
    from wpsecscan.checks.core_version import _ver_tuple as vt
    assert vt("6.4.3") < vt("6.5-rc1") < vt("6.5")
    assert vt("6.5-beta2") < vt("6.5")
    assert vt("6.5-beta2") > vt("6.4.3")
    assert vt("6.5.1-rc1") > vt("6.5") and vt("6.5.1-rc1") > vt("6.5.0")
    assert vt("6.5.1-RC2") < vt("6.5.1")
    assert vt("6.5") == vt("6.5.0")
    assert vt("6.4.2") < vt("6.4.3") < vt("6.4.10")
    assert vt("") == () and vt("abc") == ()


def _core(version: str, latest: str):
    cv = importlib.import_module("wpsecscan.checks.core_version")

    async def _fake_latest():
        return latest

    html = f'<html><meta name="generator" content="WordPress {version}"></html>'
    client = FakeClient(responses={"/": FakeResponse(text=html)})
    orig = cv._latest_wp_version
    cv._latest_wp_version = _fake_latest
    try:
        return _run(cv.check(client, _ctx()))
    finally:
        cv._latest_wp_version = orig


def test_core_version_outdated_current():
    assert any(f.severity == "high" and "outdated" in f.title for f in _core("6.4.2", "6.4.3"))
    cur = _core("6.5", "6.5")
    assert any("up to date" in f.title for f in cur)
    assert not any(f.severity == "high" for f in cur)


def test_core_version_prerelease_beyond_latest_not_outdated():
    cv = importlib.import_module("wpsecscan.checks.core_version")
    # The generator regexes only capture [0-9.], so exercise the comparison with a
    # pre-release string directly through the same comparison the check uses.
    assert not (cv._ver_tuple("6.5-rc1") < cv._ver_tuple("6.4.3"))
    assert cv._ver_tuple("6.5-beta2") < cv._ver_tuple("6.5")


# ----- W2g backup_file_fuzz: soft-404 precedence -----

def _fuzz(body_text: str):
    from wpsecscan.checks.backup_file_fuzz import check
    client = FakeClient(responses={"/wp-config.php~": FakeResponse(status_code=200, text=body_text)})
    return _run(check(client, _ctx()))


def test_backup_fuzz_large_404_body_is_soft_404():
    body = "<html>Error 404 " + ("x" * 5001) + "</html>"
    assert len(body.encode()) > 5000
    findings = _fuzz(body)
    assert not any("reachable" in f.title for f in findings)
    assert any("clean" in f.title.lower() for f in findings)


def test_backup_fuzz_small_body_containing_404_is_a_hit():
    body = "DB_PASSWORD=404 " + ("x" * 84)
    assert len(body.encode()) == 100
    findings = _fuzz(body)
    hit = [f for f in findings if "reachable" in f.title]
    assert len(hit) == 1 and hit[0].severity == "critical"


def test_backup_fuzz_page_not_found_text_is_soft_404():
    findings = _fuzz("Page not found. " + ("y" * 100))
    assert not any("reachable" in f.title for f in findings)


# ----- W0c plugin_slug_squat_check: TTL cache + cap -----

class _CountingClient(FakeClient):
    def __init__(self, author: str = "Original Author"):
        super().__init__(responses={
            "*": FakeResponse(status_code=200, text=json.dumps({"author": author})),
        })

    def external_calls(self) -> int:
        return sum(1 for _m, p, _k in self.requests if p.startswith("https://api.wordpress.org/"))


@pytest.fixture
def squat_home(tmp_path, monkeypatch):
    home = tmp_path / "wpsshome"
    home.mkdir()
    monkeypatch.setenv("WPSECSCAN_HOME", str(home))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return home / "cache" / "wporg-authors"


def _squat(client, slugs):
    from wpsecscan.checks.plugin_slug_squat_check import check
    ctx = _ctx()
    ctx["shared"]["plugins"] = [{"slug": s} for s in slugs]
    return _run(check(client, ctx))


def _seed(cache_dir, slug, author, age_seconds):
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / f"{slug}.json").write_text(
        json.dumps({"author": author, "checked_at": time.time() - age_seconds}), encoding="utf-8")


def test_slug_squat_warm_cache_makes_no_external_requests(squat_home):
    slugs = [f"plug-{i}" for i in range(10)]
    for s in slugs:
        _seed(squat_home, s, "Original Author", 3600)
    client = _CountingClient()
    findings = _squat(client, slugs)
    assert client.external_calls() == 0
    assert not any(f.severity == "high" for f in findings)
    assert any("10 plugin(s)" in f.title for f in findings)


def test_slug_squat_cold_cache_capped_at_20(squat_home):
    client = _CountingClient()
    _squat(client, [f"plug-{i}" for i in range(45)])
    assert client.external_calls() == 20


def test_slug_squat_ttl_expiry_refetches_and_detects_change(squat_home):
    _seed(squat_home, "stale-plug", "Old Author", 25 * 3600)
    client = _CountingClient(author="New Author")
    findings = _squat(client, ["stale-plug"])
    assert client.external_calls() == 1
    assert any(f.severity == "high" and "stale-plug" in f.title for f in findings)
    # cache was rewritten with a fresh timestamp
    rec = json.loads((squat_home / "stale-plug.json").read_text(encoding="utf-8"))
    assert rec["author"] == "New Author"
    assert time.time() - rec["checked_at"] < 60


def test_slug_squat_fresh_cache_skips_even_if_author_would_differ(squat_home):
    _seed(squat_home, "fresh-plug", "Old Author", 23 * 3600)
    client = _CountingClient(author="New Author")
    _squat(client, ["fresh-plug"])
    assert client.external_calls() == 0
