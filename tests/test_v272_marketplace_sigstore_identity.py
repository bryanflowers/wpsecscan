"""Regression tests for v2.7.2 C1 — marketplace sigstore identity binding.

v2.7.1 S1 closed the source_url scheme+host bypass, but left two holes:

  1. The sigstore_sig_url and sigstore_pem_url were fetched from any host
     and any scheme. A malicious or MITM'd index could point them at an
     attacker-controlled cert+sig pair.

  2. cosign was invoked with `--certificate-identity-regexp '.+'` and
     `--certificate-oidc-issuer-regexp '.+'`, so ANY Sigstore-signed
     blob passed verification regardless of who signed it.

Combined: attacker controls the index, supplies their own check + their
own sig + their own cert ⇒ install succeeds and the malicious code runs
on the next scan.
"""
import pytest

from wpsecscan import marketplace_v27


def test_safe_aux_url_rejects_file_scheme():
    ok, reason = marketplace_v27._safe_aux_url("file:///etc/passwd")
    assert ok is False
    assert "https" in reason.lower()


def test_safe_aux_url_rejects_foreign_host():
    ok, reason = marketplace_v27._safe_aux_url("https://evil.example/sig.txt")
    assert ok is False
    assert "host" in reason.lower()


def test_safe_aux_url_accepts_marketplace_origin(monkeypatch):
    monkeypatch.setattr(
        marketplace_v27, "_INDEX_URL",
        "https://bryanflowers.github.io/wpsecscan/marketplace.json",
    )
    ok, reason = marketplace_v27._safe_aux_url(
        "https://bryanflowers.github.io/wpsecscan/sigs/foo.sig"
    )
    assert ok is True
    assert reason == ""


def test_cosign_identity_regexp_is_pinned_to_author(monkeypatch, tmp_path):
    """The cosign verify-blob command must derive its identity-regexp
    from the index's author_handle, NOT use a wildcard `.+`."""
    captured: dict[str, list[str]] = {}

    class _FakeResult:
        returncode = 0
        stderr = ""

    def _fake_run(argv, **kw):
        captured["argv"] = argv
        return _FakeResult()

    monkeypatch.setattr("subprocess.run", _fake_run)
    monkeypatch.setattr("shutil.which", lambda x: "/usr/bin/cosign")
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))

    # Stub the cache so we don't network-fetch the index
    fake_index = {
        "_version": 1,
        "checks": [{
            "slug": "demo-check",
            "title": "demo",
            "description": "x",
            "author_handle": "alice",
            "source_url": "https://bryanflowers.github.io/wpsecscan/x.py",
            "sigstore_sig_url": "https://bryanflowers.github.io/wpsecscan/x.sig",
            "sigstore_pem_url": "https://bryanflowers.github.io/wpsecscan/x.pem",
        }],
    }
    monkeypatch.setattr(marketplace_v27, "_fetch_index", lambda: fake_index)

    # Pre-create a fake installed local check so the verify path doesn't bail
    local = tmp_path / "marketplace" / "checks" / "demo-check.py"
    local.parent.mkdir(parents=True, exist_ok=True)
    local.write_bytes(b"# stub")

    # Stub urlopen for sig+pem downloads
    class _FakeResp:
        def __init__(self, data=b""):
            self._d = data

        def read(self):
            return self._d

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda *a, **k: _FakeResp(b""))

    marketplace_v27.cmd_marketplace(["verify", "demo-check"])

    argv = captured["argv"]
    assert argv[0] == "cosign"
    # The identity regexp must include the author handle, not be `.+`
    identity_idx = argv.index("--certificate-identity-regexp")
    assert "alice" in argv[identity_idx + 1]
    assert argv[identity_idx + 1] != ".+"
    # OIDC issuer must be pinned, not a wildcard regexp
    assert "--certificate-oidc-issuer-regexp" not in argv
    issuer_idx = argv.index("--certificate-oidc-issuer")
    assert argv[issuer_idx + 1] == "https://token.actions.githubusercontent.com"


def test_install_rejects_sig_url_from_foreign_host(monkeypatch, tmp_path, capsys):
    """During install, a malicious index pointing sigstore_sig_url at
    `evil.example` must be refused before any download happens."""
    monkeypatch.setenv("WPSECSCAN_HOME", str(tmp_path))
    fake_index = {
        "_version": 1,
        "checks": [{
            "slug": "demo-check",
            "title": "demo",
            "description": "x",
            "author_handle": "alice",
            "source_url": "https://bryanflowers.github.io/wpsecscan/x.py",
            "sigstore_sig_url": "https://evil.example/x.sig",
            "sigstore_pem_url": "https://bryanflowers.github.io/wpsecscan/x.pem",
        }],
    }
    monkeypatch.setattr(marketplace_v27, "_fetch_index", lambda: fake_index)
    with pytest.raises(SystemExit) as exc:
        marketplace_v27.cmd_marketplace(["install", "demo-check"])
    captured = capsys.readouterr()
    assert exc.value.code != 0
    assert "sigstore" in captured.err.lower() or "host" in captured.err.lower()
