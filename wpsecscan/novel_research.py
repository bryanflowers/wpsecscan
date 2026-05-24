"""Round-59 #105-109, #111-112 — Genuinely novel research tooling.

#105 AI false-positive learner — record user-marked FPs in a tiny SQLite
     and surface a confidence_score adjustment on future findings.
#106 Honeypot-fingerprint detector — detect canary patterns deployed by
     real WordPress hosts to trap scanners.
#107 Mutation testing of WPSecScan's own checks — generate variant
     responses for each check and verify the check still triggers.
#108 Visual regression of HTML reports — pixel-diff between two
     generated report HTMLs by rendering to images (uses Playwright).
#109 Encrypted scan-result sharing — encrypt a report with a per-recipient
     X25519 public key; recipient decrypts via private key.
#111 Remediation effectiveness A/B test — for a finding that was
     re-scanned after a fix, record was-fix-effective verdict so the
     remediation library learns which prose works.
#112 Hash-chained Merkle log — append-only log where each entry's hash
     contains the previous entry's hash; reports can include a leaf
     hash proving they were issued at a particular point.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path


def _home() -> Path:
    return Path(os.environ.get("WPSECSCAN_HOME") or (Path.home() / ".wpsecscan"))


# ---- #105 AI false-positive learner ----

def _fp_db_path() -> Path:
    return _home() / "fp_learner.sqlite"


def _fp_conn() -> sqlite3.Connection:
    p = _fp_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE IF NOT EXISTS fp("
                  "check_id TEXT, title_hash TEXT, marked_fp INTEGER, ts INTEGER, "
                  "PRIMARY KEY(check_id, title_hash))")
    return conn


def record_false_positive(check_id: str, finding_title: str, is_fp: bool) -> None:
    if not check_id or not finding_title:
        return
    h = hashlib.sha256(finding_title.encode("utf-8", errors="replace")).hexdigest()[:32]
    try:
        with _fp_conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO fp(check_id, title_hash, marked_fp, ts) "
                "VALUES (?,?,?,?)",
                (check_id, h, 1 if is_fp else 0, int(time.time())),
            )
    except sqlite3.Error:
        pass


def fp_confidence_penalty(check_id: str, finding_title: str) -> float:
    """Returns 0.0..0.5 penalty to subtract from confidence_score for this
    finding-pattern. 0.5 = strong "this was previously marked FP"."""
    if not check_id or not finding_title:
        return 0.0
    h = hashlib.sha256(finding_title.encode("utf-8", errors="replace")).hexdigest()[:32]
    try:
        with _fp_conn() as c:
            r = c.execute(
                "SELECT AVG(marked_fp), COUNT(*) FROM fp WHERE check_id=? AND title_hash=?",
                (check_id, h),
            ).fetchone()
    except sqlite3.Error:
        return 0.0
    if not r or r[1] == 0:
        return 0.0
    avg, count = r
    return min(0.5, float(avg) * (0.2 + min(0.3, count * 0.02)))


# ---- #106 Honeypot-fingerprint detector ----

# Hosts known to ship canaries (the "this is a tarpit, leave us alone" pattern):
HONEYPOT_HEADERS = (
    "x-canary",
    "x-honeypot",
    "x-tarpit",
    "server: nepenthes",
)
HONEYPOT_BODY_PATTERNS = (
    "you have been added to our shame list",
    "this is a tarpit",
    "your IP has been added to our honeypot record",
)


def looks_like_honeypot(headers: dict, body: str) -> bool:
    blob = "\n".join(f"{k.lower()}: {v}" for k, v in (headers or {}).items()).lower()
    if any(h in blob for h in HONEYPOT_HEADERS):
        return True
    b = (body or "").lower()
    return any(p in b for p in HONEYPOT_BODY_PATTERNS)


# ---- #107 Mutation testing ----

def mutate_response(body: str) -> list[tuple[str, str]]:
    """Return a list of (mutation_name, mutated_body) variants of `body`.

    Used by `test_mutation.py` to verify each check's detection still
    works under realistic body variations."""
    if not body:
        return []
    variants = [
        ("identity", body),
        ("trimmed", body.strip()),
        ("upper", body.upper()),
        ("lower", body.lower()),
        ("crlf", body.replace("\n", "\r\n")),
        ("nul_strip", body.replace("\x00", "")),
        ("html_entities", body.replace("<", "&lt;").replace(">", "&gt;")),
        ("truncated", body[:max(1, len(body) // 2)]),
    ]
    return variants


# ---- #108 Visual regression of HTML reports ----

def render_html_to_png(html_path: str, out_png: str) -> str:
    """Render an HTML file to PNG via Playwright (if installed). Returns
    the path written or "" on failure."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore[import-untyped]
    except ImportError:
        return ""
    p = Path(html_path)
    out = Path(out_png)
    if not p.exists():
        return ""
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 1024})
            page.goto(p.resolve().as_uri(), wait_until="networkidle", timeout=15000)
            page.screenshot(path=str(out), full_page=True)
            browser.close()
        return str(out)
    except Exception:  # noqa: BLE001
        return ""


def diff_png(a_png: str, b_png: str) -> float:
    """Return percentage of pixels differing (0.0..100.0). Uses Pillow if
    installed; otherwise raises ImportError."""
    from PIL import Image, ImageChops  # type: ignore[import-untyped]
    a = Image.open(a_png).convert("RGB")
    b = Image.open(b_png).convert("RGB")
    if a.size != b.size:
        b = b.resize(a.size)
    diff = ImageChops.difference(a, b)
    box = diff.getbbox()
    if not box:
        return 0.0
    region = diff.crop(box)
    nonzero = sum(1 for px in region.getdata() if any(px))
    total = region.size[0] * region.size[1]
    if total == 0:
        return 0.0
    return 100.0 * nonzero / total


# ---- #109 Encrypted scan-result sharing ----

def encrypt_for_recipient(payload: bytes, recipient_pub_b64: str) -> bytes:
    """Encrypt `payload` to a recipient's X25519 public key (base64-raw,
    32 bytes). Returns the sealed-box bytes, or b"" on failure.

    Uses `cryptography`'s X25519 + AESGCM (anonymous box pattern).
    Requires `cryptography` >= 41.
    """
    if not payload or not recipient_pub_b64:
        return b""
    import base64
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        recipient_pub_raw = base64.b64decode(recipient_pub_b64)
        if len(recipient_pub_raw) != 32:
            return b""
        recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_raw)
        ephemeral = X25519PrivateKey.generate()
        ephem_pub_raw = ephemeral.public_key().public_bytes_raw()
        shared = ephemeral.exchange(recipient_pub)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"wpsecscan-share-v1").derive(shared)
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, payload, ephem_pub_raw)
        # framing: ephem_pub (32) || nonce (12) || ciphertext
        return ephem_pub_raw + nonce + ct
    except Exception:  # noqa: BLE001
        return b""


def decrypt_from_sender(sealed: bytes, recipient_priv_b64: str) -> bytes:
    if not sealed or len(sealed) < 32 + 12 + 16 or not recipient_priv_b64:
        return b""
    import base64
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        priv = X25519PrivateKey.from_private_bytes(base64.b64decode(recipient_priv_b64))
        ephem_pub_raw, nonce, ct = sealed[:32], sealed[32:44], sealed[44:]
        ephem_pub = X25519PublicKey.from_public_bytes(ephem_pub_raw)
        shared = priv.exchange(ephem_pub)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=b"wpsecscan-share-v1").derive(shared)
        return AESGCM(key).decrypt(nonce, ct, ephem_pub_raw)
    except Exception:  # noqa: BLE001
        return b""


# ---- #111 Remediation effectiveness A/B ----

def _remediation_db_path() -> Path:
    return _home() / "remediation_effectiveness.sqlite"


def _remediation_conn() -> sqlite3.Connection:
    p = _remediation_db_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.execute("CREATE TABLE IF NOT EXISTS effectiveness("
                  "check_id TEXT, remediation_hash TEXT, fixed INTEGER, ts INTEGER)")
    return conn


def record_remediation_outcome(check_id: str, remediation_text: str, fixed: bool) -> None:
    if not check_id or not remediation_text:
        return
    h = hashlib.sha256(remediation_text.encode("utf-8", errors="replace")).hexdigest()[:32]
    try:
        with _remediation_conn() as c:
            c.execute(
                "INSERT INTO effectiveness(check_id, remediation_hash, fixed, ts) VALUES (?,?,?,?)",
                (check_id, h, 1 if fixed else 0, int(time.time())),
            )
    except sqlite3.Error:
        pass


def remediation_effectiveness(check_id: str) -> dict:
    """Returns {best_hash, best_rate, worst_hash, worst_rate, samples}."""
    out = {"best_hash": None, "best_rate": 0.0,
            "worst_hash": None, "worst_rate": 0.0, "samples": 0}
    if not check_id:
        return out
    try:
        with _remediation_conn() as c:
            rows = c.execute(
                "SELECT remediation_hash, AVG(fixed), COUNT(*) FROM effectiveness "
                "WHERE check_id=? GROUP BY remediation_hash HAVING COUNT(*) >= 3",
                (check_id,),
            ).fetchall()
    except sqlite3.Error:
        return out
    if not rows:
        return out
    rows.sort(key=lambda r: float(r[1] or 0.0))
    out["worst_hash"], out["worst_rate"] = rows[0][0], float(rows[0][1] or 0.0)
    out["best_hash"], out["best_rate"] = rows[-1][0], float(rows[-1][1] or 0.0)
    out["samples"] = sum(int(r[2] or 0) for r in rows)
    return out


# ---- #112 Hash-chained Merkle log ----

def _merkle_path() -> Path:
    return _home() / "merkle.log"


def merkle_append(entry: dict) -> str:
    """Append-only hash-chained log. Returns this entry's leaf hash."""
    p = _merkle_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        prev_hash = ""
        if p.exists() and not p.is_symlink():
            with p.open("rb") as f:
                try:
                    f.seek(-512, os.SEEK_END)
                except OSError:
                    f.seek(0)
                tail = f.read().decode("utf-8", errors="replace")
                lines = [l for l in tail.splitlines() if l.strip()]
                if lines:
                    try:
                        prev = json.loads(lines[-1])
                        prev_hash = prev.get("hash", "")
                    except json.JSONDecodeError:
                        prev_hash = ""
        body = json.dumps(entry, sort_keys=True, default=str)
        leaf_hash = hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()
        record = json.dumps({"ts": int(time.time()), "prev": prev_hash,
                              "entry": entry, "hash": leaf_hash},
                              sort_keys=True, default=str)
        if p.is_symlink():
            p.unlink()
        with p.open("a", encoding="utf-8") as f:
            f.write(record + "\n")
        return leaf_hash
    except OSError:
        return ""


def merkle_verify() -> bool:
    """Re-walk the log and verify every leaf hash matches. Returns True
    iff the chain is intact."""
    p = _merkle_path()
    if not p.exists() or p.is_symlink():
        return False
    try:
        prev = ""
        with p.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False
                if rec.get("prev", "") != prev:
                    return False
                body = json.dumps(rec.get("entry"), sort_keys=True, default=str)
                want = hashlib.sha256((prev + body).encode("utf-8")).hexdigest()
                if rec.get("hash") != want:
                    return False
                prev = rec.get("hash") or ""
        return True
    except OSError:
        return False
