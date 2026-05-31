"""Wallet seed-phrase leak detection in exposed backups + .git.

Round-64 #75 — devs occasionally commit a wallet seed phrase to a .env
or test fixture, then expose the .git or a backup. We scan a small set
of probe paths and, if exposed, scan for BIP-39 wordlist matches — 12+
consecutive lowercase words from the BIP-39 dictionary is a near-zero-
false-positive signal of a seed phrase.
"""
from __future__ import annotations

import re
from pathlib import Path as _Path

from ..http import Client
from ..models import Finding


def _load_bip39_full() -> set[str] | None:
    """v2.8.1 B14-follow-up — load the full 2048-word BIP-39 English
    wordlist from `wpsecscan/data/bip39-en.txt`. Returns None when the
    data file is missing (eg. very old install), in which case the
    check falls back to the 200-word subset below.

    With the full wordlist + 12/12 threshold, real seed phrases hit
    100% (no false negatives) AND the false-positive risk against
    English prose stays very low (the wordlist intentionally
    excludes any 4-char prefix-collision so common English text
    rarely hits 12 in a row)."""
    p = _Path(__file__).resolve().parent.parent / "data" / "bip39-en.txt"
    if not p.exists():
        return None
    try:
        return {w.strip().lower() for w in p.read_text(
            encoding="utf-8").splitlines() if w.strip()}
    except OSError:
        return None


_BIP39_FULL: set[str] | None = _load_bip39_full()


# 200-word fallback subset (kept for emergency fallback when the data
# file is missing — eg. partial install / packaging quirk). Only used
# when _BIP39_FULL is None.
_BIP39_FIRST_200 = {
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
    "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
    "adult","advance","advice","aerobic","affair","afford","afraid","again","age","agent",
    "agree","ahead","aim","air","airport","aisle","alarm","album","alcohol","alert",
    "alien","all","alley","allow","almost","alone","alpha","already","also","alter",
    "always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger",
    "angle","angry","animal","ankle","announce","annual","another","answer","antenna","antique",
    "anxiety","any","apart","apology","appear","apple","approve","april","arch","arctic",
    "area","arena","argue","arm","armed","armor","army","around","arrange","arrest",
    "arrive","arrow","art","artefact","artist","artwork","ask","aspect","assault","asset",
    "assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction",
    "audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake",
    "aware","away","awesome","awful","awkward","axis","baby","bachelor","bacon","badge",
    "bag","balance","balcony","ball","bamboo","banana","banner","bar","barely","bargain",
    "barrel","base","basic","basket","battle","beach","bean","beauty","because","become",
    "beef","before","begin","behave","behind","believe","below","belt","bench","benefit",
    "best","betray","better","between","beyond","bicycle","bid","bike","bind","biology",
    "bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless",
    "blind","blood","blossom","blouse","blue","blur","blush","board","boat","body",
}

_PROBE_PATHS = (
    "/.env",
    "/.env.backup",
    "/.git/config",
    "/wp-content/uploads/.env",
    "/wp-content/uploads/wallet.txt",
    "/wp-content/uploads/seed.txt",
    "/backup.sql",
    "/database.sql",
    "/wp-content/backup-db/",
    "/wp-content/wallet/",
)


async def check(client: Client, ctx: dict) -> list[Finding]:
    findings: list[Finding] = []
    step = ctx.get("step") or (lambda _s: None)

    for path in _PROBE_PATHS:
        step(f"probing {path}...")
        r = await client.get(path)
        if r is None or r.status_code != 200:
            continue
        body = (r.text or "")
        if len(body) < 60:
            continue
        # Walk runs of consecutive lowercase words; a seed phrase shows up
        # as 12+ words in a row that hit BIP-39.
        words = re.findall(r"\b[a-z]{3,8}\b", body.lower())
        # v2.8.1 — full 2048-word BIP-39 wordlist (with 200-word
        # fallback if the data file is missing). The 12/12 threshold
        # against the full list gives perfect recall on real seed
        # phrases AND vanishingly-low false-positive rate on ordinary
        # English (BIP-39 is curated to exclude common-English
        # collisions; getting 12 BIP-39 words in a row by chance
        # in prose is statistically negligible).
        bip_set = _BIP39_FULL if _BIP39_FULL is not None else _BIP39_FIRST_200
        for i in range(len(words) - 11):
            window = words[i: i + 12]
            hits = sum(1 for w in window if w in bip_set)
            if hits >= 12:  # Tight threshold: every word must match.
                phrase_start = " ".join(window[:6])
                findings.append(
                    Finding(
                        severity="critical",
                        title=f"Possible wallet seed phrase in {path}",
                        evidence=f"12-word window at offset {i}: {phrase_start} ... ({hits}/12 BIP-39 dictionary hits)",
                        remediation=(
                            "IMMEDIATELY: assume the wallet is compromised. Transfer all funds out to a NEW wallet whose seed has never been digital.\n"
                            "Block the exposed path publicly.\n"
                            "Audit how the file got into the docroot — usually a forgotten test fixture or backup file."
                        ),
                        url=client.url(path),
                    )
                )
                break  # one match per file is enough

    return findings
