"""Wallet seed-phrase leak detection in exposed backups + .git.

Round-64 #75 — devs occasionally commit a wallet seed phrase to a .env
or test fixture, then expose the .git or a backup. We scan a small set
of probe paths and, if exposed, scan for BIP-39 wordlist matches — 12+
consecutive lowercase words from the BIP-39 dictionary is a near-zero-
false-positive signal of a seed phrase.
"""
from __future__ import annotations

import re

from ..http import Client
from ..models import Finding

# BIP-39 first 200 words — enough for a heuristic without bundling the
# full 2048-word list. A real seed will hit at least 6+ from this subset.
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
        # Sliding window of 12; if 10+ are BIP-39 hits, almost certainly a seed
        for i in range(len(words) - 11):
            window = words[i: i + 12]
            hits = sum(1 for w in window if w in _BIP39_FIRST_200)
            if hits >= 8:  # Conservative threshold for the subset
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
