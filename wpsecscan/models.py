from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    severity: str
    title: str
    evidence: str = ""
    remediation: str = ""
    url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Catch severity typos at construction. risk.py silently treats unknown
        # severities as weight 0, which masks the bug; better to fail loud.
        if self.severity not in SEVERITY_RANK:
            raise ValueError(
                f"Finding severity must be one of {SEVERITIES}; got {self.severity!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CheckResult:
    check_id: str
    check_name: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class ScanReport:
    target: str
    scanned_at: str
    duration_ms: int
    results: list[CheckResult] = field(default_factory=list)

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for r in self.results:
            out.extend(r.findings)
        return out

    @property
    def summary(self) -> dict[str, int]:
        s = {sev: 0 for sev in SEVERITIES}
        for f in self.all_findings:
            s[f.severity] = s.get(f.severity, 0) + 1
        return s

    def worst_severity(self) -> str | None:
        worst = -1
        for f in self.all_findings:
            r = SEVERITY_RANK.get(f.severity, -1)
            if r > worst:
                worst = r
        return SEVERITIES[worst] if worst >= 0 else None

    @property
    def risk_score(self) -> int:
        """Defer import to break a circular: risk -> models -> nothing."""
        from .risk import compute_risk_score
        return compute_risk_score(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scanned_at": self.scanned_at,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "risk_score": self.risk_score,
            "results": [r.to_dict() for r in self.results],
        }
