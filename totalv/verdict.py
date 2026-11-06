"""Turn VirusTotal analysis stats into a verdict. Pure functions with no I/O."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

MAX_FLAGGED_ENGINES = 5

# Categories that mean an engine actually checked the item. "timeout",
# "confirmed-timeout", "failure", and "type-unsupported" mean it did not.
ANSWERED_CATEGORIES = ("malicious", "suspicious", "harmless", "undetected")


class Verdict(StrEnum):
    """The overall result shown to the user."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EngineHit:
    """One engine that flagged the item, with the label it gave."""

    engine: str
    category: str
    label: str


@dataclass(frozen=True)
class ScanResult:
    """Everything needed to show a verdict to the user."""

    verdict: Verdict
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    flagged_by: tuple[EngineHit, ...] = ()
    report_url: str | None = None
    reason: str | None = None
    analysis_date: datetime | None = None
    from_cache: bool = False

    @property
    def engines_answered(self) -> int:
        """Engines that returned a real answer (the Y in "X / Y engines")."""
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def detections(self) -> int:
        """Engines that flagged the item as malicious or suspicious."""
        return self.malicious + self.suspicious


def unknown(reason: str, *, report_url: str | None = None) -> ScanResult:
    """Build an UNKNOWN result. Used for every error, so failures never look CLEAN."""
    return ScanResult(verdict=Verdict.UNKNOWN, reason=reason, report_url=report_url)


def evaluate(
    stats: Mapping[str, Any],
    results: Mapping[str, Any] | None = None,
    *,
    malicious_threshold: int,
    report_url: str | None = None,
    analysis_date: datetime | None = None,
) -> ScanResult:
    """Apply the verdict rules to VirusTotal's per-category counts.

    ``stats`` is ``last_analysis_stats`` (or ``stats`` from an analysis), and
    ``results`` the matching per-engine results, used to name flagging engines.
    """
    malicious = _count(stats, "malicious")
    suspicious = _count(stats, "suspicious")
    harmless = _count(stats, "harmless")
    undetected = _count(stats, "undetected")

    reason = None
    if malicious + suspicious + harmless + undetected == 0:
        verdict = Verdict.UNKNOWN
        reason = "No antivirus engine returned a result."
    elif malicious >= malicious_threshold:
        verdict = Verdict.MALICIOUS
    elif malicious >= 1 or suspicious >= 1:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    return ScanResult(
        verdict=verdict,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        flagged_by=_flagging_engines(results or {}),
        report_url=report_url,
        reason=reason,
        analysis_date=analysis_date,
    )


def _count(stats: Mapping[str, Any], category: str) -> int:
    """Read one category count, treating missing or null values as zero."""
    return max(0, int(stats.get(category) or 0))


def _flagging_engines(results: Mapping[str, Any]) -> tuple[EngineHit, ...]:
    """Pick up to MAX_FLAGGED_ENGINES engines, malicious ones first, then by name."""
    hits = []
    for name, entry in results.items():
        if not isinstance(entry, Mapping):
            continue
        category = entry.get("category")
        if category not in ("malicious", "suspicious"):
            continue
        engine = str(entry.get("engine_name") or name)
        # "result" is the engine's own label, such as "phishing". It can be null.
        label = str(entry.get("result") or category)
        hits.append(EngineHit(engine=engine, category=category, label=label))
    hits.sort(key=lambda hit: (hit.category != "malicious", hit.engine.lower()))
    return tuple(hits[:MAX_FLAGGED_ENGINES])
