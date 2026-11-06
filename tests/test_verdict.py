"""Tests for the verdict rules."""

from __future__ import annotations

import pytest

from totalv.verdict import MAX_FLAGGED_ENGINES, Verdict, evaluate, unknown

THRESHOLD = 3


def stats(malicious: int = 0, suspicious: int = 0, harmless: int = 0, undetected: int = 0):
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": 0,
    }


@pytest.mark.parametrize(
    ("counts", "expected"),
    [
        (stats(malicious=3, undetected=60), Verdict.MALICIOUS),
        (stats(malicious=40), Verdict.MALICIOUS),
        (stats(malicious=1, undetected=60), Verdict.SUSPICIOUS),
        (stats(malicious=2, undetected=60), Verdict.SUSPICIOUS),
        (stats(suspicious=1, harmless=60), Verdict.SUSPICIOUS),
        (stats(harmless=50, undetected=20), Verdict.CLEAN),
        (stats(undetected=1), Verdict.CLEAN),
        (stats(), Verdict.UNKNOWN),
    ],
)
def test_verdict_rules(counts: dict[str, int], expected: Verdict) -> None:
    assert evaluate(counts, malicious_threshold=THRESHOLD).verdict is expected


def test_only_timeouts_and_failures_is_unknown() -> None:
    counts = {"timeout": 10, "failure": 2, "type-unsupported": 5, "confirmed-timeout": 1}
    result = evaluate(counts, malicious_threshold=THRESHOLD)
    assert result.verdict is Verdict.UNKNOWN
    assert result.reason


def test_missing_and_null_counts_are_zero() -> None:
    result = evaluate({"malicious": None, "harmless": 4}, malicious_threshold=THRESHOLD)
    assert result.verdict is Verdict.CLEAN
    assert result.malicious == 0


def test_threshold_of_one_makes_any_detection_malicious() -> None:
    assert evaluate(stats(malicious=1), malicious_threshold=1).verdict is Verdict.MALICIOUS


def test_counts_and_totals() -> None:
    result = evaluate(
        stats(malicious=2, suspicious=1, harmless=10, undetected=7), malicious_threshold=THRESHOLD
    )
    assert result.detections == 3
    assert result.engines_answered == 20


def test_flagged_by_lists_malicious_first_and_caps_the_list() -> None:
    results = {
        "Zeta": {"category": "malicious", "engine_name": "Zeta", "result": "trojan"},
        "Alpha": {"category": "suspicious", "engine_name": "Alpha", "result": None},
        "Beta": {"category": "harmless", "engine_name": "Beta", "result": "clean"},
    }
    for index in range(MAX_FLAGGED_ENGINES):
        results[f"M{index}"] = {"category": "malicious", "engine_name": f"M{index}", "result": "x"}

    result = evaluate(stats(malicious=6, suspicious=1), results, malicious_threshold=THRESHOLD)

    assert len(result.flagged_by) == MAX_FLAGGED_ENGINES
    assert all(hit.category == "malicious" for hit in result.flagged_by)
    assert "Beta" not in [hit.engine for hit in result.flagged_by]


def test_flagged_by_falls_back_to_category_when_label_is_null() -> None:
    results = {"Alpha": {"category": "suspicious", "engine_name": "Alpha", "result": None}}
    result = evaluate(stats(suspicious=1), results, malicious_threshold=THRESHOLD)
    assert result.flagged_by[0].label == "suspicious"


def test_unknown_helper() -> None:
    result = unknown("timed out")
    assert result.verdict is Verdict.UNKNOWN
    assert result.reason == "timed out"
    assert result.engines_answered == 0
