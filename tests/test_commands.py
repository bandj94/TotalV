"""Tests for command input validation and result embeds (no Discord connection needed)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from totalv.cogs.scanner import parse_hash, parse_url
from totalv.embeds import DISCLAIMER, inline_code, report_button, scan_result_embed
from totalv.verdict import EngineHit, ScanResult, Verdict, unknown


@pytest.mark.parametrize(
    "text",
    ["https://example.com", "http://example.com/path?q=1", "  HTTPS://Example.com/  "],
)
def test_valid_urls(text: str) -> None:
    assert parse_url(text) == text.strip()


@pytest.mark.parametrize(
    "text",
    [
        "example.com",
        "ftp://example.com",
        "javascript:alert(1)",
        "https://",
        "https://exa mple.com",
        "http://[::1",
        "https://example.com/" + "a" * 2100,
        "",
    ],
)
def test_invalid_urls(text: str) -> None:
    assert parse_url(text) is None


@pytest.mark.parametrize("length", [32, 40, 64])
def test_valid_hashes_are_lowercased(length: int) -> None:
    assert parse_hash(" " + "A" * length + " ") == "a" * length


@pytest.mark.parametrize("text", ["a" * 31, "a" * 33, "a" * 63, "g" * 32, "", "a" * 32 + "\n0"])
def test_invalid_hashes(text: str) -> None:
    assert parse_hash(text) is None


def test_clean_embed_never_says_safe_and_has_disclaimer() -> None:
    result = ScanResult(verdict=Verdict.CLEAN, harmless=60, undetected=10)
    embed = scan_result_embed(result, target_label="URL", target="https://example.com")
    text = f"{embed.title} {embed.description}".lower()
    assert "safe" not in text
    assert "no engines flagged this" in text
    assert embed.footer.text == DISCLAIMER
    assert "0 / 70" in (embed.description or "")


def test_malicious_embed_lists_engines_and_date() -> None:
    result = ScanResult(
        verdict=Verdict.MALICIOUS,
        malicious=5,
        undetected=60,
        flagged_by=(EngineHit("Engine*", "malicious", "Trojan_X"),),
        analysis_date=datetime(2026, 1, 1, tzinfo=UTC),
    )
    embed = scan_result_embed(result, target_label="Hash", target="a" * 64)
    fields = {field.name: field.value for field in embed.fields}
    assert fields["Flagged by"] == "Engine\\*: Trojan\\_X"  # markdown escaped
    assert "Last analysis" in fields
    assert embed.color is not None and embed.color.value == 0xE74C3C


def test_unknown_embed_shows_reason_and_cache_note() -> None:
    result = ScanResult(verdict=Verdict.UNKNOWN, reason="Timed out.", from_cache=True)
    embed = scan_result_embed(result, target_label="File", target="report.pdf")
    assert embed.description == "Timed out."
    assert embed.footer.text and embed.footer.text.endswith(DISCLAIMER)


def test_targets_are_shown_as_unclickable_code() -> None:
    assert inline_code("https://evil.example/`@everyone`") == "`https://evil.example/'@everyone'`"
    assert len(inline_code("x" * 1000)) <= 302


async def test_report_button_only_when_there_is_a_link() -> None:
    assert report_button(unknown("No report.")) is None
    link = "https://www.virustotal.com/gui/file/" + "a" * 64
    view = report_button(ScanResult(verdict=Verdict.CLEAN, harmless=1, report_url=link))
    assert view is not None
    assert view.children[0].url == link  # type: ignore[attr-defined]
