"""Tests for settings validation. These pass a dict, so no .env file is ever read."""

from __future__ import annotations

import pytest

from totalv.config import (
    DEFAULT_NEVER_SUBMIT_DOMAINS,
    MAX_SCAN_TIMEOUT_SECONDS,
    ConfigError,
    load_settings,
)

FAKE_TOKEN = "fake-discord-token-for-tests"
FAKE_KEY = "fake-virustotal-key-for-tests"


def env(**overrides: str) -> dict[str, str]:
    """Return a minimal valid environment with the given overrides applied."""
    values = {"DISCORD_TOKEN": FAKE_TOKEN, "VT_API_KEY": FAKE_KEY}
    values.update(overrides)
    return values


def problems_for(environ: dict[str, str]) -> str:
    """Return the ConfigError message for an environment that should be rejected."""
    with pytest.raises(ConfigError) as caught:
        load_settings(environ)
    return str(caught.value)


def test_defaults_when_only_secrets_are_set() -> None:
    settings = load_settings(env())
    assert settings.discord_token == FAKE_TOKEN
    assert settings.vt_api_key == FAKE_KEY
    assert settings.dev_guild_id is None
    assert settings.log_level == "INFO"
    assert settings.vt_requests_per_minute == 4
    assert settings.vt_daily_limit == 500
    assert settings.scan_timeout_seconds == 180
    assert settings.max_report_age_days == 7
    assert settings.max_file_mb == 32
    assert settings.cache_ttl_minutes == 60
    assert settings.malicious_threshold == 3
    assert settings.never_submit_domains == DEFAULT_NEVER_SUBMIT_DOMAINS


def test_missing_secrets_are_all_named() -> None:
    message = problems_for({})
    assert "DISCORD_TOKEN" in message
    assert "VT_API_KEY" in message


def test_blank_secret_counts_as_missing() -> None:
    assert "DISCORD_TOKEN" in problems_for(env(DISCORD_TOKEN="   "))


def test_secret_with_spaces_is_rejected_without_echoing_it() -> None:
    message = problems_for(env(DISCORD_TOKEN="Bot abc123"))
    assert "DISCORD_TOKEN" in message
    assert "abc123" not in message


def test_secrets_never_appear_in_repr_or_errors() -> None:
    settings = load_settings(env())
    assert FAKE_TOKEN not in repr(settings)
    assert FAKE_KEY not in repr(settings)

    message = problems_for(env(VT_DAILY_LIMIT="lots"))
    assert FAKE_TOKEN not in message
    assert FAKE_KEY not in message


@pytest.mark.parametrize("bad_value", ["abc", "1.5", "0", "-3"])
def test_invalid_numbers_are_rejected(bad_value: str) -> None:
    assert "VT_REQUESTS_PER_MINUTE" in problems_for(env(VT_REQUESTS_PER_MINUTE=bad_value))


def test_blank_number_uses_default() -> None:
    assert load_settings(env(MAX_FILE_MB="")).max_file_mb == 32


def test_scan_timeout_has_an_upper_limit() -> None:
    too_long = str(MAX_SCAN_TIMEOUT_SECONDS + 1)
    assert "SCAN_TIMEOUT_SECONDS" in problems_for(env(SCAN_TIMEOUT_SECONDS=too_long))
    allowed = load_settings(env(SCAN_TIMEOUT_SECONDS=str(MAX_SCAN_TIMEOUT_SECONDS)))
    assert allowed.scan_timeout_seconds == MAX_SCAN_TIMEOUT_SECONDS


def test_every_problem_is_reported_together() -> None:
    message = problems_for({"MALICIOUS_THRESHOLD": "0", "LOG_LEVEL": "loud"})
    for name in ("DISCORD_TOKEN", "VT_API_KEY", "MALICIOUS_THRESHOLD", "LOG_LEVEL"):
        assert name in message


def test_log_level_ignores_case() -> None:
    assert load_settings(env(LOG_LEVEL="debug")).log_level == "DEBUG"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("", None), ("123456789012345678", 123456789012345678)],
)
def test_dev_guild_id(raw: str, expected: int | None) -> None:
    assert load_settings(env(DEV_GUILD_ID=raw)).dev_guild_id == expected


# "²" is a superscript two: str.isdigit() accepts it but int() does not.
@pytest.mark.parametrize("bad_value", ["my-server", "-5", "0", "12.5", "²"])
def test_invalid_dev_guild_id_is_rejected(bad_value: str) -> None:
    assert "DEV_GUILD_ID" in problems_for(env(DEV_GUILD_ID=bad_value))


def test_domains_are_trimmed_and_lowercased() -> None:
    settings = load_settings(env(NEVER_SUBMIT_DOMAINS=" Docs.Google.com , ,example.org. "))
    assert settings.never_submit_domains == {"docs.google.com", "example.org"}


def test_blank_domain_list_means_no_domains() -> None:
    assert load_settings(env(NEVER_SUBMIT_DOMAINS="")).never_submit_domains == frozenset()


@pytest.mark.parametrize(
    "bad_entry", ["https://docs.google.com", "docs.google.com/x", "*.google.com", "localhost"]
)
def test_domain_list_rejects_non_domains(bad_entry: str) -> None:
    assert "NEVER_SUBMIT_DOMAINS" in problems_for(env(NEVER_SUBMIT_DOMAINS=bad_entry))
