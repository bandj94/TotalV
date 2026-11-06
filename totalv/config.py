"""Load and validate TotalV settings from environment variables.

Values come from the process environment, with a ``.env`` file in the project
root filling in anything not already set. Every problem is collected and
reported at once, so fixing a ``.env`` file takes one run instead of several.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# The project root is the folder that contains the ``totalv`` package.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOTENV_PATH = PROJECT_ROOT / ".env"

# Discord interaction tokens expire after 15 minutes. A scan has to finish
# well before that, including time spent waiting in the rate-limit queue,
# or its result can no longer be posted.
MAX_SCAN_TIMEOUT_SECONDS = 600

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

# Used only when NEVER_SUBMIT_DOMAINS is absent. Setting it to an empty value
# is an explicit choice to allow submitting every domain.
DEFAULT_NEVER_SUBMIT_DOMAINS = frozenset({"docs.google.com", "drive.google.com"})


class ConfigError(Exception):
    """Raised when one or more settings are missing or invalid."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("\n".join(f"  - {problem}" for problem in problems))


@dataclass(frozen=True)
class Settings:
    """Validated settings for the whole bot.

    The token and API key are left out of ``repr`` so that logging or printing
    a ``Settings`` object can never leak them.
    """

    discord_token: str = field(repr=False)
    vt_api_key: str = field(repr=False)
    dev_guild_id: int | None
    log_level: str
    vt_requests_per_minute: int
    vt_daily_limit: int
    scan_timeout_seconds: int
    max_report_age_days: int
    max_file_mb: int
    cache_ttl_minutes: int
    malicious_threshold: int
    never_submit_domains: frozenset[str]


class _EnvReader:
    """Reads typed values from an environment mapping and records every problem found."""

    def __init__(self, environ: Mapping[str, str]) -> None:
        self._environ = environ
        self.problems: list[str] = []

    def _get(self, name: str) -> str | None:
        """Return the trimmed value, or None when the variable is unset or blank."""
        value = self._environ.get(name, "").strip()
        return value or None

    def secret(self, name: str) -> str:
        """Read a required secret. Error messages never include the value itself."""
        value = self._get(name)
        if value is None:
            self.problems.append(f"{name} is not set.")
            return ""
        if any(char.isspace() for char in value):
            self.problems.append(
                f"{name} contains spaces or line breaks. Paste only the value itself."
            )
        return value

    def positive_int(self, name: str, default: int, maximum: int | None = None) -> int:
        """Read a whole number of at least 1, falling back to ``default`` when blank."""
        raw = self._get(name)
        if raw is None:
            return default
        try:
            value = int(raw)
        except ValueError:
            self.problems.append(f"{name} must be a whole number, got {raw!r}.")
            return default
        if value < 1:
            self.problems.append(f"{name} must be 1 or more, got {value}.")
        elif maximum is not None and value > maximum:
            self.problems.append(f"{name} must be at most {maximum}, got {value}.")
        return value

    def optional_id(self, name: str) -> int | None:
        """Read an optional Discord ID. Blank means not set."""
        raw = self._get(name)
        if raw is None:
            return None
        try:
            value = int(raw)
        except ValueError:
            value = 0
        if value < 1:
            self.problems.append(f"{name} must be a numeric Discord ID, got {raw!r}.")
            return None
        return value

    def log_level(self, name: str, default: str) -> str:
        """Read a logging level name, ignoring case."""
        level = (self._get(name) or default).upper()
        if level not in VALID_LOG_LEVELS:
            choices = ", ".join(VALID_LOG_LEVELS)
            self.problems.append(f"{name} must be one of {choices}, got {level!r}.")
            return default
        return level

    def domain_set(self, name: str, default: frozenset[str]) -> frozenset[str]:
        """Read a comma-separated list of bare domain names into a lowercase set."""
        if name not in self._environ:
            return default
        domains: set[str] = set()
        for part in self._environ[name].split(","):
            # A trailing dot is valid DNS ("example.com.") but would never
            # match a hostname taken from a URL, so it is dropped.
            domain = part.strip().lower().rstrip(".")
            if not domain:
                continue
            # Entries like "https://docs.google.com/" or "*.google.com" would
            # silently never match, which defeats the privacy protection.
            if any(char in domain for char in "/:@* ") or "." not in domain:
                self.problems.append(
                    f"{name} entries must be bare domain names like docs.google.com, "
                    f"got {part.strip()!r}."
                )
                continue
            domains.add(domain)
        return frozenset(domains)


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    """Build validated settings, raising ConfigError that lists every problem.

    Pass ``environ`` to validate a specific mapping (tests do this). When it is
    omitted, the ``.env`` file is loaded first and ``os.environ`` is used.
    """
    if environ is None:
        # override=False lets real environment variables (Docker, CI) win over .env.
        load_dotenv(DOTENV_PATH, override=False)
        environ = os.environ

    env = _EnvReader(environ)
    settings = Settings(
        discord_token=env.secret("DISCORD_TOKEN"),
        vt_api_key=env.secret("VT_API_KEY"),
        dev_guild_id=env.optional_id("DEV_GUILD_ID"),
        log_level=env.log_level("LOG_LEVEL", default="INFO"),
        vt_requests_per_minute=env.positive_int("VT_REQUESTS_PER_MINUTE", default=4),
        vt_daily_limit=env.positive_int("VT_DAILY_LIMIT", default=500),
        scan_timeout_seconds=env.positive_int(
            "SCAN_TIMEOUT_SECONDS", default=180, maximum=MAX_SCAN_TIMEOUT_SECONDS
        ),
        max_report_age_days=env.positive_int("MAX_REPORT_AGE_DAYS", default=7),
        max_file_mb=env.positive_int("MAX_FILE_MB", default=32),
        cache_ttl_minutes=env.positive_int("CACHE_TTL_MINUTES", default=60),
        malicious_threshold=env.positive_int("MALICIOUS_THRESHOLD", default=3),
        never_submit_domains=env.domain_set(
            "NEVER_SUBMIT_DOMAINS", default=DEFAULT_NEVER_SUBMIT_DOMAINS
        ),
    )
    if env.problems:
        raise ConfigError(env.problems)
    return settings
