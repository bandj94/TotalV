"""Command-line entry point, run with ``python -m totalv``."""

from __future__ import annotations

import logging
import sys

import discord

from totalv.bot import TotalVBot
from totalv.config import ConfigError, load_settings


def main() -> int:
    """Validate the configuration and run TotalV until stopped. Returns an exit code."""
    try:
        settings = load_settings()
    except ConfigError as error:
        print("TotalV can't start because of configuration problems:", file=sys.stderr)
        print(error, file=sys.stderr)
        print(
            "Copy .env.example to .env, fill in the values, and try again.",
            file=sys.stderr,
        )
        return 1

    # root=True sends TotalV's own log messages through discord.py's formatter too.
    discord.utils.setup_logging(level=getattr(logging, settings.log_level), root=True)

    bot = TotalVBot(settings)
    try:
        # log_handler=None because logging is already configured above.
        bot.run(settings.discord_token, log_handler=None)
    except discord.LoginFailure:
        print(
            "Discord rejected DISCORD_TOKEN. Reset the token in the Discord Developer "
            "Portal (your application -> Bot -> Reset Token) and update .env.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
