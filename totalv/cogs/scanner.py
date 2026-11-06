"""Slash commands: /ping, /help, /scanurl, /scanfile, /scanhash, and /quota."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import discord
from discord import app_commands
from discord.ext import commands

from totalv.bot import NO_MENTIONS
from totalv.embeds import help_embed, quota_embed, report_button, scan_result_embed
from totalv.verdict import ScanResult, unknown

if TYPE_CHECKING:
    from totalv.bot import TotalVBot

MAX_URL_LENGTH = 2048
BYTES_PER_MB = 1024 * 1024

# MD5, SHA-1, and SHA-256 are 32, 40, and 64 hexadecimal characters long.
HASH_PATTERN = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


def parse_url(text: str) -> str | None:
    """Return the URL if it is a usable http(s) link, otherwise None."""
    url = text.strip()
    if not url or len(url) > MAX_URL_LENGTH or any(char.isspace() for char in url):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:  # for example a malformed IPv6 address
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    return url


def parse_hash(text: str) -> str | None:
    """Return the hash in lowercase if it is a valid MD5, SHA-1, or SHA-256."""
    file_hash = text.strip()
    return file_hash.lower() if HASH_PATTERN.fullmatch(file_hash) else None


class Scanner(commands.Cog):
    """TotalV's slash commands."""

    def __init__(self, bot: TotalVBot) -> None:
        self.bot = bot

    @app_commands.command(name="ping", description="Check that TotalV is online.")
    async def ping(self, interaction: discord.Interaction) -> None:
        latency_ms = round(self.bot.latency * 1000)
        await interaction.response.send_message(
            f"Pong! Gateway latency: {latency_ms} ms.",
            ephemeral=True,
            allowed_mentions=NO_MENTIONS,
        )

    @app_commands.command(name="help", description="Show TotalV's commands and verdicts.")
    async def help(self, interaction: discord.Interaction) -> None:
        await interaction.response.send_message(
            embed=help_embed(self.bot.settings), ephemeral=True, allowed_mentions=NO_MENTIONS
        )

    @app_commands.command(name="scanurl", description="Check a link with VirusTotal.")
    @app_commands.describe(url="The full link, starting with http:// or https://")
    async def scan_url(
        self, interaction: discord.Interaction, url: app_commands.Range[str, 1, MAX_URL_LENGTH]
    ) -> None:
        target = parse_url(url)
        if target is None:
            await self._reply_error(
                interaction,
                "That doesn't look like a web link. Use a full address that starts "
                "with http:// or https://",
            )
            return
        # Discord needs an answer within 3 seconds, and a scan can take minutes.
        await interaction.response.defer(thinking=True)
        result = await self.bot.vt.scan_url(target)
        await self._send_result(interaction, result, target_label="URL", target=target)

    @app_commands.command(name="scanfile", description="Check a file with VirusTotal.")
    @app_commands.describe(file="The file to check. It is never saved or opened.")
    async def scan_file(self, interaction: discord.Interaction, file: discord.Attachment) -> None:
        limit_mb = self.bot.settings.max_file_mb
        # Attachment.size comes from Discord's metadata, so oversized files are
        # rejected before a single byte is downloaded.
        if file.size > limit_mb * BYTES_PER_MB:
            await self._reply_error(
                interaction,
                f"That file is {file.size / BYTES_PER_MB:.1f} MB. The limit is {limit_mb} MB, "
                "so it was not downloaded.",
            )
            return
        await interaction.response.defer(thinking=True)
        try:
            # Kept in memory only: never written to disk, opened, or executed.
            content = await file.read()
        except discord.HTTPException:
            result = unknown("Could not download the attachment from Discord. Try again.")
        else:
            result = await self.bot.vt.scan_file(content)
        await self._send_result(interaction, result, target_label="File", target=file.filename)

    @app_commands.command(name="scanhash", description="Look up a file hash on VirusTotal.")
    @app_commands.rename(file_hash="hash")
    @app_commands.describe(file_hash="An MD5, SHA-1, or SHA-256 hash. Nothing is uploaded.")
    async def scan_hash(self, interaction: discord.Interaction, file_hash: str) -> None:
        target = parse_hash(file_hash)
        if target is None:
            await self._reply_error(
                interaction,
                "That isn't a valid hash. Use an MD5, SHA-1, or SHA-256 hash: "
                "32, 40, or 64 characters of 0-9 and a-f.",
            )
            return
        await interaction.response.defer(thinking=True)
        result = await self.bot.vt.lookup_hash(target)
        await self._send_result(interaction, result, target_label="Hash", target=target)

    @app_commands.command(name="quota", description="Show VirusTotal requests used today.")
    async def quota(self, interaction: discord.Interaction) -> None:
        embed = quota_embed(self.bot.vt.limiter.usage(), self.bot.vt.cached_results)
        await interaction.response.send_message(
            embed=embed, ephemeral=True, allowed_mentions=NO_MENTIONS
        )

    async def _send_result(
        self,
        interaction: discord.Interaction,
        result: ScanResult,
        *,
        target_label: str,
        target: str,
    ) -> None:
        """Send a scan result as the follow-up to a deferred interaction."""
        extras: dict[str, Any] = {}
        view = report_button(result)
        if view is not None:
            extras["view"] = view
        await interaction.followup.send(
            embed=scan_result_embed(result, target_label=target_label, target=target),
            allowed_mentions=NO_MENTIONS,
            **extras,
        )

    async def _reply_error(self, interaction: discord.Interaction, message: str) -> None:
        """Answer with an error only the user who ran the command can see."""
        await interaction.response.send_message(
            message, ephemeral=True, allowed_mentions=NO_MENTIONS
        )


async def setup(bot: TotalVBot) -> None:
    """Called by discord.py when the extension is loaded."""
    await bot.add_cog(Scanner(bot))
