"""Discord embeds and buttons for scan results, /quota, and /help."""

from __future__ import annotations

import discord

from totalv.config import Settings
from totalv.rate_limiter import QuotaUsage
from totalv.verdict import ScanResult, Verdict

DISCLAIMER = "A clean result isn't a guarantee. New threats often go undetected."

COLORS = {
    Verdict.CLEAN: discord.Color.green(),
    Verdict.SUSPICIOUS: discord.Color.yellow(),
    Verdict.MALICIOUS: discord.Color.red(),
    Verdict.UNKNOWN: discord.Color.light_grey(),
}

# CLEAN is deliberately worded as "no engines flagged this", never as "safe".
TITLES = {
    Verdict.MALICIOUS: "\N{LARGE RED CIRCLE} MALICIOUS",
    Verdict.SUSPICIOUS: "\N{LARGE YELLOW CIRCLE} SUSPICIOUS",
    Verdict.CLEAN: "\N{LARGE GREEN CIRCLE} CLEAN: no engines flagged this",
    Verdict.UNKNOWN: "\N{MEDIUM WHITE CIRCLE} UNKNOWN",
}

MAX_TARGET_LENGTH = 300
MAX_ENGINE_LINE_LENGTH = 100


def inline_code(text: str, limit: int = MAX_TARGET_LENGTH) -> str:
    """Show user-supplied text as inline code.

    Inline code is never turned into a clickable link, so a malicious URL in a
    result can't be opened by accident. Backticks are swapped out so the text
    can't break out of the code span.
    """
    text = text.replace("`", "'")
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return f"`{text}`"


def scan_result_embed(result: ScanResult, *, target_label: str, target: str) -> discord.Embed:
    """Build the result embed for a URL, file, or hash scan."""
    embed = discord.Embed(title=TITLES[result.verdict], color=COLORS[result.verdict])
    embed.add_field(name=target_label, value=inline_code(target), inline=False)

    if result.verdict is Verdict.UNKNOWN:
        embed.description = result.reason or "VirusTotal did not return a verdict."
    else:
        embed.description = (
            f"**{result.detections} / {result.engines_answered}** engines flagged this."
        )
        embed.add_field(
            name="Breakdown",
            value=(
                f"Malicious: {result.malicious}\n"
                f"Suspicious: {result.suspicious}\n"
                f"Harmless: {result.harmless}\n"
                f"Undetected: {result.undetected}"
            ),
            inline=True,
        )
        if result.flagged_by:
            lines = []
            for hit in result.flagged_by:
                # Engine labels come from third parties, so escape their markdown.
                line = f"{hit.engine}: {hit.label}"[:MAX_ENGINE_LINE_LENGTH]
                lines.append(discord.utils.escape_markdown(line))
            embed.add_field(name="Flagged by", value="\n".join(lines), inline=True)

    if result.analysis_date is not None:
        # Discord renders these timestamps in each reader's own time zone.
        embed.add_field(
            name="Last analysis",
            value=(
                f"{discord.utils.format_dt(result.analysis_date, 'f')} "
                f"({discord.utils.format_dt(result.analysis_date, 'R')})"
            ),
            inline=False,
        )

    footer = DISCLAIMER
    if result.from_cache:
        footer = f"Cached result. {DISCLAIMER}"
    embed.set_footer(text=footer)
    return embed


def report_button(result: ScanResult) -> discord.ui.View | None:
    """A "View on VirusTotal" link button, or None if there is no report to link."""
    if not result.report_url:
        return None
    view = discord.ui.View()
    view.add_item(discord.ui.Button(label="View on VirusTotal", url=result.report_url))
    return view


def quota_embed(usage: QuotaUsage, cached_results: int) -> discord.Embed:
    """Show VirusTotal request usage for today."""
    embed = discord.Embed(title="VirusTotal quota", color=discord.Color.blurple())
    embed.add_field(
        name="Requests today",
        value=f"{usage.used_today} / {usage.daily_limit} (resets at 00:00 UTC)",
        inline=False,
    )
    embed.add_field(name="Waiting in queue", value=str(usage.queue_length), inline=True)
    embed.add_field(name="Cached results", value=str(cached_results), inline=True)
    embed.set_footer(
        text="Counted by this bot since it started. VirusTotal's own count may differ."
    )
    return embed


def help_embed(settings: Settings) -> discord.Embed:
    """List the commands and explain the verdicts."""
    embed = discord.Embed(title="TotalV help", color=discord.Color.blurple())
    embed.add_field(
        name="Commands",
        value=(
            "`/scanurl` Check a link.\n"
            f"`/scanfile` Check an attachment (up to {settings.max_file_mb} MB).\n"
            "`/scanhash` Look up an MD5, SHA-1, or SHA-256 file hash.\n"
            "`/quota` VirusTotal requests used today.\n"
            "`/ping` Check that the bot is online."
        ),
        inline=False,
    )
    embed.add_field(
        name="Verdicts",
        value=(
            f"{TITLES[Verdict.MALICIOUS]}: {settings.malicious_threshold} or more engines "
            "flagged it as malicious.\n"
            f"{TITLES[Verdict.SUSPICIOUS]}: fewer engines flagged it, or some marked it "
            "suspicious.\n"
            f"{TITLES[Verdict.CLEAN]}. That is not a guarantee of safety.\n"
            f"{TITLES[Verdict.UNKNOWN]}: no verdict, because of an error, a timeout, the "
            "quota, or because it was not scanned."
        ),
        inline=False,
    )
    embed.add_field(
        name="Privacy",
        value=(
            "Links and files sent for a new scan are shared with VirusTotal's community. "
            "Don't scan private links such as password resets or shared documents."
        ),
        inline=False,
    )
    embed.set_footer(text=DISCLAIMER)
    return embed
