"""Discord client: loads the command cogs, syncs slash commands, and handles errors."""

from __future__ import annotations

import logging

import discord
from discord import app_commands
from discord.ext import commands

from totalv.config import Settings
from totalv.vt_client import VirusTotalClient

log = logging.getLogger(__name__)

EXTENSIONS = ("totalv.cogs.scanner",)

# Used for every message the bot sends. Scanned URLs and filenames are user
# input, so they must never be able to ping @everyone, roles, or users.
NO_MENTIONS = discord.AllowedMentions.none()

# The permissions TotalV needs, used to build the invite link.
INVITE_PERMISSIONS = discord.Permissions(
    view_channel=True,
    send_messages=True,
    embed_links=True,
    attach_files=True,
    read_message_history=True,
)


class TotalVBot(commands.Bot):
    """The TotalV Discord client. Only slash commands are used."""

    def __init__(self, settings: Settings) -> None:
        # TotalV never joins voice channels, so the startup warnings about
        # missing voice libraries are just noise.
        discord.VoiceClient.warn_nacl = False
        discord.VoiceClient.warn_dave = False
        super().__init__(
            # commands.Bot requires a prefix. Mention-only means no message text
            # is ever read, so the privileged Message Content intent is not needed.
            command_prefix=commands.when_mentioned,
            intents=discord.Intents.default(),
            help_command=None,
            allowed_mentions=NO_MENTIONS,
        )
        self.settings = settings
        # One client for the whole bot, so every command shares the same rate
        # limiter, daily counter, and cache.
        self.vt = VirusTotalClient.from_settings(settings)

    async def setup_hook(self) -> None:
        """Runs once after login and before connecting to the gateway."""
        await self.vt.start()
        self.tree.on_error = self.on_app_command_error
        for extension in EXTENSIONS:
            await self.load_extension(extension)
        await self.sync_commands()

    async def sync_commands(self) -> None:
        """Register slash commands with Discord.

        Commands synced to one server appear immediately, which is handy while
        developing. Global commands can take a while to show up everywhere.
        """
        guild_id = self.settings.dev_guild_id
        try:
            if guild_id is not None:
                guild = discord.Object(id=guild_id)
                self.tree.copy_global_to(guild=guild)
                synced = await self.tree.sync(guild=guild)
                log.info("Synced %d commands to server %s.", len(synced), guild_id)
            else:
                synced = await self.tree.sync()
                log.info("Synced %d commands globally.", len(synced))
        except discord.Forbidden:
            log.error(
                "Could not sync commands to server %s. Is TotalV in that server, and "
                "was it invited with the applications.commands scope?",
                guild_id,
            )

    async def close(self) -> None:
        """Close the VirusTotal HTTP session along with the Discord connection."""
        await self.vt.close()
        await super().close()

    async def on_ready(self) -> None:
        """Log who we are and help with the invite if the bot is in no server yet."""
        assert self.user is not None  # always set once the bot is ready
        log.info(
            "Logged in as %s (ID %s), in %d server(s).", self.user, self.user.id, len(self.guilds)
        )
        if not self.guilds:
            invite = discord.utils.oauth_url(
                self.user.id,
                permissions=INVITE_PERMISSIONS,
                scopes=("bot", "applications.commands"),
            )
            log.warning("TotalV is not in any server yet. Invite it with: %s", invite)

    async def on_app_command_error(
        self, interaction: discord.Interaction, error: app_commands.AppCommandError
    ) -> None:
        """Last-resort handler: log the full error, show the user a short message."""
        command = interaction.command.name if interaction.command else "unknown"
        log.error("Error in /%s", command, exc_info=error)
        message = "Something went wrong while running that command. Please try again later."
        try:
            if interaction.response.is_done():
                await interaction.followup.send(
                    message, ephemeral=True, allowed_mentions=NO_MENTIONS
                )
            else:
                await interaction.response.send_message(
                    message, ephemeral=True, allowed_mentions=NO_MENTIONS
                )
        except discord.HTTPException:
            # The interaction may have expired; the error is already logged.
            pass
