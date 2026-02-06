"""Telegram bot pairing flow manager."""

import hmac
import os
from datetime import datetime, timezone
from typing import Callable, Awaitable

import httpx
from loguru import logger

from nanobot.config.loader import load_config, save_config


class PairingManager:
    """Manages Telegram bot pairing flow."""

    def __init__(self):
        self.pairing_token = os.environ.get("NANOBOT_PAIRING_TOKEN")
        self.webhook_url = os.environ.get("NANOBOT_PAIRING_WEBHOOK_URL")
        self.bot_id = os.environ.get("NANOBOT_BOT_ID")
        self._is_paired = os.environ.get("NANOBOT_IS_PAIRED", "").lower() == "true"
        self._paired_user_id: int | None = None
        self._load_pairing_state()

    def _load_pairing_state(self) -> None:
        """Load paired user from config on startup."""
        try:
            config = load_config()
            if config.channels.telegram.paired:
                self._is_paired = True
                allow_from = config.channels.telegram.allow_from
                if allow_from:
                    first_entry = allow_from[0]
                    user_id_str = first_entry.split("|")[0]
                    self._paired_user_id = int(user_id_str)
                    logger.debug(f"Loaded paired user ID: {self._paired_user_id}")
        except Exception as e:
            logger.warning(f"Failed to load pairing state: {e}")

    @property
    def pairing_enabled(self) -> bool:
        """Returns True if all pairing env vars are set."""
        return bool(self.pairing_token and self.webhook_url and self.bot_id)

    @property
    def is_paired(self) -> bool:
        """Returns True if already paired."""
        return self._is_paired

    def _token_matches(self, provided_token: str) -> bool:
        """Constant-time token comparison."""
        if not self.pairing_token or not provided_token:
            return False
        return hmac.compare_digest(self.pairing_token, provided_token)

    async def handle_start_command(
        self,
        user_id: int,
        username: str | None,
        first_name: str | None,
        token_arg: str | None,
        reply_func: Callable[[str], Awaitable[None]],
    ) -> bool:
        """
        Handle /start command with pairing support.

        Returns True if the command was handled by pairing logic,
        False if normal /start flow should proceed.
        """
        if not self.pairing_enabled:
            return False

        if token_arg:
            safe_token = token_arg[:10] + "..." if len(token_arg) > 10 else token_arg
            logger.debug(f"Start command with token: {safe_token}")

        if self._is_paired and self._paired_user_id == user_id:
            await reply_func(
                f"Welcome back, {first_name or 'friend'}! You're already paired with this bot."
            )
            return True

        if self._is_paired and self._paired_user_id != user_id:
            logger.debug(f"Ignoring start from unpaired user: {user_id}")
            return True

        if token_arg:
            if self._token_matches(token_arg):
                await self._execute_pairing(user_id, username, first_name, reply_func)
                return True
            else:
                logger.warning(f"Invalid pairing token from user {user_id}")
                await reply_func(
                    "Invalid pairing token. Please check your link and try again."
                )
                return True

        await reply_func(
            "This bot requires pairing. Please use the pairing link provided to you."
        )
        return True

    def should_accept_message(self, user_id: int) -> bool:
        """Check if user is authorized to send messages."""
        if not self.pairing_enabled:
            return True
        if not self._is_paired:
            return False
        return self._paired_user_id == user_id

    async def _execute_pairing(
        self,
        user_id: int,
        username: str | None,
        first_name: str | None,
        reply_func: Callable[[str], Awaitable[None]],
    ) -> None:
        """Execute the pairing: update config, send webhook, reply to user."""
        paired_at = datetime.now(timezone.utc).isoformat()

        self._update_config(user_id, username, paired_at)
        self._is_paired = True
        self._paired_user_id = user_id

        await self._send_webhook(user_id, username, first_name, paired_at)

        await reply_func(
            f"Successfully paired! Welcome, {first_name or 'friend'}. "
            "You can now send me messages."
        )
        logger.info(f"Paired with Telegram user {user_id} ({username})")

    def _update_config(self, user_id: int, username: str | None, paired_at: str) -> None:
        """Update config.json with pairing info."""
        try:
            config = load_config()

            allow_entry = str(user_id)
            if username:
                allow_entry = f"{user_id}|{username}"

            if allow_entry not in config.channels.telegram.allow_from:
                config.channels.telegram.allow_from.append(allow_entry)

            config.channels.telegram.paired = True
            config.channels.telegram.paired_at = paired_at

            save_config(config)
            logger.debug("Updated config with pairing info")
        except Exception as e:
            logger.error(f"Failed to update config: {e}")

    async def _send_webhook(
        self,
        user_id: int,
        username: str | None,
        first_name: str | None,
        paired_at: str,
    ) -> None:
        """Send webhook notification (best-effort)."""
        if not self.webhook_url:
            return

        payload = {
            "bot_id": self.bot_id,
            "telegram_user_id": user_id,
            "telegram_username": username,
            "telegram_first_name": first_name,
            "paired_at": paired_at,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(self.webhook_url, json=payload)
                if response.status_code >= 400:
                    logger.warning(
                        f"Webhook returned {response.status_code}: {response.text[:100]}"
                    )
                else:
                    logger.debug(f"Webhook sent successfully: {response.status_code}")
        except Exception as e:
            logger.warning(f"Failed to send pairing webhook: {e}")
