"""Notify wrapper for multi-platform security alert notifications."""
from __future__ import annotations

import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

logger = logging.getLogger("owasp_sentinel.tools.notify")


class NotifyWrapper:
    """Send security notifications via Slack, Discord, Telegram, or Email."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    async def send_notification(self, provider: str, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a notification via the specified provider.

        Args:
            provider: 'slack' | 'discord' | 'telegram' | 'email'
            message: Notification message text.
            **kwargs: Provider-specific options.

        Returns:
            Dict with 'success' bool and optional 'error'.
        """
        provider = provider.lower()
        if provider == "slack":
            return await self.send_slack(message, **kwargs)
        elif provider == "discord":
            return await self.send_discord(message, **kwargs)
        elif provider == "telegram":
            return await self.send_telegram(message, **kwargs)
        elif provider == "email":
            return self.send_email(message, **kwargs)
        else:
            return {"success": False, "error": f"Unknown provider: {provider}"}

    async def send_slack(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a Slack notification via webhook URL."""
        try:
            import httpx
        except ImportError:
            return {"success": False, "error": "httpx not installed"}

        webhook_url = kwargs.get("webhook_url") or self.config.get("slack_webhook_url", "")
        if not webhook_url:
            return {"success": False, "error": "No Slack webhook URL configured"}

        payload: dict[str, Any] = {
            "text": message,
            "username": kwargs.get("username", "OWASP Sentinel"),
            "icon_emoji": kwargs.get("icon_emoji", ":shield:"),
        }
        if channel := kwargs.get("channel"):
            payload["channel"] = channel

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
            return {"success": resp.status_code == 200, "status_code": resp.status_code}

    async def send_discord(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a Discord notification via webhook URL."""
        try:
            import httpx
        except ImportError:
            return {"success": False, "error": "httpx not installed"}

        webhook_url = kwargs.get("webhook_url") or self.config.get("discord_webhook_url", "")
        if not webhook_url:
            return {"success": False, "error": "No Discord webhook URL configured"}

        payload: dict[str, Any] = {
            "content": message,
            "username": kwargs.get("username", "OWASP Sentinel"),
        }
        if embeds := kwargs.get("embeds"):
            payload["embeds"] = embeds

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
            return {"success": resp.status_code in (200, 204), "status_code": resp.status_code}

    async def send_telegram(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send a Telegram message via Bot API."""
        try:
            import httpx
        except ImportError:
            return {"success": False, "error": "httpx not installed"}

        token = kwargs.get("bot_token") or self.config.get("telegram_bot_token", "")
        chat_id = kwargs.get("chat_id") or self.config.get("telegram_chat_id", "")
        if not token or not chat_id:
            return {"success": False, "error": "Telegram bot_token and chat_id required"}

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}

        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json=payload)
            return {"success": resp.status_code == 200, "status_code": resp.status_code}

    def send_email(self, message: str, **kwargs: Any) -> dict[str, Any]:
        """Send an email notification via SMTP."""
        smtp_host = kwargs.get("smtp_host") or self.config.get("smtp_host", "localhost")
        smtp_port = int(kwargs.get("smtp_port") or self.config.get("smtp_port", 587))
        smtp_user = kwargs.get("smtp_user") or self.config.get("smtp_user", "")
        smtp_pass = kwargs.get("smtp_pass") or self.config.get("smtp_pass", "")
        to_addr = kwargs.get("to") or self.config.get("email_to", "")
        from_addr = kwargs.get("from_addr") or self.config.get("email_from", smtp_user)
        subject = kwargs.get("subject", "OWASP Sentinel Alert")

        if not to_addr:
            return {"success": False, "error": "No recipient email address configured"}

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg.attach(MIMEText(message, "plain"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, [to_addr], msg.as_string())
            return {"success": True}
        except Exception as exc:
            logger.error("Email send failed: %s", exc)
            return {"success": False, "error": str(exc)}
