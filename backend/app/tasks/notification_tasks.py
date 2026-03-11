"""Notification delivery Celery tasks for OWASP Sentinel v3.

Handles outbound notifications via:
- Email (SMTP)
- Generic HTTP webhooks
- Slack incoming webhooks
- Real-time push via Redis pub-sub (consumed by WebSocket gateway)
"""
import json
import logging
import smtplib
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, Optional

import httpx
import redis as redis_lib

from ..config import settings
from .celery_app import celery_app

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="notification_tasks.send_email_notification", max_retries=3)
def send_email_notification(
    self,
    to_email: str,
    subject: str,
    body: str,
    html_body: Optional[str] = None,
) -> Dict[str, Any]:
    """Send an email notification via SMTP.

    Falls back to plain text when *html_body* is not provided.  Uses TLS
    (``STARTTLS``) when ``settings.smtp_port`` is 587, plain connection on
    port 25, and SSL on port 465.
    """
    if not settings.smtp_host:
        logger.warning("SMTP host not configured – skipping email to %s", to_email)
        return {"status": "skipped", "reason": "SMTP not configured", "to": to_email}

    msg = MIMEMultipart("alternative") if html_body else MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from
    msg["To"] = to_email

    # Attach plain-text part
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # Attach HTML part (takes precedence in capable mail clients)
    if html_body:
        msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if settings.smtp_port == 465:
            # Implicit SSL
            with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port) as smtp:
                if settings.smtp_user and settings.smtp_password:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.sendmail(settings.smtp_from, [to_email], msg.as_string())
        else:
            # Plain or STARTTLS
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
                smtp.ehlo()
                if settings.smtp_port == 587:
                    smtp.starttls()
                    smtp.ehlo()
                if settings.smtp_user and settings.smtp_password:
                    smtp.login(settings.smtp_user, settings.smtp_password)
                smtp.sendmail(settings.smtp_from, [to_email], msg.as_string())

        logger.info("send_email_notification: sent to %s subject=%r", to_email, subject)
        return {"status": "sent", "to": to_email, "subject": subject}

    except smtplib.SMTPException as exc:
        logger.exception("send_email_notification SMTP error: %s", exc)
        raise self.retry(exc=exc, countdown=60)
    except Exception as exc:
        logger.exception("send_email_notification unexpected error: %s", exc)
        raise self.retry(exc=exc, countdown=120)


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------


@celery_app.task(bind=True, name="notification_tasks.send_webhook_notification", max_retries=3)
def send_webhook_notification(
    self,
    webhook_url: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Send an HTTP POST request to an arbitrary webhook URL.

    Uses ``httpx`` (sync) with a 15-second timeout and retries on HTTP
    5xx responses or connection errors.
    """
    headers = {
        "Content-Type": "application/json",
        "User-Agent": f"OWASP-Sentinel/{settings.app_version}",
    }
    try:
        with httpx.Client(timeout=15) as client:
            response = client.post(
                webhook_url,
                json=payload,
                headers=headers,
            )

        if response.status_code >= 500:
            raise RuntimeError(
                f"Webhook returned HTTP {response.status_code}: {response.text[:200]}"
            )

        logger.info(
            "send_webhook_notification: url=%s status=%d",
            webhook_url,
            response.status_code,
        )
        return {
            "status": "sent",
            "webhook_url": webhook_url,
            "http_status": response.status_code,
        }

    except httpx.TimeoutException as exc:
        logger.warning("send_webhook_notification timeout: %s", webhook_url)
        raise self.retry(exc=exc, countdown=60)
    except httpx.RequestError as exc:
        logger.warning("send_webhook_notification request error: %s", exc)
        raise self.retry(exc=exc, countdown=60)
    except Exception as exc:
        logger.exception("send_webhook_notification failed: %s", exc)
        raise self.retry(exc=exc, countdown=120)


# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------

# Severity → Slack attachment colour mapping
_SLACK_COLOURS = {
    "critical": "#ff4757",
    "high": "#ff6b35",
    "medium": "#ffa502",
    "low": "#2ed573",
    "info": "#70a1ff",
    "success": "#2ed573",
    "warning": "#ffa502",
    "error": "#ff4757",
}


@celery_app.task(bind=True, name="notification_tasks.send_slack_notification", max_retries=3)
def send_slack_notification(
    self,
    message: str,
    severity: str = "info",
    title: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Send a notification to a Slack channel via the configured incoming webhook.

    The message is formatted as a Slack attachment so that severity is
    visually indicated by colour.
    """
    webhook_url = settings.slack_webhook_url
    if not webhook_url:
        logger.warning("Slack webhook URL not configured – skipping notification")
        return {"status": "skipped", "reason": "Slack webhook not configured"}

    colour = _SLACK_COLOURS.get(severity.lower(), "#70a1ff")
    attachment: Dict[str, Any] = {
        "color": colour,
        "text": message,
        "footer": f"OWASP Sentinel v{settings.app_version}",
        "ts": int(datetime.now(timezone.utc).timestamp()),
    }
    if title:
        attachment["title"] = title
    if details:
        attachment["fields"] = [
            {"title": k, "value": str(v), "short": len(str(v)) < 50}
            for k, v in details.items()
        ]

    slack_payload = {
        "attachments": [attachment],
        "username": "OWASP Sentinel",
        "icon_emoji": ":shield:",
    }

    try:
        with httpx.Client(timeout=10) as client:
            response = client.post(webhook_url, json=slack_payload)

        if response.status_code != 200 or response.text != "ok":
            raise RuntimeError(
                f"Slack responded HTTP {response.status_code}: {response.text}"
            )

        logger.info("send_slack_notification: delivered severity=%s", severity)
        return {"status": "sent", "severity": severity}

    except httpx.TimeoutException as exc:
        raise self.retry(exc=exc, countdown=30)
    except Exception as exc:
        logger.exception("send_slack_notification failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)


# ---------------------------------------------------------------------------
# Real-time (Redis pub-sub)
# ---------------------------------------------------------------------------


@celery_app.task(name="notification_tasks.broadcast_realtime_notification")
def broadcast_realtime_notification(
    user_id: str,
    notification_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Publish a notification to the Redis pub-sub channel for the given user.

    The WebSocket gateway subscribes to ``notifications:<user_id>`` and
    forwards the payload to the connected browser client in real time.
    """
    channel = f"notifications:{user_id}"
    payload = json.dumps(
        {
            **notification_data,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        default=str,
    )

    try:
        client = redis_lib.from_url(settings.redis_url, decode_responses=True)
        subscribers = client.publish(channel, payload)
        client.close()

        logger.info(
            "broadcast_realtime_notification: channel=%s subscribers=%d",
            channel,
            subscribers,
        )
        return {
            "status": "published",
            "channel": channel,
            "subscribers": subscribers,
        }

    except Exception as exc:
        logger.exception("broadcast_realtime_notification failed: %s", exc)
        # Best-effort delivery — do not retry, as the client may have disconnected.
        return {"status": "error", "channel": channel, "error": str(exc)}
