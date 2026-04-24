"""
Alerting system for significant findings.
"""

import json
import logging
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class AlertLevel(str, Enum):
    """Alert severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertChannel:
    """Alert notification channels."""

    def __init__(self):
        self.channels = ["email", "slack", "webhook"]

    async def send_email(
        self,
        to: List[str],
        subject: str,
        body: str,
        smtp_config: Optional[Dict] = None,
    ) -> bool:
        """Send email alert."""
        if not to:
            return False

        msg = MIMEMultipart()
        msg["From"] = smtp_config.get("from", "alerts@tbhm.local")
        msg["To"] = ", ".join(to)
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "html"))

        try:
            with smtplib.SMTP(
                smtp_config.get("host", "localhost"),
                smtp_config.get("port", 25),
            ) as server:
                if smtp_config.get("username"):
                    server.login(
                        smtp_config.get("username"),
                        smtp_config.get("password"),
                    )
                server.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"Error sending email: {e}")
            return False

    async def send_slack(
        self,
        webhook_url: str,
        message: str,
        severity: str = "warning",
    ) -> bool:
        """Send Slack alert."""
        import httpx

        color_map = {
            "critical": "#d32f2f",
            "high": "#f57c00",
            "medium": "#fbc02d",
            "low": "#388e3c",
            "info": "#1976d2",
        }

        payload = {
            "attachments": [{
                "color": color_map.get(severity, "#888888"),
                "text": message,
                "ts": int(datetime.utcnow().timestamp()),
            }]
        }

        try:
            async with httpx.AsyncClient() as client:
                await client.post(webhook_url, json=payload)
            return True
        except Exception as e:
            logger.error(f"Error sending Slack alert: {e}")
            return False

    async def send_webhook(
        self,
        url: str,
        payload: Dict,
    ) -> bool:
        """Send webhook alert."""
        import httpx

        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, json=payload)
            return True
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")
            return False


class AlertManager:
    """Manage alert rules and notifications."""

    def __init__(self):
        self.rules = []
        self.alert_history = []

    def add_rule(
        self,
        name: str,
        condition: str,
        level: AlertLevel,
        channels: List[str],
    ) -> None:
        """Add alert rule."""
        self.rules.append({
            "name": name,
            "condition": condition,
            "level": level,
            "channels": channels,
            "enabled": True,
        })

    def check_conditions(
        self,
        findings: Dict,
    ) -> List[Dict]:
        """Check alert conditions."""
        alerts = []

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            condition = rule.get("condition", "")

            triggered = False
            if condition == "new_critical_vuln":
                vulns = findings.get("vulnerabilities", {}).get("vulnerabilities", [])
                triggered = any(v.get("severity") == "critical" for v in vulns)
            elif condition == "new_subdomain":
                triggered = findings.get("subdomains", {}).get("added_count", 0) > 0
            elif condition == "new_service":
                triggered = findings.get("services", {}).get("new_count", 0) > 0

            if triggered:
                alerts.append({
                    "rule": rule.get("name"),
                    "level": rule.get("level"),
                    "channels": rule.get("channels"),
                    "timestamp": datetime.utcnow().isoformat(),
                })

        return alerts

    async def send_alerts(
        self,
        alerts: List[Dict],
        config: Dict,
    ) -> None:
        """Send alerts through configured channels."""
        channel = AlertChannel()

        for alert in alerts:
            for channel_name in alert.get("channels", []):
                if channel_name == "email":
                    await channel.send_email(
                        config.get("email_to", []),
                        f"[{alert.get('level')}] TBHM Alert",
                        json.dumps(alert, indent=2),
                        config.get("smtp", {}),
                    )
                elif channel_name == "slack":
                    await channel.send_slack(
                        config.get("slack_webhook", ""),
                        json.dumps(alert, indent=2),
                        alert.get("level", "warning"),
                    )
                elif channel_name == "webhook":
                    await channel.send_webhook(
                        config.get("webhook_url", ""),
                        alert,
                    )

            self.alert_history.append(alert)


async def trigger_alert(
    target_id: str,
    alert_type: str,
    findings: Dict,
    config: Dict,
) -> dict:
    """Trigger alerts based on findings."""
    manager = AlertManager()

    alerts = manager.check_conditions(findings)

    await manager.send_alerts(alerts, config)

    return {
        "target_id": target_id,
        "alert_type": alert_type,
        "alerts_sent": len(alerts),
        "alerts": alerts,
    }