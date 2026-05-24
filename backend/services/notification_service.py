# ============================================
# SentinelAI - Notification Service
# ============================================
"""
Notification service for scan completion, alerts, and CI/CD webhooks.
Supports Slack webhooks, generic HTTP webhooks, and email notifications.
"""

import logging
import json
from typing import Optional, Dict, Any, List
from datetime import datetime

import httpx

from config import settings

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending scan notifications and alerts."""
    
    def __init__(self):
        pass
    
    async def send_slack_notification(self, webhook_url: str, scan_data: Dict[str, Any]) -> bool:
        """
        Send a scan completion notification to Slack.
        
        Args:
            webhook_url: Slack incoming webhook URL
            scan_data: Scan summary data
            
        Returns:
            True if sent successfully
        """
        try:
            color = self._get_severity_color(scan_data.get("grade", "C"))
            
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🛡️ SentinelAI Scan Complete - Grade {scan_data.get('grade', 'N/A')}",
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Target:*\n{scan_data.get('target', 'N/A')}"},
                            {"type": "mrkdwn", "text": f"*Type:*\n{scan_data.get('scan_type', 'N/A')}"},
                            {"type": "mrkdwn", "text": f"*Risk Score:*\n{scan_data.get('risk_score', 'N/A')}/100"},
                            {"type": "mrkdwn", "text": f"*Duration:*\n{scan_data.get('duration_seconds', 0)//60}m {scan_data.get('duration_seconds', 0)%60}s"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Findings:* {scan_data.get('stats', {}).get('critical', 0)} critical, "
                                    f"{scan_data.get('stats', {}).get('high', 0)} high, "
                                    f"{scan_data.get('stats', {}).get('medium', 0)} medium, "
                                    f"{scan_data.get('stats', {}).get('low', 0)} low",
                        }
                    }
                ]
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload, timeout=30.0)
                response.raise_for_status()
            
            logger.info("Slack notification sent successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    async def send_webhook(self, webhook_url: str, webhook_secret: Optional[str],
                          event: str, data: Dict[str, Any]) -> bool:
        """
        Send a generic HTTP webhook notification.
        
        Args:
            webhook_url: Target webhook URL
            webhook_secret: Optional secret for HMAC signature
            event: Event type (e.g., 'scan.complete', 'scan.failed')
            data: Event payload
            
        Returns:
            True if sent successfully
        """
        try:
            payload = {
                "event": event,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": settings.APP_NAME,
                "version": settings.APP_VERSION,
                "data": data,
            }
            
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"SentinelAI/{settings.APP_VERSION}",
                "X-SentinelAI-Event": event,
            }
            
            if webhook_secret:
                import hmac
                import hashlib
                payload_bytes = json.dumps(payload).encode()
                signature = hmac.new(
                    webhook_secret.encode(),
                    payload_bytes,
                    hashlib.sha256,
                ).hexdigest()
                headers["X-SentinelAI-Signature"] = f"sha256={signature}"
            
            async with httpx.AsyncClient() as client:
                response = await client.post(webhook_url, json=payload, headers=headers, timeout=30.0)
                response.raise_for_status()
            
            logger.info(f"Webhook sent successfully to {webhook_url}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
            return False
    
    async def send_scan_complete(self, scan_summary: Dict[str, Any], notification_config: Dict[str, Any]) -> Dict[str, bool]:
        """
        Send scan completion notifications through all configured channels.
        
        Args:
            scan_summary: Scan summary data
            notification_config: Configuration for notifications
            
        Returns:
            Dict of channel -> success status
        """
        results = {}
        
        # Check severity threshold
        min_severity = notification_config.get("notify_on_severity", "high")
        severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "none": -1, "all": 4}
        min_level = severity_levels.get(min_severity, 3)
        
        stats = scan_summary.get("stats", {})
        scan_level = 4 if stats.get("critical", 0) > 0 else 3 if stats.get("high", 0) > 0 else 2 if stats.get("medium", 0) > 0 else 1 if stats.get("low", 0) > 0 else 0
        
        if scan_level < min_level and min_severity != "all":
            logger.info(f"Scan severity level ({scan_level}) below notification threshold ({min_level})")
            return {}
        
        # Slack notification
        if notification_config.get("slack_webhook_url"):
            results["slack"] = await self.send_slack_notification(
                notification_config["slack_webhook_url"],
                scan_summary,
            )
        
        # Generic webhook
        if notification_config.get("webhook_url"):
            results["webhook"] = await self.send_webhook(
                notification_config["webhook_url"],
                notification_config.get("webhook_secret"),
                "scan.complete",
                scan_summary,
            )
        
        return results
    
    @staticmethod
    def _get_severity_color(grade: str) -> str:
        """Get color for a grade."""
        colors = {
            "A": "#22c55e",
            "B": "#84cc16",
            "C": "#eab308",
            "D": "#f97316",
            "F": "#ef4444",
        }
        return colors.get(grade, "#64748b")