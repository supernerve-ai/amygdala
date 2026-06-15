"""Output handler for Slack/webhook notifications."""

import os
import json
import logging

import httpx

logger = logging.getLogger(__name__)


class OutputHandler:
    """Sends incident reports to Slack and webhook endpoints."""

    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.slack_channel = os.getenv("SLACK_CHANNEL", "#security-alerts")

    async def send(self, report: dict):
        """Send report to configured outputs."""
        if self.slack_webhook:
            await self._send_slack(report)
        else:
            logger.warning("No Slack webhook configured, printing report")
            print(json.dumps(report, indent=2))

    async def _send_slack(self, report: dict):
        """Send formatted report to Slack."""
        message = self._format_slack_message(report)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.slack_webhook,
                json=message,
            )
            if response.status_code == 200:
                logger.info(f"Report {report['report_id']} sent to Slack")
            else:
                logger.error(f"Failed to send to Slack: {response.status_code}")

    def _format_slack_message(self, report: dict) -> dict:
        """Format report as Slack Block Kit message."""
        triage = report["triage"]
        investigation = report["investigation"]

        return {
            "channel": self.slack_channel,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🚨 Security Alert: {report['report_id']}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:* {triage['severity']}/10"},
                        {"type": "mrkdwn", "text": f"*Category:* {triage['category']}"},
                        {"type": "mrkdwn", "text": f"*Risk Score:* {investigation['risk_score']:.2f}"},
                        {"type": "mrkdwn", "text": f"*IOCs:* {len(investigation['ioc_matches'])}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Summary:* {triage['summary']}",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Recommendation:* {investigation['recommendation']}",
                    },
                },
            ],
        }
