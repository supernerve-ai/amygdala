"""Output handler for Slack/webhook notifications."""

import json
import os
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class OutputError(Exception):
    """Raised when output delivery fails."""
    pass


class OutputHandler:
    """Sends incident reports to Slack and webhook endpoints.

    Supports multiple output channels with graceful fallback.
    Failed deliveries are logged but don't crash the pipeline.
    """

    def __init__(self):
        self.slack_webhook = os.getenv("SLACK_WEBHOOK_URL")
        self.slack_channel = os.getenv("SLACK_CHANNEL", "#security-alerts")
        self.custom_webhook = os.getenv("CUSTOM_WEBHOOK_URL")
        self.timeout = int(os.getenv("OUTPUT_TIMEOUT", "15"))

    async def send(self, report: dict) -> bool:
        """Send report to all configured outputs.

        Args:
            report: Structured incident report dictionary

        Returns:
            True if at least one output succeeded, False if all failed
        """
        success = False

        if self.slack_webhook:
            try:
                await self._send_slack(report)
                success = True
            except OutputError as e:
                logger.error(f"Slack delivery failed: {e}")

        if self.custom_webhook:
            try:
                await self._send_webhook(report)
                success = True
            except OutputError as e:
                logger.error(f"Webhook delivery failed: {e}")

        if not self.slack_webhook and not self.custom_webhook:
            # No outputs configured — print to stdout
            self._print_report(report)
            success = True

        return success

    async def _send_slack(self, report: dict):
        """Send formatted report to Slack via incoming webhook."""
        message = self._format_slack_message(report)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(self.slack_webhook, json=message)

                if response.status_code == 200:
                    logger.info(f"Report {report['report_id']} sent to Slack")
                else:
                    raise OutputError(
                        f"Slack returned {response.status_code}: {response.text[:100]}"
                    )
            except httpx.ConnectError as e:
                raise OutputError(f"Cannot reach Slack webhook: {e}")
            except httpx.TimeoutException:
                raise OutputError("Slack webhook request timed out")

    async def _send_webhook(self, report: dict):
        """Send raw JSON report to a custom webhook endpoint."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    self.custom_webhook,
                    json=report,
                    headers={"Content-Type": "application/json"},
                )
                if response.status_code in (200, 201, 202, 204):
                    logger.info(f"Report {report['report_id']} sent to webhook")
                else:
                    raise OutputError(
                        f"Webhook returned {response.status_code}: {response.text[:100]}"
                    )
            except httpx.ConnectError as e:
                raise OutputError(f"Cannot reach webhook: {e}")
            except httpx.TimeoutException:
                raise OutputError("Webhook request timed out")

    def _print_report(self, report: dict):
        """Print report to stdout as formatted JSON."""
        logger.warning("No output channels configured — printing to stdout")
        print(json.dumps(report, indent=2, default=str))

    def _format_slack_message(self, report: dict) -> dict:
        """Format report as Slack Block Kit message.

        Produces a rich message with severity, category, risk score,
        IOC count, summary, and recommendation.
        """
        triage = report["triage"]
        investigation = report["investigation"]

        # Severity emoji
        sev = triage["severity"]
        if sev >= 8:
            sev_emoji = "🔴"
        elif sev >= 5:
            sev_emoji = "🟡"
        else:
            sev_emoji = "🟢"

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
                        {"type": "mrkdwn", "text": f"*Severity:* {sev_emoji} {sev}/10"},
                        {"type": "mrkdwn", "text": f"*Category:* {triage['category']}"},
                        {"type": "mrkdwn", "text": f"*Risk Score:* {investigation['risk_score']:.0%}"},
                        {"type": "mrkdwn", "text": f"*IOCs:* {len(investigation['ioc_matches'])}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Summary:* {triage['summary'][:300]}",
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
