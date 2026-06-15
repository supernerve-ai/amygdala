"""Entrypoint for the Amygdala security triage system."""

import asyncio
import logging

from dotenv import load_dotenv

from .alert_ingestor import AlertIngestor
from .triage_agent import TriageAgent
from .investigate_agent import InvestigateAgent
from .report_builder import ReportBuilder
from .output_handler import OutputHandler

load_dotenv()

logger = logging.getLogger(__name__)


async def main():
    """Main pipeline: ingest -> triage -> investigate -> report -> notify."""
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting Amygdala security triage pipeline")

    # Initialize components
    ingestor = AlertIngestor()
    triage = TriageAgent()
    investigator = InvestigateAgent()
    reporter = ReportBuilder()
    output = OutputHandler()

    # Pipeline
    alerts = await ingestor.fetch_alerts()
    logger.info(f"Fetched {len(alerts)} alerts")

    for alert in alerts:
        triage_result = await triage.evaluate(alert)

        if triage_result.severity >= triage_result.threshold:
            investigation = await investigator.correlate(alert, triage_result)
            report = reporter.build(alert, triage_result, investigation)
            await output.send(report)
            logger.info(f"Alert {alert.get('id')} processed and reported")
        else:
            logger.debug(f"Alert {alert.get('id')} below threshold, skipping")


if __name__ == "__main__":
    asyncio.run(main())
