"""Entrypoint for the Amygdala security triage system."""

import argparse
import asyncio
import logging
import sys

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


async def run_live():
    """Main pipeline: ingest -> triage -> investigate -> report -> notify."""
    from .alert_ingestor import AlertIngestor
    from .triage_agent import TriageAgent
    from .investigate_agent import InvestigateAgent
    from .report_builder import ReportBuilder
    from .output_handler import OutputHandler

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


async def run_demo():
    """Run the pipeline in demo mode with sample data."""
    from .demo import run_demo as demo_pipeline
    await demo_pipeline()


def main():
    """Parse args and run the appropriate mode."""
    parser = argparse.ArgumentParser(
        description="🧠 Amygdala — Autonomous SOC Analyst",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m amygdala.main --demo        Run with sample data (no Splunk needed)
  python -m amygdala.main               Run live pipeline (requires Splunk + MCP)
  python -m amygdala.main --verbose     Run with debug logging
        """,
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with sample alerts (no Splunk connection required)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if args.demo:
        asyncio.run(run_demo())
    else:
        asyncio.run(run_live())


if __name__ == "__main__":
    main()
