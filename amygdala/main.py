"""Entrypoint for the Amygdala security triage system."""

import argparse
import asyncio
import logging
import sys

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


async def run_live():
    """Main pipeline: ingest -> triage -> investigate -> report -> notify.

    Connects to Splunk via MCP, evaluates alerts with Foundation-Sec,
    investigates high-severity alerts, and delivers reports.
    """
    from .alert_ingestor import AlertIngestor
    from .triage_agent import TriageAgent
    from .investigate_agent import InvestigateAgent
    from .report_builder import ReportBuilder
    from .output_handler import OutputHandler
    from .mcp_client import MCPConnectionError

    logger.info("Starting Amygdala security triage pipeline")

    # Initialize components
    ingestor = AlertIngestor()
    triage = TriageAgent()
    investigator = InvestigateAgent()
    reporter = ReportBuilder()
    output = OutputHandler()

    try:
        # Check MCP health
        if not await ingestor.mcp.health_check():
            logger.warning("MCP server health check failed — proceeding anyway")

        # Fetch alerts
        alerts = await ingestor.fetch_alerts()
        logger.info(f"Fetched {len(alerts)} alerts")

        if not alerts:
            logger.info("No alerts to process. Pipeline complete.")
            return

        # Process each alert through the pipeline
        processed = 0
        escalated = 0
        errors = 0

        for alert in alerts:
            try:
                triage_result = await triage.evaluate(alert)
                logger.debug(
                    f"Alert {alert.get('id')}: severity={triage_result.severity}, "
                    f"category={triage_result.category}"
                )

                if triage_result.severity >= triage_result.threshold:
                    investigation = await investigator.correlate(alert, triage_result)
                    report = reporter.build(alert, triage_result, investigation)
                    await output.send(report)
                    processed += 1

                    if "ESCALATE" in investigation.recommendation:
                        escalated += 1
                        logger.warning(
                            f"ESCALATION: Alert {alert.get('id')} — "
                            f"{investigation.recommendation}"
                        )
                    else:
                        logger.info(f"Alert {alert.get('id')} processed and reported")
                else:
                    logger.debug(
                        f"Alert {alert.get('id')} below threshold "
                        f"({triage_result.severity} < {triage_result.threshold}), skipping"
                    )

            except Exception as e:
                errors += 1
                logger.error(f"Error processing alert {alert.get('id')}: {e}")
                continue  # Don't let one alert crash the whole pipeline

        # Summary
        logger.info(
            f"Pipeline complete: {len(alerts)} alerts, {processed} reported, "
            f"{escalated} escalated, {errors} errors"
        )

    except MCPConnectionError as e:
        logger.critical(f"Cannot connect to MCP server: {e}")
        sys.exit(1)

    finally:
        await ingestor.close()
        await investigator.close()


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
