"""Streamlit UI for Amygdala demo mode."""

import json
import time
import streamlit as st
from pathlib import Path

# Must be first Streamlit call
st.set_page_config(
    page_title="Amygdala — Autonomous SOC Analyst",
    page_icon="🧠",
    layout="wide",
    initial_sidebar_state="expanded",
)

from amygdala.demo import (
    load_sample_alerts,
    simulate_triage,
    simulate_investigation,
    format_human_readable,
)
from amygdala.report_builder import ReportBuilder


# --- Styling ---
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background: #f8fafc;
        border-radius: 12px;
        padding: 1.25rem;
        border: 1px solid #e2e8f0;
    }
    .severity-critical { color: #dc2626; font-weight: 700; }
    .severity-high { color: #ea580c; font-weight: 700; }
    .severity-medium { color: #ca8a04; font-weight: 700; }
    .severity-low { color: #16a34a; font-weight: 700; }
    .escalate-badge {
        background: #fef2f2;
        color: #dc2626;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .monitor-badge {
        background: #f0fdf4;
        color: #16a34a;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.8rem;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


def severity_color(severity: int) -> str:
    if severity >= 8:
        return "severity-critical"
    elif severity >= 6:
        return "severity-high"
    elif severity >= 4:
        return "severity-medium"
    return "severity-low"


def severity_emoji(severity: int) -> str:
    if severity >= 8:
        return "🔴"
    elif severity >= 5:
        return "🟡"
    return "🟢"


def main():
    # Header
    st.markdown("<h1 style='text-align:center;'>🧠 Amygdala</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:#6b7280; font-size:1.1rem;'>Autonomous SOC Analyst — Demo Mode</p>", unsafe_allow_html=True)
    st.markdown("---")

    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        threshold = st.slider("Severity Threshold", 1, 10, 5, help="Alerts below this severity are skipped")
        st.markdown("---")

        st.header("📖 About")
        st.markdown("""
        **Amygdala** connects to Splunk via MCP, 
        triages alerts with Foundation-Sec-1.1-8B, 
        and spawns investigation sub-agents autonomously.
        
        This demo uses sample alerts to showcase 
        the full pipeline without needing Splunk.
        """)

        st.markdown("---")
        st.markdown("[GitHub](https://github.com/supernerve-ai/amygdala) · [Docs](https://supernerve-ai.github.io/amygdala/)")

    # Load alerts
    alerts = load_sample_alerts()

    # Pipeline control
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        run_pipeline = st.button("▶️ Run Pipeline", use_container_width=True, type="primary")

    if run_pipeline:
        st.markdown("---")

        # Progress
        progress_bar = st.progress(0, text="Ingesting alerts...")
        time.sleep(0.5)

        # Metrics placeholders
        metric_cols = st.columns(4)
        total_placeholder = metric_cols[0].empty()
        processed_placeholder = metric_cols[1].empty()
        escalated_placeholder = metric_cols[2].empty()
        skipped_placeholder = metric_cols[3].empty()

        reports = []
        skipped = 0
        escalated_count = 0
        builder = ReportBuilder()

        st.markdown("---")
        st.subheader("📋 Alert Processing")

        for i, alert in enumerate(alerts):
            progress = (i + 1) / len(alerts)
            progress_bar.progress(progress, text=f"Processing alert {i+1}/{len(alerts)}...")
            time.sleep(0.3)  # Simulate processing time

            # Triage
            triage_result = simulate_triage(alert)
            triage_result.threshold = threshold  # Use user-configured threshold

            with st.expander(
                f"{severity_emoji(triage_result.severity)} **{alert['id']}** — "
                f"{alert['event_type']} | Severity: {triage_result.severity}/10",
                expanded=(triage_result.severity >= threshold),
            ):
                col_a, col_b = st.columns([2, 1])

                with col_a:
                    st.markdown(f"**Description:** {alert['description']}")
                    st.markdown(f"**Source IP:** `{alert['src_ip']}` → **Dest IP:** `{alert.get('dst_ip', 'N/A')}`")
                    st.markdown(f"**User:** {alert.get('user', 'N/A')} | **Host:** {alert.get('host', 'N/A')}")

                with col_b:
                    st.metric("Severity", f"{triage_result.severity}/10")
                    st.caption(f"Category: {triage_result.category}")

                if triage_result.severity >= threshold:
                    # Investigation
                    investigation = simulate_investigation(alert, triage_result)
                    report = builder.build(alert, triage_result, investigation)
                    reports.append(report)

                    if "ESCALATE" in investigation.recommendation:
                        escalated_count += 1

                    st.markdown("---")
                    inv_cols = st.columns(4)
                    inv_cols[0].metric("Risk Score", f"{investigation.risk_score:.0%}")
                    inv_cols[1].metric("Correlated", f"{len(investigation.correlated_events)}")
                    inv_cols[2].metric("IOCs", f"{len(investigation.ioc_matches)}")
                    inv_cols[3].metric("Timeline", f"{len(investigation.timeline)} events")

                    st.markdown(f"**Summary:** {triage_result.summary}")

                    if investigation.ioc_matches:
                        st.warning("**IOC Matches:**")
                        for ioc in investigation.ioc_matches:
                            st.markdown(f"- `{ioc}`")

                    if "ESCALATE" in investigation.recommendation:
                        st.error(f"🚨 **{investigation.recommendation}**")
                    else:
                        st.info(f"ℹ️ {investigation.recommendation}")
                else:
                    skipped += 1
                    st.info(f"⏭️ Below threshold ({triage_result.severity} < {threshold}) — skipped")

        # Update metrics
        progress_bar.progress(1.0, text="Pipeline complete!")
        total_placeholder.metric("Total Alerts", len(alerts))
        processed_placeholder.metric("Reports Generated", len(reports))
        escalated_placeholder.metric("Escalated", escalated_count)
        skipped_placeholder.metric("Skipped", skipped)

        # Reports section
        if reports:
            st.markdown("---")
            st.subheader("📊 Generated Reports")

            tab_json, tab_human = st.tabs(["JSON Reports", "Human-Readable"])

            with tab_json:
                st.json(reports)

            with tab_human:
                for report in reports:
                    st.code(format_human_readable(report), language="text")

            # Download button
            json_str = json.dumps(reports, indent=2, default=str)
            st.download_button(
                "📥 Download Reports (JSON)",
                data=json_str,
                file_name="amygdala_demo_reports.json",
                mime="application/json",
            )

    else:
        # Show alert preview when pipeline hasn't run yet
        st.markdown("---")
        st.subheader("📥 Sample Alerts Ready")
        st.markdown(f"**{len(alerts)} alerts** loaded from sample data. Click **Run Pipeline** to process them.")

        st.markdown("")
        cols = st.columns(len(alerts))
        for i, (col, alert) in enumerate(zip(cols, alerts)):
            with col:
                st.markdown(f"**{alert['id'].split('-')[-1]}**")
                st.caption(alert["event_type"])
                hint = alert.get("severity_hint", "medium")
                st.markdown(f"_{hint}_")


if __name__ == "__main__":
    main()
