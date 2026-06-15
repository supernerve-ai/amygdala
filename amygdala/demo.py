"""Demo mode — runs the full pipeline with sample data and simulated LLM responses."""

import json
import logging
import os
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .triage_agent import TriageResult
from .investigate_agent import InvestigationResult
from .report_builder import ReportBuilder
from .output_handler import OutputHandler

logger = logging.getLogger(__name__)

# Simulated triage evaluations keyed by event_type
SIMULATED_TRIAGE = {
    "brute_force": TriageResult(
        severity=7,
        threshold=5,
        category="credential_attack",
        summary="High-volume SSH brute force attack detected. 150 failed login attempts "
        "against admin account in 60 seconds from single external IP. Pattern consistent "
        "with automated credential stuffing tool.",
        recommended_action="Block source IP at firewall, force password reset for targeted account, "
        "check for successful logins from same source.",
    ),
    "lateral_movement": TriageResult(
        severity=9,
        threshold=5,
        category="lateral_movement",
        summary="Post-compromise lateral movement detected. Source IP previously flagged for "
        "brute force is now accessing SMB shares on internal file server using service "
        "account credentials. Finance and HR shares accessed.",
        recommended_action="ESCALATE immediately. Isolate source and destination hosts. "
        "Revoke svc_backup credentials. Begin incident response.",
    ),
    "malware_download": TriageResult(
        severity=9,
        threshold=5,
        category="malware",
        summary="Executable download from known malicious domain. User workstation connected "
        "to evil-payload.example.com and downloaded a 2MB executable. File hash matches "
        "known malware signature in threat intel feeds.",
        recommended_action="ESCALATE. Isolate workstation-45 from network. Acquire disk image "
        "for forensics. Check if payload executed. Scan for IOCs across fleet.",
    ),
    "privilege_escalation": TriageResult(
        severity=10,
        threshold=5,
        category="privilege_escalation",
        summary="Critical privilege escalation on compromised host. Service account that was "
        "targeted by brute force has now gained root access via sudo. This indicates "
        "full system compromise following credential attack chain.",
        recommended_action="ESCALATE: CRITICAL. Host is fully compromised. Isolate immediately. "
        "This is part of an active attack chain: scan → brute force → lateral movement → "
        "privilege escalation.",
    ),
    "port_scan": TriageResult(
        severity=4,
        threshold=5,
        category="reconnaissance",
        summary="Horizontal port scan from external IP across internal subnet. 1024 SYN probes "
        "sent to 254 hosts in 30 seconds. Common ports targeted (SSH, HTTP, SMB, RDP). "
        "Traffic was blocked by firewall.",
        recommended_action="Monitor source IP. Add to watchlist. No immediate action required "
        "as traffic was blocked, but may indicate pre-attack reconnaissance.",
    ),
}

# Simulated correlated events
SIMULATED_CORRELATIONS = {
    "192.168.1.100": [
        {
            "_time": "2026-06-15T10:18:30Z",
            "event_type": "firewall_deny",
            "src_ip": "192.168.1.100",
            "dst_port": 3389,
            "description": "RDP connection attempt blocked",
        },
        {
            "_time": "2026-06-15T10:19:45Z",
            "event_type": "dns_query",
            "src_ip": "192.168.1.100",
            "query": "prod-server-01.internal.corp",
            "description": "DNS lookup for target host",
        },
        {
            "_time": "2026-06-15T10:20:00Z",
            "event_type": "port_scan",
            "src_ip": "192.168.1.100",
            "ports": "22,80,443,445,3389",
            "description": "SYN scan detected",
        },
        {
            "_time": "2026-06-15T10:30:00Z",
            "event_type": "brute_force",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "description": "150 failed SSH attempts",
        },
        {
            "_time": "2026-06-15T10:31:45Z",
            "event_type": "auth_success",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "user": "admin",
            "description": "SSH login successful after brute force",
        },
        {
            "_time": "2026-06-15T10:32:15Z",
            "event_type": "smb_access",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.12",
            "description": "SMB share access to file server",
        },
    ],
    "10.0.1.45": [
        {
            "_time": "2026-06-15T10:25:00Z",
            "event_type": "dns_query",
            "src_ip": "10.0.1.45",
            "query": "evil-payload.example.com",
            "description": "DNS resolution for malicious domain",
        },
        {
            "_time": "2026-06-15T10:27:30Z",
            "event_type": "http_request",
            "src_ip": "10.0.1.45",
            "dst_ip": "203.0.113.99",
            "url": "/update.exe",
            "description": "HTTP GET for executable payload",
        },
        {
            "_time": "2026-06-15T10:28:10Z",
            "event_type": "process_create",
            "host": "workstation-45",
            "process": "update.exe",
            "parent": "chrome.exe",
            "description": "Suspicious process spawned from browser",
        },
    ],
    "10.0.0.5": [
        {
            "_time": "2026-06-15T10:31:45Z",
            "event_type": "auth_success",
            "src_ip": "192.168.1.100",
            "user": "admin",
            "description": "SSH login from attacker IP",
        },
        {
            "_time": "2026-06-15T10:33:00Z",
            "event_type": "command_exec",
            "host": "prod-server-01",
            "command": "whoami && uname -a",
            "description": "System reconnaissance commands",
        },
        {
            "_time": "2026-06-15T10:34:30Z",
            "event_type": "command_exec",
            "host": "prod-server-01",
            "command": "cat /etc/shadow",
            "description": "Attempt to read credential file",
        },
        {
            "_time": "2026-06-15T10:35:00Z",
            "event_type": "privilege_escalation",
            "host": "prod-server-01",
            "command": "sudo /bin/bash",
            "description": "Escalated to root",
        },
    ],
}

SIMULATED_IOCS = {
    "192.168.1.100": ["192.168.1.100 — Known scanner (AbuseIPDB confidence: 87%)"],
    "203.0.113.99": [
        "203.0.113.99 — C2 server (VirusTotal: 14/72 detections)",
        "evil-payload.example.com — Malware distribution domain (OTX pulse match)",
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4 — Trojan.GenericKD (VT: 52/72)",
    ],
}


def load_sample_alerts() -> List[dict]:
    """Load sample alerts from the examples directory."""
    sample_path = Path(__file__).parent.parent / "examples" / "sample_alerts.json"
    if not sample_path.exists():
        # Fallback to single alert
        single_path = Path(__file__).parent.parent / "examples" / "sample_alert.json"
        if single_path.exists():
            with open(single_path) as f:
                return [json.load(f)]
        return []

    with open(sample_path) as f:
        return json.load(f)


def simulate_triage(alert: dict) -> TriageResult:
    """Simulate Foundation-Sec triage evaluation."""
    event_type = alert.get("event_type", "unknown")
    if event_type in SIMULATED_TRIAGE:
        return SIMULATED_TRIAGE[event_type]

    # Generic fallback
    return TriageResult(
        severity=5,
        threshold=5,
        category="unknown",
        summary=f"Alert type '{event_type}' detected. Requires manual review.",
        recommended_action="Review alert manually and classify.",
    )


def simulate_investigation(alert: dict, triage: TriageResult) -> InvestigationResult:
    """Simulate investigation sub-agents."""
    src_ip = alert.get("src_ip", "")
    dst_ip = alert.get("dst_ip", "")

    # Get correlated events
    correlated = SIMULATED_CORRELATIONS.get(src_ip, [])
    if not correlated:
        correlated = SIMULATED_CORRELATIONS.get(dst_ip, [])

    # Get IOC matches
    iocs = SIMULATED_IOCS.get(src_ip, [])
    if not iocs:
        iocs = SIMULATED_IOCS.get(dst_ip, [])

    # Build timeline
    timeline = sorted(
        [alert] + correlated, key=lambda e: e.get("_time", e.get("timestamp", ""))
    )

    # Calculate risk
    base = triage.severity / 10.0
    correlation_factor = min(len(correlated) / 10.0, 0.3)
    ioc_factor = min(len(iocs) * 0.1, 0.3)
    risk_score = min(base + correlation_factor + ioc_factor, 1.0)

    # Recommendation
    if iocs:
        recommendation = "ESCALATE: IOC matches confirmed — immediate incident response required"
    elif triage.severity >= 8:
        recommendation = "ESCALATE: High severity with correlated activity — SOC analyst review required"
    elif triage.severity >= 5:
        recommendation = "INVESTIGATE: Moderate severity — additional context needed before escalation"
    else:
        recommendation = "MONITOR: Below threshold — continue passive monitoring"

    return InvestigationResult(
        correlated_events=correlated,
        ioc_matches=iocs,
        timeline=timeline,
        risk_score=risk_score,
        recommendation=recommendation,
    )


def format_human_readable(report: dict) -> str:
    """Format a report as a human-readable summary."""
    triage = report["triage"]
    investigation = report["investigation"]
    alert = report["alert"]

    severity_bar = "█" * triage["severity"] + "░" * (10 - triage["severity"])
    risk_pct = int(investigation["risk_score"] * 100)

    lines = [
        "",
        f"{'='*70}",
        f"  INCIDENT REPORT: {report['report_id']}",
        f"{'='*70}",
        f"",
        f"  Alert ID:     {alert['id']}",
        f"  Generated:    {report['generated_at']}",
        f"  Status:       {report['status'].upper()}",
        f"",
        f"  ┌─ TRIAGE ─────────────────────────────────────────────────────────┐",
        f"  │ Severity:    [{severity_bar}] {triage['severity']}/10",
        f"  │ Category:    {triage['category']}",
        f"  │ Summary:     {triage['summary'][:80]}",
        f"  └───────────────────────────────────────────────────────────────────┘",
        f"",
        f"  ┌─ INVESTIGATION ───────────────────────────────────────────────────┐",
        f"  │ Risk Score:       {risk_pct}%",
        f"  │ Correlated:       {investigation['correlated_events_count']} events",
        f"  │ IOC Matches:      {len(investigation['ioc_matches'])}",
        f"  │ Timeline Events:  {investigation['timeline_events']}",
        f"  │ Recommendation:   {investigation['recommendation']}",
        f"  └───────────────────────────────────────────────────────────────────┘",
    ]

    if investigation["ioc_matches"]:
        lines.append(f"")
        lines.append(f"  ┌─ IOC MATCHES ────────────────────────────────────────────────────┐")
        for ioc in investigation["ioc_matches"]:
            lines.append(f"  │  • {ioc}")
        lines.append(f"  └───────────────────────────────────────────────────────────────────┘")

    lines.append(f"")
    lines.append(f"{'='*70}")
    lines.append(f"")

    return "\n".join(lines)


async def run_demo():
    """Run the full pipeline in demo mode with simulated data."""
    logger.info("🧠 Starting Amygdala in DEMO MODE")
    logger.info("Using sample alerts — no live Splunk connection required")
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║            🧠 AMYGDALA — Autonomous SOC Analyst                    ║")
    print("║                      [ DEMO MODE ]                                 ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print()

    # Load sample alerts
    alerts = load_sample_alerts()
    logger.info(f"Loaded {len(alerts)} sample alerts")
    print(f"  📥 Ingested {len(alerts)} alerts from sample data")
    print()

    reporter = ReportBuilder()
    output = OutputHandler()
    reports = []

    for i, alert in enumerate(alerts, 1):
        print(f"  ──── Processing Alert {i}/{len(alerts)}: {alert['id']} ────")
        print(f"  Type: {alert.get('event_type', 'unknown')} | Source: {alert.get('src_ip', 'N/A')}")

        # Simulate triage
        triage_result = simulate_triage(alert)
        severity_indicator = "🔴" if triage_result.severity >= 8 else "🟡" if triage_result.severity >= 5 else "🟢"
        print(f"  {severity_indicator} Triage: severity={triage_result.severity}/10, category={triage_result.category}")

        if triage_result.severity >= triage_result.threshold:
            # Simulate investigation
            investigation = simulate_investigation(alert, triage_result)
            print(f"  🔍 Investigation: {len(investigation.correlated_events)} correlated events, "
                  f"{len(investigation.ioc_matches)} IOCs, risk={investigation.risk_score:.0%}")

            # Build report
            report = reporter.build(alert, triage_result, investigation)
            reports.append(report)

            # Output
            if os.getenv("SLACK_WEBHOOK_URL"):
                await output.send(report)
                print(f"  📤 Report sent to Slack")
            else:
                print(f"  📋 Report generated (no Slack webhook configured)")
        else:
            print(f"  ⏭️  Below threshold ({triage_result.severity} < {triage_result.threshold}), skipping")

        print()

    # Print summary
    print(f"{'─'*70}")
    print(f"  📊 PIPELINE SUMMARY")
    print(f"{'─'*70}")
    print(f"  Total alerts processed:  {len(alerts)}")
    print(f"  Reports generated:       {len(reports)}")
    print(f"  Escalations:             {sum(1 for r in reports if 'ESCALATE' in r['investigation']['recommendation'])}")
    print(f"  Below threshold:         {len(alerts) - len(reports)}")
    print()

    # Print human-readable reports
    if reports:
        print(f"{'─'*70}")
        print(f"  📄 DETAILED REPORTS")
        print(f"{'─'*70}")
        for report in reports:
            print(format_human_readable(report))

    # Also dump JSON reports
    output_dir = Path(__file__).parent.parent / "output"
    output_dir.mkdir(exist_ok=True)
    output_file = output_dir / f"demo_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(reports, f, indent=2, default=str)
    print(f"  💾 JSON reports saved to: {output_file}")
    print()

    return reports
