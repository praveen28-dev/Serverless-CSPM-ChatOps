"""CSPM Scanner — entry point for local execution.

Run with::

    python -m src.scanner.main [OPTIONS]

Examples::

    # Default — scan ap-south-1 and us-east-1, console output
    python -m src.scanner.main

    # Use a named AWS profile and emit JSON
    python -m src.scanner.main --profile dev --output json

    # Custom regions
    python -m src.scanner.main --regions ap-south-1,eu-west-1
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import boto3

from src.scanner.models import Finding, ScanResult, Severity
from src.scanner.notifier import ConsoleNotifier, SlackNotifier, SNSNotifier
from src.scanner.scanner import RDSScanner, S3Scanner, SecurityGroupScanner
from src.scanner.state_manager import StateManager

logger = logging.getLogger("cspm")

# ── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
   ____  ____  ____  __  __
  / ___\/ ___||  _ \|  \/  |
 | |    \___ \| |_) | |\/| |
 | |___  ___) |  __/| |  | |
  \____||____/|_|   |_|  |_|

  Cloud Security Posture Management Scanner
  -------------------------------------------
"""


def _print_banner() -> None:
    """Print the startup banner."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    print(BANNER)


# ── CLI argument parsing ────────────────────────────────────────────────────

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Parsed namespace.
    """
    parser = argparse.ArgumentParser(
        prog="cspm-scanner",
        description="AWS Cloud Security Posture Management scanner",
    )
    parser.add_argument(
        "--regions",
        type=str,
        default="ap-south-1,us-east-1",
        help="Comma-separated list of AWS regions to scan (default: ap-south-1,us-east-1)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="AWS CLI profile name (default: default credentials chain)",
    )
    parser.add_argument(
        "--output",
        type=str,
        choices=["console", "json"],
        default="console",
        help="Output format: 'console' for pretty terminal, 'json' for machine-readable (default: console)",
    )
    parser.add_argument(
        "--state-file",
        type=str,
        default="findings_state.json",
        help="Path to the local JSON state file for finding deduplication (default: findings_state.json)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable DEBUG-level logging",
    )
    parser.add_argument(
        "--dynamodb",
        action="store_true",
        default=False,
        help="Use DynamoDB for state tracking instead of local JSON file (Phase 2+)",
    )
    parser.add_argument(
        "--dynamodb-table",
        type=str,
        default="cspm-findings",
        help="DynamoDB table name for state tracking (default: cspm-findings)",
    )
    parser.add_argument(
        "--dynamodb-region",
        type=str,
        default="ap-south-1",
        help="AWS region where the DynamoDB table is located (default: ap-south-1)",
    )
    parser.add_argument(
        "--slack-webhook",
        type=str,
        default=None,
        help="Slack Incoming Webhook URL to send alerts to",
    )
    parser.add_argument(
        "--sns-topic-arn",
        type=str,
        default=None,
        help="AWS SNS Topic ARN to publish findings to",
    )
    return parser.parse_args(argv)


# ── Logging setup ───────────────────────────────────────────────────────────

def _configure_logging(verbose: bool) -> None:
    """Set up structured logging for the scanner.

    Args:
        verbose: If ``True``, use DEBUG level; otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    fmt = (
        "%(asctime)s │ %(levelname)-8s │ %(name)-24s │ %(message)s"
    )
    logging.basicConfig(
        level=level,
        format=fmt,
        datefmt="%Y-%m-%dT%H:%M:%S",
        handlers=[logging.StreamHandler(sys.stderr)],
    )
    # Suppress noisy boto/urllib3 loggers unless truly verbose
    if not verbose:
        logging.getLogger("boto3").setLevel(logging.WARNING)
        logging.getLogger("botocore").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("s3transfer").setLevel(logging.WARNING)


# ── Session factory ─────────────────────────────────────────────────────────

def _create_session(profile: str | None) -> boto3.Session:
    """Create a boto3 session, optionally using a named profile.

    Args:
        profile: AWS profile name, or ``None`` for the default chain.

    Returns:
        A configured ``boto3.Session``.
    """
    kwargs: dict[str, str] = {}
    if profile:
        kwargs["profile_name"] = profile
    session = boto3.Session(**kwargs)
    logger.info("AWS session created (profile=%s)", profile or "default")
    return session


# ── Scan orchestration ──────────────────────────────────────────────────────

def _run_scanners(
    session: boto3.Session, regions: list[str]
) -> ScanResult:
    """Execute all scanners and aggregate results into a ``ScanResult``.

    Args:
        session: Authenticated boto3 session.
        regions: Regions to scan for EC2/RDS resources.

    Returns:
        Aggregated ``ScanResult``.
    """
    result = ScanResult(regions_scanned=regions)
    total_resources = 0

    # ── S3 (global) ─────────────────────────────────────────────────────
    print("\n  🪣  Scanning S3 buckets …")
    s3_scanner = S3Scanner(session)
    s3_findings = s3_scanner.scan()
    result.findings.extend(s3_findings)
    s3_count = s3_scanner.resources_scanned
    total_resources += s3_count
    print(f"     └─ {s3_count} bucket(s) checked, {len(s3_findings)} finding(s)\n")

    # ── Security Groups (per-region) ────────────────────────────────────
    print("  🔒  Scanning Security Groups …")
    sg_scanner = SecurityGroupScanner(session, regions)
    sg_findings = sg_scanner.scan()
    result.findings.extend(sg_findings)
    sg_count = sg_scanner.resources_scanned
    total_resources += sg_count
    print(f"     └─ {sg_count} group(s) checked, {len(sg_findings)} finding(s)\n")

    # ── RDS (per-region) ────────────────────────────────────────────────
    print("  🗄️   Scanning RDS instances …")
    rds_scanner = RDSScanner(session, regions)
    rds_findings = rds_scanner.scan()
    result.findings.extend(rds_findings)
    rds_count = rds_scanner.resources_scanned
    total_resources += rds_count
    print(f"     └─ {rds_count} instance(s) checked, {len(rds_findings)} finding(s)\n")

    result.total_resources_scanned = total_resources
    return result


def _deduplicate(
    findings: list[Finding], state: StateManager
) -> tuple[list[Finding], list[Finding], list[dict]]:
    """Split findings into *new* and *known* using the state manager.

    Also detects previously-open findings that are no longer present
    (i.e. resolved).

    Args:
        findings: All findings from the current scan.
        state: The state manager to query/update.

    Returns:
        A 3-tuple of ``(new_findings, known_findings, resolved_entries)``.
    """
    new_findings: list[Finding] = []
    known_findings: list[Finding] = []

    current_resource_ids = {f.resource_id for f in findings}

    for finding in findings:
        if state.is_known_finding(finding.resource_id):
            known_findings.append(finding)
        else:
            new_findings.append(finding)
            state.record_finding(finding)

    # Detect resolved findings (were open, no longer flagged)
    open_entries = state.get_all_open_findings()
    resolved_entries: list[dict] = []
    for entry in open_entries:
        rid = entry.get("resource_id", "")
        if rid and rid not in current_resource_ids:
            state.resolve_finding(rid)
            resolved_entries.append(entry)

    return new_findings, known_findings, resolved_entries


def _print_summary(
    result: ScanResult,
    new_findings: list[Finding],
    known_findings: list[Finding],
    resolved_count: int,
    elapsed: float,
) -> None:
    """Print a human-readable summary to the terminal.

    Args:
        result: The full scan result.
        new_findings: Findings not previously seen.
        known_findings: Findings already tracked.
        resolved_count: Count of findings that were resolved.
        elapsed: Wall-clock seconds the scan took.
    """
    # Colour shortcuts
    B = "\033[1m"
    R = "\033[0m"
    G = "\033[92m"
    Y = "\033[93m"
    RED = "\033[91m"
    C = "\033[96m"

    crit = sum(1 for f in new_findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in new_findings if f.severity == Severity.HIGH)

    print(f"\n{B}{'═' * 72}{R}")
    print(f"  {B}📊  SCAN SUMMARY{R}")
    print(f"{'═' * 72}")
    print(f"  🌍  Regions scanned        : {C}{', '.join(result.regions_scanned)}{R}")
    print(f"  📦  Resources scanned      : {B}{result.total_resources_scanned}{R}")
    print(f"  ⏱️   Duration               : {elapsed:.1f}s")
    print(f"  🆔  Scan ID                : {result.scan_id}")
    print(f"{'─' * 72}")
    print(f"  🆕  New findings           : {RED if new_findings else G}{B}{len(new_findings)}{R}")
    print(f"  📌  Known (existing)       : {Y}{len(known_findings)}{R}")
    print(f"  ✅  Resolved this scan     : {G}{resolved_count}{R}")
    print(f"  📋  Total findings         : {B}{len(result.findings)}{R}")

    if crit or high:
        print(f"\n  {RED}{B}⚠️   {crit} CRITICAL, {high} HIGH severity finding(s) detected!{R}")
    else:
        print(f"\n  {G}{B}✅  No critical or high-severity findings.{R}")

    print(f"{'═' * 72}\n")


# ── Main entry point ────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    """Run the full CSPM scan pipeline.

    1. Parse CLI args and configure logging.
    2. Create boto3 session.
    3. Execute all scanners.
    4. Deduplicate findings via state manager.
    5. Notify on new findings.
    6. Print summary and return exit code.

    Args:
        argv: CLI argument list (for testing); defaults to ``sys.argv[1:]``.

    Returns:
        ``1`` if new CRITICAL/HIGH findings are present, ``0`` otherwise.
    """
    args = parse_args(argv)
    _configure_logging(args.verbose)
    _print_banner()

    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    logger.info("Target regions: %s", regions)

    start = time.monotonic()

    # ── Session ─────────────────────────────────────────────────────────
    session = _create_session(args.profile)

    # ── Scan ────────────────────────────────────────────────────────────
    result = _run_scanners(session, regions)

    # ── State management / deduplication ────────────────────────────────
    dynamodb_resource = None
    if args.dynamodb:
        print("  📦  DynamoDB state tracking: ENABLED")
        print(f"      Table: {args.dynamodb_table} ({args.dynamodb_region})")
        dynamodb_resource = session.resource(
            "dynamodb", region_name=args.dynamodb_region
        )
    else:
        print(f"  📄  Local state file: {args.state_file}")

    state = StateManager(
        table_name=args.dynamodb_table,
        dynamodb_resource=dynamodb_resource,
        state_file=args.state_file,
    )
    new_findings, known_findings, resolved = _deduplicate(
        result.findings, state
    )

    # ── Notification ────────────────────────────────────────────────────
    if args.output == "json":
        output = {
            "scan": result.to_dict(),
            "new_findings": [f.to_dict() for f in new_findings],
            "known_findings": [f.to_dict() for f in known_findings],
            "resolved_count": len(resolved),
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        # We always output to the console
        notifiers = [ConsoleNotifier()]

        if args.slack_webhook:
            notifiers.append(SlackNotifier(webhook_url=args.slack_webhook))

        if args.sns_topic_arn:
            sns_client = session.client("sns", region_name=args.dynamodb_region)
            notifiers.append(SNSNotifier(sns_client=sns_client, topic_arn=args.sns_topic_arn))

        for notifier in notifiers:
            notifier.notify(new_findings)

    elapsed = time.monotonic() - start

    # ── Summary ─────────────────────────────────────────────────────────
    _print_summary(result, new_findings, known_findings, len(resolved), elapsed)

    # ── Exit code ───────────────────────────────────────────────────────
    has_critical_or_high = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH)
        for f in new_findings
    )
    if has_critical_or_high:
        logger.warning(
            "Exiting with code 1 — new critical/high findings detected"
        )
        return 1

    logger.info("Exiting with code 0 — no new critical/high findings")
    return 0


# ── AWS Lambda entry point ──────────────────────────────────────────────────

def lambda_handler(event: dict, context: object) -> dict:
    """AWS Lambda handler for Phase 4.

    Pulls configuration from environment variables rather than CLI arguments.
    Expected environment variables:
      - SCAN_REGIONS (e.g. "ap-south-1,us-east-1")
      - DYNAMODB_TABLE
      - DYNAMODB_REGION
      - SLACK_WEBHOOK_URL (optional)
      - SNS_TOPIC_ARN (optional)
    """
    _configure_logging(verbose=os.environ.get("DEBUG", "").lower() == "true")
    logger.info("Starting CSPM scan from Lambda")

    # Parse config
    regions_str = os.environ.get("SCAN_REGIONS", "ap-south-1,us-east-1")
    regions = [r.strip() for r in regions_str.split(",") if r.strip()]

    dynamodb_table = os.environ.get("DYNAMODB_TABLE", "cspm-findings")
    dynamodb_region = os.environ.get("DYNAMODB_REGION", "ap-south-1")
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")
    sns_topic_arn = os.environ.get("SNS_TOPIC_ARN")

    start = time.monotonic()
    session = _create_session(profile=None)  # Lambda uses attached IAM role

    # Execute Scans
    result = _run_scanners(session, regions)

    # State tracking
    dynamodb_resource = session.resource("dynamodb", region_name=dynamodb_region)
    state = StateManager(
        table_name=dynamodb_table,
        dynamodb_resource=dynamodb_resource,
        state_file="/tmp/findings_state.json", # Lambda has write access to /tmp
    )
    new_findings, known_findings, resolved = _deduplicate(result.findings, state)

    # Notifications
    notifiers = []
    if slack_webhook:
        notifiers.append(SlackNotifier(webhook_url=slack_webhook))
    if sns_topic_arn:
        sns_client = session.client("sns", region_name=dynamodb_region)
        notifiers.append(SNSNotifier(sns_client=sns_client, topic_arn=sns_topic_arn))
    
    for notifier in notifiers:
        notifier.notify(new_findings)

    elapsed = time.monotonic() - start

    has_critical_or_high = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH)
        for f in new_findings
    )

    return {
        "statusCode": 200,
        "body": {
            "message": "Scan completed",
            "scan_id": result.scan_id,
            "resources_scanned": result.total_resources_scanned,
            "new_findings": len(new_findings),
            "known_findings": len(known_findings),
            "resolved": len(resolved),
            "has_critical_or_high": has_critical_or_high,
            "duration_seconds": round(elapsed, 2)
        }
    }


if __name__ == "__main__":
    sys.exit(main())
