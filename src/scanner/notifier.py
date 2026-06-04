"""Notification backends for CSPM scanner findings.

Provides three backends:

- ``ConsoleNotifier`` — pretty terminal output with ANSI colours.
- ``SlackNotifier``   — posts Block Kit messages via Slack Incoming Webhook.
- ``SNSNotifier``     — publishes JSON payloads to an AWS SNS topic.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Any

from src.scanner.models import Finding, Severity

logger = logging.getLogger(__name__)


# ── ANSI colour helpers ─────────────────────────────────────────────────────

class _Colours:
    """ANSI escape-code constants for terminal colouring."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    MAGENTA = "\033[95m"

    BG_RED = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_MAGENTA = "\033[45m"
    BG_BLUE = "\033[44m"


_SEVERITY_STYLE: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: (
        f"{_Colours.BOLD}{_Colours.BG_RED}{_Colours.WHITE}",
        "🔴",
    ),
    Severity.HIGH: (
        f"{_Colours.BOLD}{_Colours.RED}",
        "🟠",
    ),
    Severity.MEDIUM: (
        f"{_Colours.BOLD}{_Colours.YELLOW}",
        "🟡",
    ),
    Severity.LOW: (
        f"{_Colours.DIM}{_Colours.CYAN}",
        "🔵",
    ),
}

_SEVERITY_EMOJI: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}


# ── Abstract base ───────────────────────────────────────────────────────────

class BaseNotifier(ABC):
    """Interface that all notifier backends must implement."""

    @abstractmethod
    def notify(self, findings: list[Finding]) -> None:
        """Send a batch of findings to the notification channel.

        Args:
            findings: List of new (not previously reported) findings.
        """


# ── Console notifier ────────────────────────────────────────────────────────

class ConsoleNotifier(BaseNotifier):
    """Pretty-prints findings to the terminal with ANSI colours and emoji."""

    def notify(self, findings: list[Finding]) -> None:
        """Render each finding as a formatted block to stdout.

        Args:
            findings: Findings to display.
        """
        if not findings:
            print(
                f"\n{_Colours.GREEN}{_Colours.BOLD}"
                f"  ✅  No new findings to report.{_Colours.RESET}\n"
            )
            return

        print(
            f"\n{_Colours.BOLD}{_Colours.MAGENTA}"
            f"{'═' * 72}\n"
            f"  📋  SECURITY FINDINGS  ({len(findings)} issue"
            f"{'s' if len(findings) != 1 else ''})\n"
            f"{'═' * 72}{_Colours.RESET}\n"
        )

        for idx, finding in enumerate(findings, start=1):
            style, emoji = _SEVERITY_STYLE.get(
                finding.severity,
                (f"{_Colours.WHITE}", "⚪"),
            )
            sev_label = f"{style} {finding.severity.value} {_Colours.RESET}"

            print(
                f"  {_Colours.DIM}──── Finding {idx}/{len(findings)} "
                f"{'─' * 48}{_Colours.RESET}"
            )
            print(f"  {emoji}  Severity   : {sev_label}")
            print(
                f"  📌  Resource   : {_Colours.BOLD}"
                f"{finding.resource_name}{_Colours.RESET}"
            )
            print(f"  🏷️   Type       : {finding.resource_type}")
            print(f"  🌍  Region     : {finding.region}")
            print(
                f"  ⚠️   Issue      : {_Colours.BOLD}"
                f"{finding.issue}{_Colours.RESET}"
            )
            print(f"  🆔  Resource ID: {_Colours.DIM}{finding.resource_id}{_Colours.RESET}")
            print(f"  🕐  Detected   : {finding.detected_at}")

            if finding.details:
                print(f"  📝  Details    :")
                for key, value in finding.details.items():
                    print(
                        f"      {_Colours.CYAN}{key}{_Colours.RESET}: {value}"
                    )
            print()

        print(
            f"{_Colours.BOLD}{_Colours.MAGENTA}"
            f"{'═' * 72}{_Colours.RESET}\n"
        )


# ── Slack notifier ──────────────────────────────────────────────────────────

class SlackNotifier(BaseNotifier):
    """Posts findings to a Slack channel via Incoming Webhook (Block Kit).

    Uses Python's built-in ``urllib`` — no extra dependencies required.
    """

    def __init__(
        self,
        webhook_url: str,
        channel: str = "#aws-security-alerts",
    ) -> None:
        """Initialise the Slack notifier.

        Args:
            webhook_url: Slack Incoming Webhook URL.
            channel: Target Slack channel name (for display/logging only).
        """
        self.webhook_url = webhook_url
        self.channel = channel

    def _build_blocks(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Build a Slack Block Kit payload for the given findings.

        Args:
            findings: Findings to format.

        Returns:
            A list of Block Kit block dicts.
        """
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)

        # Header
        header_text = (
            f"🚨 CSPM ALERT — {len(findings)} new finding(s) detected"
        )
        if crit_count:
            header_text += f" | {crit_count} CRITICAL"
        if high_count:
            header_text += f" | {high_count} HIGH"

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": header_text,
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ]

        # Individual findings (limit to 10 to stay within Slack block limits)
        display_findings = findings[:10]
        for finding in display_findings:
            emoji = _SEVERITY_EMOJI.get(finding.severity, "⚪")
            blocks.append(
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:*\n{emoji} {finding.severity.value}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Resource Type:*\n{finding.resource_type}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Resource Name:*\n`{finding.resource_name}`",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Region:*\n`{finding.region}`",
                        },
                    ],
                }
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"⚠️ *Issue:* {finding.issue}\n"
                            f"🆔 *ID:* `{finding.resource_id}`"
                        ),
                    },
                }
            )
            blocks.append({"type": "divider"})

        # Overflow notice
        if len(findings) > 10:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"_… and {len(findings) - 10} more finding(s). "
                            f"Check the full scan logs for details._"
                        ),
                    },
                }
            )

        # Footer with action hint
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            "🛡️ *CSPM Scanner* | "
                            "Action Required: Investigate or execute SSM remediation document."
                        ),
                    },
                ],
            }
        )

        return blocks

    def notify(self, findings: list[Finding]) -> None:
        """Post findings to Slack via the Incoming Webhook.

        Args:
            findings: Findings to send to Slack.
        """
        if not findings:
            logger.debug("SlackNotifier: no findings to send.")
            return

        blocks = self._build_blocks(findings)
        payload = json.dumps({"blocks": blocks}).encode("utf-8")

        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                logger.info(
                    "SlackNotifier: posted %d finding(s) to %s (HTTP %d)",
                    len(findings),
                    self.channel,
                    status,
                )
                print(
                    f"  💬  Slack alert sent to {self.channel} "
                    f"({len(findings)} finding(s))"
                )
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            logger.error(
                "SlackNotifier: HTTP %d error — %s", exc.code, body
            )
            print(f"  ❌  Slack alert FAILED (HTTP {exc.code}): {body}")
        except urllib.error.URLError as exc:
            logger.error("SlackNotifier: URL error — %s", exc.reason)
            print(f"  ❌  Slack alert FAILED: {exc.reason}")
        except Exception as exc:
            logger.error("SlackNotifier: unexpected error — %s", exc)
            print(f"  ❌  Slack alert FAILED: {exc}")


# ── SNS notifier ────────────────────────────────────────────────────────────

class SNSNotifier(BaseNotifier):
    """Publishes findings to an AWS SNS topic.

    Other services (email, PagerDuty, additional Lambda functions) can
    subscribe to the topic independently.
    """

    def __init__(self, sns_client: Any, topic_arn: str) -> None:
        """Initialise the SNS notifier.

        Args:
            sns_client: A ``boto3.client('sns')`` instance.
            topic_arn: The ARN of the target SNS topic.
        """
        self._client = sns_client
        self.topic_arn = topic_arn

    def _build_message(self, findings: list[Finding]) -> dict[str, Any]:
        """Build a structured SNS message payload.

        Args:
            findings: Findings to include.

        Returns:
            A dict suitable for ``json.dumps`` and SNS publish.
        """
        return {
            "source": "cspm-scanner",
            "detail_type": "CSPM Scan Findings",
            "findings_count": len(findings),
            "critical_count": sum(
                1 for f in findings if f.severity == Severity.CRITICAL
            ),
            "high_count": sum(
                1 for f in findings if f.severity == Severity.HIGH
            ),
            "findings": [f.to_dict() for f in findings],
        }

    def notify(self, findings: list[Finding]) -> None:
        """Publish findings to the configured SNS topic.

        Args:
            findings: Findings to publish.
        """
        if not findings:
            logger.debug("SNSNotifier: no findings to publish.")
            return

        message = self._build_message(findings)
        subject = (
            f"CSPM Alert: {len(findings)} new finding(s) detected"
        )
        # SNS subject max 100 chars
        subject = subject[:100]

        try:
            resp = self._client.publish(
                TopicArn=self.topic_arn,
                Subject=subject,
                Message=json.dumps(message, indent=2, default=str),
            )
            msg_id = resp.get("MessageId", "unknown")
            logger.info(
                "SNSNotifier: published %d finding(s) to %s (MessageId: %s)",
                len(findings),
                self.topic_arn,
                msg_id,
            )
            print(
                f"  📣  SNS alert published to topic "
                f"({len(findings)} finding(s), MessageId: {msg_id})"
            )
        except Exception as exc:
            logger.error(
                "SNSNotifier: failed to publish to %s — %s",
                self.topic_arn,
                exc,
            )
            print(f"  ❌  SNS publish FAILED: {exc}")

