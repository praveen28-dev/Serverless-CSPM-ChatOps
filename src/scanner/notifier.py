"""Notification backends for CSPM scanner findings.

Phase 1 provides a fully functional ``ConsoleNotifier`` with coloured terminal
output.  ``SlackNotifier`` and ``SNSNotifier`` are placeholders that will be
wired up in later phases.
"""

from __future__ import annotations

import json
import logging
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


# ── Slack notifier (Phase 3 placeholder) ────────────────────────────────────

class SlackNotifier(BaseNotifier):
    """Posts findings to a Slack channel using Block Kit formatting.

    .. note::
        Slack integration will be enabled in **Phase 3**.  For now this
        notifier only logs a message and prepares the Block Kit payload.
    """

    def __init__(self, webhook_url: str | None = None, channel: str = "#security-alerts") -> None:
        """Initialise the Slack notifier.

        Args:
            webhook_url: Slack Incoming Webhook URL (not used yet).
            channel: Target Slack channel name.
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
        severity_emoji = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
        }

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🛡️ CSPM Scanner — {len(findings)} finding(s)",
                    "emoji": True,
                },
            },
            {"type": "divider"},
        ]

        for finding in findings:
            emoji = severity_emoji.get(finding.severity, "⚪")
            blocks.append(
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Severity:* {emoji} {finding.severity.value}",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Region:* `{finding.region}`",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Resource:* `{finding.resource_name}`",
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Type:* {finding.resource_type}",
                        },
                    ],
                }
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"⚠️ *{finding.issue}*",
                    },
                }
            )
            blocks.append({"type": "divider"})

        return blocks

    def notify(self, findings: list[Finding]) -> None:
        """Log the prepared payload.  Actual delivery deferred to Phase 3.

        Args:
            findings: Findings to (eventually) send to Slack.
        """
        if not findings:
            return
        blocks = self._build_blocks(findings)
        logger.info(
            "Slack integration will be enabled in Phase 3. "
            "Prepared %d Block Kit blocks for channel %s.",
            len(blocks),
            self.channel,
        )
        logger.debug("Slack payload: %s", json.dumps(blocks, indent=2))


# ── SNS notifier (Phase 3 placeholder) ──────────────────────────────────────

class SNSNotifier(BaseNotifier):
    """Publishes findings to an AWS SNS topic.

    .. note::
        SNS integration will be enabled in **Phase 3**.
    """

    def __init__(self, topic_arn: str | None = None) -> None:
        """Initialise the SNS notifier.

        Args:
            topic_arn: The ARN of the target SNS topic (not used yet).
        """
        self.topic_arn = topic_arn

    def _build_message(self, findings: list[Finding]) -> dict[str, Any]:
        """Build an SNS message payload.

        Args:
            findings: Findings to include.

        Returns:
            A dict suitable for ``json.dumps`` and SNS publish.
        """
        return {
            "source": "cspm-scanner",
            "findings_count": len(findings),
            "findings": [f.to_dict() for f in findings],
        }

    def notify(self, findings: list[Finding]) -> None:
        """Log the prepared payload.  Actual delivery deferred to Phase 3.

        Args:
            findings: Findings to (eventually) publish to SNS.
        """
        if not findings:
            return
        message = self._build_message(findings)
        logger.info(
            "SNS integration will be enabled in Phase 3. "
            "Prepared message with %d finding(s) for topic %s.",
            len(findings),
            self.topic_arn or "<not configured>",
        )
        logger.debug("SNS payload: %s", json.dumps(message, indent=2))
