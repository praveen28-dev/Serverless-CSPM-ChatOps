"""State management for CSPM findings — DynamoDB with local JSON fallback.

In Phase 1 (local testing) the ``StateManager`` uses a JSON file on disk.
When DynamoDB is available (Phase 2+), it switches to a DynamoDB table
automatically — a failed DynamoDB operation on init triggers the fallback.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError, BotoCoreError

from src.scanner.models import Finding

logger = logging.getLogger(__name__)


class StateManager:
    """Tracks known findings to enable deduplication and resolution tracking.

    Tries DynamoDB first; falls back to a local JSON file if the table is
    unreachable.
    """

    def __init__(
        self,
        table_name: str,
        dynamodb_resource: Any | None = None,
        state_file: str = "findings_state.json",
    ) -> None:
        """Initialise the state manager.

        Args:
            table_name: Name of the DynamoDB table (e.g. ``cspm-findings``).
            dynamodb_resource: A ``boto3.resource('dynamodb')`` instance.
                               Pass ``None`` to skip DynamoDB entirely.
            state_file: Path to the local JSON fallback file.
        """
        self._table_name = table_name
        self._state_file = Path(state_file)
        self._use_dynamodb = False
        self._table: Any | None = None

        if dynamodb_resource is not None:
            try:
                table = dynamodb_resource.Table(table_name)
                # Probe the table — if it doesn't exist, this will raise.
                table.table_status  # noqa: B018 — intentional attribute access
                self._table = table
                self._use_dynamodb = True
                logger.info(
                    "StateManager: using DynamoDB table '%s'", table_name
                )
            except (ClientError, BotoCoreError, Exception) as exc:
                logger.warning(
                    "StateManager: DynamoDB unavailable (%s) — falling back "
                    "to local file '%s'",
                    exc,
                    self._state_file,
                )

        if not self._use_dynamodb:
            logger.info(
                "StateManager: using local JSON state file '%s'",
                self._state_file,
            )
            self._ensure_state_file()

    # ── public API ──────────────────────────────────────────────────────────

    def is_known_finding(self, resource_id: str) -> bool:
        """Check whether a finding for *resource_id* is already tracked.

        Args:
            resource_id: The AWS ARN or unique resource identifier.

        Returns:
            ``True`` if the finding exists **and is open**, ``False`` otherwise.
        """
        if self._use_dynamodb:
            return self._dynamo_is_known(resource_id)
        return self._local_is_known(resource_id)

    def record_finding(self, finding: Finding) -> None:
        """Persist a new finding (or update an existing one).

        Args:
            finding: The finding to record.
        """
        if self._use_dynamodb:
            self._dynamo_record(finding)
        else:
            self._local_record(finding)

    def resolve_finding(self, resource_id: str) -> None:
        """Mark a finding as resolved.

        Args:
            resource_id: The resource whose finding should be resolved.
        """
        if self._use_dynamodb:
            self._dynamo_resolve(resource_id)
        else:
            self._local_resolve(resource_id)

    def get_all_open_findings(self) -> list[dict[str, Any]]:
        """Return all findings currently in the *open* state.

        Returns:
            A list of finding dictionaries.
        """
        if self._use_dynamodb:
            return self._dynamo_get_open()
        return self._local_get_open()

    # ── DynamoDB backend ────────────────────────────────────────────────────

    def _dynamo_is_known(self, resource_id: str) -> bool:
        """Check DynamoDB for an open finding."""
        try:
            resp = self._table.get_item(Key={"resource_id": resource_id})
            item = resp.get("Item")
            return item is not None and item.get("status") == "open"
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "StateManager: DynamoDB get_item failed for '%s': %s",
                resource_id,
                exc,
            )
            return False

    def _dynamo_record(self, finding: Finding) -> None:
        """Write a finding to DynamoDB."""
        try:
            self._table.put_item(
                Item={
                    "resource_id": finding.resource_id,
                    "resource_type": finding.resource_type,
                    "resource_name": finding.resource_name,
                    "region": finding.region,
                    "severity": finding.severity.value,
                    "issue": finding.issue,
                    "details": json.dumps(finding.details),
                    "detected_at": finding.detected_at,
                    "status": "open",
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            logger.debug(
                "StateManager: recorded finding for '%s' in DynamoDB",
                finding.resource_id,
            )
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "StateManager: DynamoDB put_item failed for '%s': %s",
                finding.resource_id,
                exc,
            )

    def _dynamo_resolve(self, resource_id: str) -> None:
        """Mark a finding as resolved in DynamoDB."""
        try:
            self._table.update_item(
                Key={"resource_id": resource_id},
                UpdateExpression=(
                    "SET #s = :resolved, resolved_at = :now"
                ),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":resolved": "resolved",
                    ":now": datetime.now(timezone.utc).isoformat(),
                },
            )
            logger.debug(
                "StateManager: resolved finding for '%s' in DynamoDB",
                resource_id,
            )
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "StateManager: DynamoDB update_item failed for '%s': %s",
                resource_id,
                exc,
            )

    def _dynamo_get_open(self) -> list[dict[str, Any]]:
        """Scan DynamoDB for all open findings."""
        try:
            items: list[dict[str, Any]] = []
            resp = self._table.scan(
                FilterExpression="#s = :open",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={":open": "open"},
            )
            items.extend(resp.get("Items", []))

            # Handle pagination for scan
            while "LastEvaluatedKey" in resp:
                resp = self._table.scan(
                    FilterExpression="#s = :open",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={":open": "open"},
                    ExclusiveStartKey=resp["LastEvaluatedKey"],
                )
                items.extend(resp.get("Items", []))

            return items
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "StateManager: DynamoDB scan failed: %s", exc
            )
            return []

    # ── Local JSON backend ──────────────────────────────────────────────────

    def _ensure_state_file(self) -> None:
        """Create the local state file if it does not exist."""
        if not self._state_file.exists():
            self._write_state({})
            logger.debug(
                "StateManager: created new state file '%s'", self._state_file
            )

    def _read_state(self) -> dict[str, Any]:
        """Read the full state dictionary from disk.

        Returns:
            The deserialized state dict.
        """
        try:
            text = self._state_file.read_text(encoding="utf-8")
            return json.loads(text) if text.strip() else {}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning(
                "StateManager: failed to read state file: %s", exc
            )
            return {}

    def _write_state(self, state: dict[str, Any]) -> None:
        """Atomically write the state dictionary to disk.

        Args:
            state: The full state dict to persist.
        """
        try:
            self._state_file.write_text(
                json.dumps(state, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError as exc:
            logger.warning(
                "StateManager: failed to write state file: %s", exc
            )

    def _local_is_known(self, resource_id: str) -> bool:
        """Check the local JSON file for an open finding."""
        state = self._read_state()
        entry = state.get(resource_id)
        return entry is not None and entry.get("status") == "open"

    def _local_record(self, finding: Finding) -> None:
        """Record a finding in the local JSON file."""
        state = self._read_state()
        state[finding.resource_id] = {
            **finding.to_dict(),
            "status": "open",
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._write_state(state)
        logger.debug(
            "StateManager: recorded finding for '%s' locally",
            finding.resource_id,
        )

    def _local_resolve(self, resource_id: str) -> None:
        """Mark a finding as resolved in the local JSON file."""
        state = self._read_state()
        if resource_id in state:
            state[resource_id]["status"] = "resolved"
            state[resource_id]["resolved_at"] = (
                datetime.now(timezone.utc).isoformat()
            )
            self._write_state(state)
            logger.debug(
                "StateManager: resolved finding for '%s' locally",
                resource_id,
            )

    def _local_get_open(self) -> list[dict[str, Any]]:
        """Return all open findings from the local JSON file."""
        state = self._read_state()
        return [
            entry
            for entry in state.values()
            if isinstance(entry, dict) and entry.get("status") == "open"
        ]
