"""Data models for the CSPM scanner.

Defines the core data structures used across all scanner modules:
Finding, ScanResult, and Severity enum.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(Enum):
    """Severity levels for security findings, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    def __str__(self) -> str:
        """Return the string value for display."""
        return self.value


@dataclass(frozen=True)
class Finding:
    """Represents a single security finding discovered by a scanner.

    Attributes:
        resource_id: The AWS ARN or unique identifier of the affected resource.
        resource_type: The AWS resource type (e.g. 'S3::Bucket', 'EC2::SecurityGroup').
        resource_name: A human-friendly name for the resource.
        region: The AWS region where the resource resides.
        severity: The severity level of the finding.
        issue: A short, one-line description of the security issue.
        details: Arbitrary metadata providing additional context.
        detected_at: ISO-8601 timestamp string of when the finding was detected.
    """

    resource_id: str
    resource_type: str
    resource_name: str
    region: str
    severity: Severity
    issue: str
    details: dict[str, Any] = field(default_factory=dict)
    detected_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a plain dictionary for JSON storage."""
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "region": self.region,
            "severity": self.severity.value,
            "issue": self.issue,
            "details": self.details,
            "detected_at": self.detected_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize a finding from a plain dictionary.

        Args:
            data: Dictionary with finding fields. ``severity`` may be a string
                  or a ``Severity`` enum member.

        Returns:
            A new ``Finding`` instance.
        """
        severity = data["severity"]
        if isinstance(severity, str):
            severity = Severity(severity)
        return cls(
            resource_id=data["resource_id"],
            resource_type=data["resource_type"],
            resource_name=data["resource_name"],
            region=data["region"],
            severity=severity,
            issue=data["issue"],
            details=data.get("details", {}),
            detected_at=data.get(
                "detected_at", datetime.now(timezone.utc).isoformat()
            ),
        )


@dataclass
class ScanResult:
    """Aggregated result of a full CSPM scan run.

    Attributes:
        findings: All security findings discovered during the scan.
        scan_id: A unique UUID identifying this scan run.
        scan_timestamp: ISO-8601 timestamp of when the scan started.
        total_resources_scanned: Count of individual resources examined.
        regions_scanned: List of AWS regions that were scanned.
    """

    findings: list[Finding] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_resources_scanned: int = 0
    regions_scanned: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full scan result to a plain dictionary."""
        return {
            "scan_id": self.scan_id,
            "scan_timestamp": self.scan_timestamp,
            "total_resources_scanned": self.total_resources_scanned,
            "regions_scanned": self.regions_scanned,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
