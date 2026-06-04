"""CSPM security scanners for AWS resources.

Provides three scanner classes:
- ``S3Scanner``         — checks S3 bucket public access block configurations
- ``SecurityGroupScanner`` — flags overly permissive ingress rules (SSH/MySQL)
- ``RDSScanner``        — flags RDS instances without storage encryption
"""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from src.scanner.models import Finding, Severity

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
#  S3 Scanner
# ═══════════════════════════════════════════════════════════════════════════════

class S3Scanner:
    """Scans all S3 buckets for missing or misconfigured public access blocks.

    S3 is a global service, so this scanner runs once regardless of the
    region list.  A bucket is flagged when:
    - ``GetPublicAccessBlock`` returns ``NoSuchPublicAccessBlockConfiguration``
      (no block exists at all — most dangerous).
    - Any of the four public-access-block booleans is ``False``.
    """

    RESOURCE_TYPE = "S3::Bucket"

    def __init__(self, session: boto3.Session) -> None:
        """Initialise with a boto3 session.

        Args:
            session: An authenticated ``boto3.Session``.
        """
        self._s3 = session.client("s3")

    # ── public API ──────────────────────────────────────────────────────────

    def scan(self) -> list[Finding]:
        """List every bucket and check its public access block configuration.

        Returns:
            A list of ``Finding`` objects for misconfigured buckets.
        """
        findings: list[Finding] = []
        buckets = self._list_buckets()
        logger.info("S3Scanner: examining %d bucket(s)", len(buckets))

        for bucket in buckets:
            name: str = bucket["Name"]
            region = self._get_bucket_region(name)
            try:
                finding = self._check_bucket(name, region)
                if finding is not None:
                    findings.append(finding)
            except (ClientError, BotoCoreError) as exc:
                logger.warning(
                    "S3Scanner: failed to inspect bucket '%s': %s",
                    name,
                    exc,
                )
                continue

        logger.info(
            "S3Scanner: completed — %d finding(s) across %d bucket(s)",
            len(findings),
            len(buckets),
        )
        return findings

    @property
    def resources_scanned(self) -> int:
        """Return a count of buckets discovered (re-populated on each scan)."""
        return len(self._list_buckets())

    # ── internal helpers ────────────────────────────────────────────────────

    def _list_buckets(self) -> list[dict[str, Any]]:
        """Return all S3 buckets in the account.

        Uses the ``ListBuckets`` API (no paginator available for this call).
        """
        logger.debug("S3Scanner: calling ListBuckets")
        try:
            response = self._s3.list_buckets()
            return response.get("Buckets", [])
        except (ClientError, BotoCoreError) as exc:
            logger.warning("S3Scanner: ListBuckets failed: %s", exc)
            return []

    def _get_bucket_region(self, bucket_name: str) -> str:
        """Resolve the region a bucket lives in.

        Args:
            bucket_name: Name of the S3 bucket.

        Returns:
            The AWS region string, defaulting to ``'us-east-1'`` when the API
            returns ``None`` (which it does for us-east-1 buckets).
        """
        try:
            resp = self._s3.get_bucket_location(Bucket=bucket_name)
            location = resp.get("LocationConstraint")
            return location or "us-east-1"
        except (ClientError, BotoCoreError) as exc:
            logger.debug(
                "S3Scanner: could not determine region for '%s': %s",
                bucket_name,
                exc,
            )
            return "unknown"

    def _check_bucket(self, bucket_name: str, region: str) -> Finding | None:
        """Check one bucket's public access block configuration.

        Args:
            bucket_name: S3 bucket name.
            region: AWS region where the bucket resides.

        Returns:
            A ``Finding`` if the bucket is misconfigured, else ``None``.
        """
        try:
            logger.debug(
                "S3Scanner: GetPublicAccessBlock for '%s'", bucket_name
            )
            resp = self._s3.get_public_access_block(Bucket=bucket_name)
            config = resp.get("PublicAccessBlockConfiguration", {})

            disabled_settings: list[str] = [
                key
                for key in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
                if not config.get(key, False)
            ]

            if not disabled_settings:
                logger.debug(
                    "S3Scanner: bucket '%s' — all public access blocks enabled",
                    bucket_name,
                )
                return None

            return Finding(
                resource_id=f"arn:aws:s3:::{bucket_name}",
                resource_type=self.RESOURCE_TYPE,
                resource_name=bucket_name,
                region=region,
                severity=Severity.CRITICAL,
                issue="S3 bucket has public access block settings disabled",
                details={
                    "disabled_settings": disabled_settings,
                    "configuration": config,
                },
            )

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                logger.info(
                    "S3Scanner: bucket '%s' has NO public access block at all",
                    bucket_name,
                )
                return Finding(
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    resource_type=self.RESOURCE_TYPE,
                    resource_name=bucket_name,
                    region=region,
                    severity=Severity.CRITICAL,
                    issue=(
                        "S3 bucket has no Public Access Block configuration — "
                        "bucket contents may be publicly accessible"
                    ),
                    details={"public_access_block": "not_configured"},
                )
            raise


# ═══════════════════════════════════════════════════════════════════════════════
#  Security Group Scanner
# ═══════════════════════════════════════════════════════════════════════════════

class SecurityGroupScanner:
    """Scans EC2 security groups for dangerous ingress rules.

    Flags rules that allow inbound traffic on sensitive ports (SSH 22,
    MySQL 3306) from anywhere (``0.0.0.0/0`` or ``::/0``).  Properly handles
    port *ranges* — e.g. ``0-65535`` includes port 22.
    """

    RESOURCE_TYPE = "EC2::SecurityGroup"
    SENSITIVE_PORTS: dict[int, str] = {
        22: "SSH",
        3306: "MySQL",
    }

    def __init__(self, session: boto3.Session, regions: list[str]) -> None:
        """Initialise the security-group scanner.

        Args:
            session: An authenticated ``boto3.Session``.
            regions: AWS regions to scan.
        """
        self._session = session
        self._regions = regions
        self._total_scanned = 0

    # ── public API ──────────────────────────────────────────────────────────

    def scan(self) -> list[Finding]:
        """Scan security groups across all configured regions.

        Returns:
            A list of findings for overly permissive security groups.
        """
        all_findings: list[Finding] = []
        self._total_scanned = 0

        for region in self._regions:
            try:
                findings = self._scan_region(region)
                all_findings.extend(findings)
            except (ClientError, BotoCoreError) as exc:
                logger.warning(
                    "SecurityGroupScanner: failed to scan region '%s': %s",
                    region,
                    exc,
                )
                continue

        logger.info(
            "SecurityGroupScanner: completed — %d finding(s) across %d "
            "security group(s) in %d region(s)",
            len(all_findings),
            self._total_scanned,
            len(self._regions),
        )
        return all_findings

    @property
    def resources_scanned(self) -> int:
        """Return total security groups inspected across all regions."""
        return self._total_scanned

    # ── internal helpers ────────────────────────────────────────────────────

    def _scan_region(self, region: str) -> list[Finding]:
        """Scan all security groups in a single region.

        Args:
            region: AWS region to scan.

        Returns:
            Findings discovered in this region.
        """
        ec2 = self._session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        findings: list[Finding] = []

        logger.debug(
            "SecurityGroupScanner: paginating security groups in %s", region
        )

        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                self._total_scanned += 1
                sg_findings = self._check_security_group(sg, region)
                findings.extend(sg_findings)

        return findings

    def _check_security_group(
        self, sg: dict[str, Any], region: str
    ) -> list[Finding]:
        """Evaluate a single security group's ingress rules.

        Args:
            sg: The security group descriptor from the AWS API.
            region: Region the SG belongs to.

        Returns:
            Findings for any dangerous rules found.
        """
        findings: list[Finding] = []
        sg_id: str = sg["GroupId"]
        sg_name: str = sg.get("GroupName", sg_id)

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            ip_protocol: str = rule.get("IpProtocol", "")

            # Protocol "-1" means all traffic — all ports exposed
            if ip_protocol == "-1":
                from_port = 0
                to_port = 65535

            open_cidrs = self._extract_open_cidrs(rule)
            if not open_cidrs:
                continue

            exposed_ports = self._sensitive_ports_in_range(from_port, to_port)
            for port, service in exposed_ports.items():
                severity = (
                    Severity.CRITICAL if port == 22 else Severity.HIGH
                )
                finding = Finding(
                    resource_id=sg_id,
                    resource_type=self.RESOURCE_TYPE,
                    resource_name=sg_name,
                    region=region,
                    severity=severity,
                    issue=(
                        f"{service} (port {port}) is open to the internet "
                        f"({', '.join(open_cidrs)})"
                    ),
                    details={
                        "security_group_id": sg_id,
                        "security_group_name": sg_name,
                        "port": port,
                        "service": service,
                        "protocol": ip_protocol,
                        "open_cidrs": open_cidrs,
                        "from_port": from_port,
                        "to_port": to_port,
                        "vpc_id": sg.get("VpcId", "n/a"),
                    },
                )
                findings.append(finding)
                logger.info(
                    "SecurityGroupScanner: %s — port %d (%s) open to %s",
                    sg_id,
                    port,
                    service,
                    open_cidrs,
                )

        return findings

    @staticmethod
    def _extract_open_cidrs(rule: dict[str, Any]) -> list[str]:
        """Return CIDR strings from a rule that represent open-to-internet.

        Args:
            rule: An ``IpPermissions`` entry from the AWS API.

        Returns:
            List of open CIDR strings (e.g. ``['0.0.0.0/0', '::/0']``).
        """
        open_cidrs: list[str] = []
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                open_cidrs.append(cidr)
        for ipv6_range in rule.get("Ipv6Ranges", []):
            cidr = ipv6_range.get("CidrIpv6", "")
            if cidr == "::/0":
                open_cidrs.append(cidr)
        return open_cidrs

    def _sensitive_ports_in_range(
        self, from_port: int, to_port: int
    ) -> dict[int, str]:
        """Return sensitive ports that fall within the given port range.

        Args:
            from_port: Start of the port range (inclusive).
            to_port: End of the port range (inclusive).

        Returns:
            Mapping of port → service name for each sensitive port in range.
        """
        return {
            port: name
            for port, name in self.SENSITIVE_PORTS.items()
            if from_port <= port <= to_port
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  RDS Scanner
# ═══════════════════════════════════════════════════════════════════════════════

class RDSScanner:
    """Scans RDS instances for unencrypted storage.

    Checks the ``StorageEncrypted`` boolean on every DB instance across
    the configured regions.
    """

    RESOURCE_TYPE = "RDS::DBInstance"

    def __init__(self, session: boto3.Session, regions: list[str]) -> None:
        """Initialise the RDS scanner.

        Args:
            session: An authenticated ``boto3.Session``.
            regions: AWS regions to scan.
        """
        self._session = session
        self._regions = regions
        self._total_scanned = 0

    # ── public API ──────────────────────────────────────────────────────────

    def scan(self) -> list[Finding]:
        """Scan RDS instances across all configured regions.

        Returns:
            Findings for unencrypted RDS instances.
        """
        all_findings: list[Finding] = []
        self._total_scanned = 0

        for region in self._regions:
            try:
                findings = self._scan_region(region)
                all_findings.extend(findings)
            except (ClientError, BotoCoreError) as exc:
                logger.warning(
                    "RDSScanner: failed to scan region '%s': %s", region, exc
                )
                continue

        logger.info(
            "RDSScanner: completed — %d finding(s) across %d instance(s) "
            "in %d region(s)",
            len(all_findings),
            self._total_scanned,
            len(self._regions),
        )
        return all_findings

    @property
    def resources_scanned(self) -> int:
        """Return total RDS instances inspected across all regions."""
        return self._total_scanned

    # ── internal helpers ────────────────────────────────────────────────────

    def _scan_region(self, region: str) -> list[Finding]:
        """Scan all RDS instances in one region.

        Args:
            region: AWS region to scan.

        Returns:
            Findings for this region.
        """
        rds = self._session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        findings: list[Finding] = []

        logger.debug("RDSScanner: paginating DB instances in %s", region)

        for page in paginator.paginate():
            for instance in page.get("DBInstances", []):
                self._total_scanned += 1
                finding = self._check_instance(instance, region)
                if finding is not None:
                    findings.append(finding)

        return findings

    @staticmethod
    def _check_instance(
        instance: dict[str, Any], region: str
    ) -> Finding | None:
        """Check a single RDS instance for storage encryption.

        Args:
            instance: The DB instance descriptor from the AWS API.
            region: Region the instance belongs to.

        Returns:
            A ``Finding`` if storage is unencrypted, else ``None``.
        """
        db_id: str = instance.get("DBInstanceIdentifier", "unknown")
        db_arn: str = instance.get("DBInstanceArn", db_id)
        encrypted: bool = instance.get("StorageEncrypted", False)

        if encrypted:
            logger.debug("RDSScanner: instance '%s' is encrypted", db_id)
            return None

        logger.info(
            "RDSScanner: instance '%s' has UNENCRYPTED storage", db_id
        )

        return Finding(
            resource_id=db_arn,
            resource_type=RDSScanner.RESOURCE_TYPE,
            resource_name=db_id,
            region=region,
            severity=Severity.HIGH,
            issue="RDS instance storage is not encrypted",
            details={
                "db_instance_identifier": db_id,
                "engine": instance.get("Engine", "unknown"),
                "engine_version": instance.get("EngineVersion", "unknown"),
                "instance_class": instance.get("DBInstanceClass", "unknown"),
                "storage_encrypted": False,
                "multi_az": instance.get("MultiAZ", False),
            },
        )
