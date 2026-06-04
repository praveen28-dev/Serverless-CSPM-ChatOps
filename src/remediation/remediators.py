import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

def remediate_security_group(group_id: str, region: str) -> str:
    """Remediation action for EC2 Security Groups with open sensitive ports.
    
    Revokes ingress rules that allow 0.0.0.0/0 or ::/0 for port 22 and 3306.
    """
    ec2 = boto3.client("ec2", region_name=region)
    
    try:
        response = ec2.describe_security_groups(GroupIds=[group_id])
        sg = response['SecurityGroups'][0]
    except ClientError as e:
        logger.error(f"Failed to describe security group {group_id}: {e}")
        return f"Error: Failed to fetch Security Group {group_id} details."

    revoked_count = 0
    sensitive_ports = [22, 3306]

    for rule in sg.get("IpPermissions", []):
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        ip_protocol = rule.get("IpProtocol", "")

        # Check if the rule covers sensitive ports
        is_sensitive = False
        if ip_protocol == "-1":
            is_sensitive = True
        elif from_port is not None and to_port is not None:
            for sp in sensitive_ports:
                if from_port <= sp <= to_port:
                    is_sensitive = True
                    break

        if not is_sensitive:
            continue

        # Find open CIDRs
        ipv4_ranges_to_revoke = [ip for ip in rule.get("IpRanges", []) if ip.get("CidrIp") == "0.0.0.0/0"]
        ipv6_ranges_to_revoke = [ip for ip in rule.get("Ipv6Ranges", []) if ip.get("CidrIpv6") == "::/0"]

        if not ipv4_ranges_to_revoke and not ipv6_ranges_to_revoke:
            continue

        revoke_kwargs = {
            "GroupId": group_id,
            "IpPermissions": [{
                "IpProtocol": ip_protocol,
                "FromPort": rule.get("FromPort"),
                "ToPort": rule.get("ToPort"),
                "IpRanges": ipv4_ranges_to_revoke,
                "Ipv6Ranges": ipv6_ranges_to_revoke,
            }]
        }
        
        # Remove None values from IpPermissions to avoid API errors if protocol is -1
        if revoke_kwargs["IpPermissions"][0]["FromPort"] is None:
            del revoke_kwargs["IpPermissions"][0]["FromPort"]
        if revoke_kwargs["IpPermissions"][0]["ToPort"] is None:
            del revoke_kwargs["IpPermissions"][0]["ToPort"]

        try:
            ec2.revoke_security_group_ingress(**revoke_kwargs)
            logger.info(f"Revoked rule in {group_id}: {revoke_kwargs['IpPermissions']}")
            revoked_count += 1
        except ClientError as e:
            logger.error(f"Failed to revoke rule in {group_id}: {e}")
            return f"Error: Failed to revoke rule in {group_id}."

    if revoked_count > 0:
        return f"Successfully revoked {revoked_count} open ingress rule(s) for Security Group {group_id}."
    else:
        return f"No open rules found for port 22/3306 on Security Group {group_id}."
