import os
import hmac
import hashlib
import json
import logging
import time
import urllib.parse
import urllib.request
from typing import Any

from src.remediation.remediators import remediate_security_group

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def verify_slack_signature(headers: dict, body: str, signing_secret: str) -> bool:
    """Verify that the request comes from Slack using the signing secret."""
    # API Gateway lowercases headers sometimes, handle both
    slack_signature = headers.get("x-slack-signature") or headers.get("X-Slack-Signature")
    slack_request_timestamp = headers.get("x-slack-request-timestamp") or headers.get("X-Slack-Request-Timestamp")

    if not slack_signature or not slack_request_timestamp:
        logger.warning("Missing Slack signature headers.")
        return False

    # Prevent replay attacks (allow 5 mins variance)
    if abs(time.time() - int(slack_request_timestamp)) > 60 * 5:
        logger.warning("Slack request timestamp is too old.")
        return False

    sig_basestring = f"v0:{slack_request_timestamp}:{body}"
    my_signature = "v0=" + hmac.new(
        signing_secret.encode(),
        sig_basestring.encode(),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(my_signature, slack_signature)

def send_slack_response(response_url: str, text: str) -> None:
    """Send a response back to the Slack message via its response_url."""
    payload = json.dumps({"text": text, "replace_original": False}).encode("utf-8")
    req = urllib.request.Request(
        response_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info(f"Response URL status: {resp.status}")
    except Exception as e:
        logger.error(f"Failed to send response back to Slack: {e}")

def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda entry point for handling Slack interactivity."""
    signing_secret = os.environ.get("SLACK_SIGNING_SECRET")
    if not signing_secret:
        logger.error("SLACK_SIGNING_SECRET is not configured.")
        return {"statusCode": 500, "body": "Configuration error"}

    headers = event.get("headers", {})
    body = event.get("body", "")

    # API Gateway might base64 encode the body depending on configuration
    if event.get("isBase64Encoded"):
        import base64
        body = base64.b64decode(body).decode("utf-8")

    if not verify_slack_signature(headers, body, signing_secret):
        return {"statusCode": 401, "body": "Invalid signature"}

    # The body is x-www-form-urlencoded
    parsed_body = urllib.parse.parse_qs(body)
    if "payload" not in parsed_body:
        return {"statusCode": 400, "body": "Missing payload"}

    payload_str = parsed_body["payload"][0]
    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        return {"statusCode": 400, "body": "Invalid payload JSON"}

    # We only care about block_actions
    if payload.get("type") != "block_actions":
        return {"statusCode": 200, "body": ""}

    response_url = payload.get("response_url")
    user = payload.get("user", {}).get("username", "Someone")

    for action in payload.get("actions", []):
        action_value_str = action.get("value")
        if not action_value_str:
            continue

        try:
            action_value = json.loads(action_value_str)
        except json.JSONDecodeError:
            continue

        action_type = action_value.get("action")
        resource_type = action_value.get("type")
        resource_id = action_value.get("id")
        region = action_value.get("region")

        if action_type == "remediate" and resource_type == "EC2::SecurityGroup":
            logger.info(f"Remediating Security Group {resource_id} in {region}")
            result_msg = remediate_security_group(resource_id, region)
            
            # Send the result back to Slack
            if response_url:
                send_slack_response(response_url, f"🛠️ *Remediation by @{user}:* {result_msg}")

    # Return empty 200 OK so Slack knows we received it
    return {"statusCode": 200, "body": ""}
