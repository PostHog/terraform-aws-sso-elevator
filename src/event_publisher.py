"""Publishes access change events to EventBridge.

When EVENT_BUS_ARN is configured, publishes events after SSO account
assignment grants and revocations. Downstream consumers (e.g. Lambda
functions that update EKS aws-auth ConfigMaps) can subscribe to these
events via EventBridge rules.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError
from mypy_boto3_events import EventBridgeClient

logger = logging.getLogger(__name__)

_events_client: EventBridgeClient | None = None


def _get_events_client() -> EventBridgeClient:
    global _events_client  # noqa: PLW0603
    if _events_client is None:
        _events_client = boto3.client("events")
    return _events_client


def publish_access_event(
    action: str,
    account_id: str,
    permission_set_name: str,
    permission_set_arn: str,
    user_principal_id: str,
) -> None:
    """Publish an access change event to EventBridge.

    No-ops if EVENT_BUS_ARN is not set or empty.
    Logs errors but does not raise — event publishing should never
    block the main grant/revoke flow.
    """
    bus_arn = os.environ.get("EVENT_BUS_ARN", "")
    if not bus_arn:
        return

    detail = {
        "action": action,
        "account_id": account_id,
        "permission_set_name": permission_set_name,
        "permission_set_arn": permission_set_arn,
        "user_principal_id": user_principal_id,
    }

    try:
        response = _get_events_client().put_events(
            Entries=[
                {
                    "Source": "sso-elevator",
                    "DetailType": "AccessChange",
                    "EventBusName": bus_arn,
                    "Detail": json.dumps(detail),
                }
            ]
        )
        if response.get("FailedEntryCount", 0) > 0:
            logger.error(
                "Failed to publish EventBridge event",
                extra={"response": response, "detail": detail},
            )
        else:
            logger.info(
                "Published %s event for %s on account %s",
                action,
                permission_set_name,
                account_id,
            )
    except Exception:
        logger.exception(
            "Error publishing EventBridge event",
            extra={"detail": detail},
        )
