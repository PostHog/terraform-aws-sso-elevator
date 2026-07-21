"""CLI access-request entry point.

A non-Slack ingress that lets the `posthog/secrets` CLI (and any AWS-authenticated caller)
request temporary access through the *same* decision/grant pipeline the Slack flow uses.

Auth model
----------
The caller cannot be trusted to self-report its identity, and normal engineers hold no
standing identity in this (the elevator's) AWS account, so we can't put an IAM authorizer on
the API Gateway route. Instead the caller signs an ``sts:GetCallerIdentity`` request with
SigV4 using whatever member-account credentials it already has, and sends that signed request
here as an opaque token. We replay it to STS to obtain the *verified* caller ARN and derive
the requester's email from the ``AWSReservedSSO`` role-session name (the same convention the
CLI itself uses). This is the well-known "AWS IAM auth" pattern (as used by HashiCorp Vault).

A required, signed audience header (``X-SSO-Elevator-Audience``) binds the token to this
service: because it must appear in the SigV4 ``SignedHeaders`` list, a token minted for any
other purpose (or with the header tampered in after signing) cannot be replayed here.

Once the email is verified, the request flows through exactly the same code the Slack shortcut
uses (``main._process_single_access_request`` → ``access_control.make_decision_on_access_request``
→ ``access_control.execute_decision``), so eligibility, auto-approval, approval routing,
auditing and auto-revocation all behave identically regardless of how the request arrived.
"""

import datetime
import json
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import timezone

import boto3
import slack_sdk

import config
import slack_helpers
import sso
from access_control import DecisionReason
from errors import SSOUserNotFound

logger = config.get_logger(service="cli_handler")

session = boto3._get_default_session()
sso_client = session.client("sso-admin")
identity_store_client = session.client("identitystore")

# API Gateway (HTTP API, payload format 2.0) route this handler serves. Kept in sync with the
# route declared in slack_handler_lambda.tf.
ROUTE_KEY = "POST /cli-access-request"

# Audience binding — the header the CLI must include in the SigV4 SignedHeaders of its
# GetCallerIdentity token. Lower-cased because we compare against normalised header names.
AUDIENCE_HEADER = "x-sso-elevator-audience"
EXPECTED_AUDIENCE = "sso-elevator"

# SigV4 tokens are only valid for ~5 minutes at STS anyway; we independently reject anything
# older than this to keep the replay window tight. Two-sided to tolerate minor clock skew.
MAX_TOKEN_AGE = datetime.timedelta(minutes=5)

STS_TIMEOUT_SECONDS = 5
_STS_HOST_RE = re.compile(r"^sts(-fips)?(\.[a-z0-9-]+)?\.amazonaws\.com$")
_DEFAULT_REASON = "Requested via secrets CLI"


class CliRequestError(Exception):
    """A client-facing failure with an HTTP status and a machine-readable status code."""

    def __init__(self, status_code: int, status: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.status = status
        self.message = message

    def response(self) -> dict:
        return _response(self.status_code, {"status": self.status, "message": self.message})


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def _parse_body(event: dict) -> dict:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        import base64

        raw = base64.b64decode(raw).decode("utf-8")
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError) as e:
        raise CliRequestError(400, "invalid_body", "Request body must be valid JSON.") from e
    if not isinstance(parsed, dict):
        raise CliRequestError(400, "invalid_body", "Request body must be a JSON object.")
    return parsed


def _signed_headers(authorization: str) -> set[str]:
    """Extract the SignedHeaders list from a SigV4 Authorization header (lower-cased)."""
    match = re.search(r"SignedHeaders=([^,]+)", authorization)
    if not match:
        return set()
    return {h.strip().lower() for h in match.group(1).split(";") if h.strip()}


def _check_freshness(amz_date: str) -> None:
    try:
        signed_at = datetime.datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError) as e:
        raise CliRequestError(401, "invalid_token", "Token is missing a valid X-Amz-Date header.") from e
    if abs(datetime.datetime.now(timezone.utc) - signed_at) > MAX_TOKEN_AGE:
        raise CliRequestError(401, "token_expired", "Identity token has expired; please retry.")


def _parse_arn_from_sts_response(raw: str) -> str:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        raise CliRequestError(401, "invalid_token", "Could not parse the STS response.") from e
    # Ignore XML namespaces — match on the local tag name.
    for el in root.iter():
        if el.tag.rsplit("}", 1)[-1] == "Arn" and el.text:
            return el.text
    raise CliRequestError(401, "invalid_token", "STS response did not contain a caller ARN.")


def _email_from_arn(arn: str) -> str:
    # SSO assumed-role ARNs carry the user's email as the role-session name:
    #   arn:aws:sts::<acct>:assumed-role/AWSReservedSSO_<permset>_<hash>/<email>
    # This mirrors the `email_from_arn` convention used by the secrets CLI itself.
    session_name = arn.rsplit("/", 1)[-1] if "/" in arn else ""
    if "@" not in session_name:
        raise CliRequestError(401, "invalid_token", "Caller identity is not an SSO user (no email in the role-session name).")
    return session_name


def verify_sts_token(token: dict) -> str:
    """Verify a signed sts:GetCallerIdentity token and return the caller's verified email.

    The token is a dict of ``{method, url, headers, body}`` produced by the CLI. We validate
    its shape/audience/freshness locally, then replay it to STS which validates the signature.
    """
    method = str(token.get("method", "")).upper()
    url = str(token.get("url", ""))
    body = str(token.get("body", ""))
    raw_headers = token.get("headers") or {}
    if not isinstance(raw_headers, dict):
        raise CliRequestError(401, "invalid_token", "Token headers are malformed.")
    headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}

    if method != "POST":
        raise CliRequestError(401, "invalid_token", "Token must be a POST request.")

    host = (urllib.parse.urlparse(url).hostname or "").lower()
    if not _STS_HOST_RE.match(host):
        raise CliRequestError(401, "invalid_token", "Token is not addressed to AWS STS.")

    # The token must be a GetCallerIdentity call and nothing else.
    params = urllib.parse.parse_qs(body)
    if params.get("Action") != ["GetCallerIdentity"]:
        raise CliRequestError(401, "invalid_token", "Token is not a GetCallerIdentity request.")

    # Audience binding: present, correct, and covered by the signature.
    if headers.get(AUDIENCE_HEADER) != EXPECTED_AUDIENCE:
        raise CliRequestError(401, "invalid_token", "Token is missing the expected audience header.")
    if AUDIENCE_HEADER not in _signed_headers(headers.get("authorization", "")):
        raise CliRequestError(401, "invalid_token", "Audience header is not covered by the token signature.")

    _check_freshness(headers.get("x-amz-date", ""))

    # Replay to STS, which validates the signature. Forward the caller's original-case headers.
    request = urllib.request.Request(url=url, data=body.encode("utf-8"), method="POST")
    for key, value in raw_headers.items():
        request.add_header(str(key), str(value))
    try:
        with urllib.request.urlopen(request, timeout=STS_TIMEOUT_SECONDS) as resp:  # noqa: S310 (host pinned to STS above)
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        logger.warning("STS rejected the identity token", extra={"status": e.code})
        raise CliRequestError(401, "invalid_token", "STS rejected the identity token (bad signature or expired).") from e
    except (urllib.error.URLError, TimeoutError) as e:
        logger.exception("Failed to reach STS while verifying identity token")
        raise CliRequestError(502, "sts_unreachable", "Could not reach AWS STS to verify identity; please retry.") from e

    email = _email_from_arn(_parse_arn_from_sts_response(raw))
    logger.info("Verified CLI requester identity", extra={"email": email})
    return email


def _decision_response(decision, account_id: str, permission_set_name: str, duration: datetime.timedelta) -> dict:
    duration_seconds = int(duration.total_seconds())
    if decision is not None and decision.grant:
        expires_at = (datetime.datetime.now(timezone.utc) + duration).isoformat()
        return _response(
            200,
            {
                "status": "granted",
                "account_id": account_id,
                "permission_set": permission_set_name,
                "duration_seconds": duration_seconds,
                "expires_at": expires_at,
            },
        )

    reason = decision.reason if decision is not None else None
    if reason == DecisionReason.RequiresApproval:
        return _response(
            202,
            {
                "status": "pending_approval",
                "permission_set": permission_set_name,
                "account_id": account_id,
                "message": "Request submitted. An approver must approve it in Slack.",
            },
        )
    if reason == DecisionReason.NoApprovers:
        return _response(
            403,
            {"status": "no_approvers", "message": "No approvers are configured for this permission set and account."},
        )
    # NoStatements (or any unexpected non-grant) → not eligible.
    return _response(
        403,
        {
            "status": "not_eligible",
            "message": "You are not eligible to request this permission set for this account.",
        },
    )


def handle(event: dict, context) -> dict:  # noqa: ANN001, ARG001
    """Handle a CLI access request (API Gateway HTTP API proxy event)."""
    logger.info("Handling CLI access request")
    try:
        cfg = config.get_config()
        body = _parse_body(event)

        token = body.get("sts_token")
        if not isinstance(token, dict):
            raise CliRequestError(400, "missing_sts_token", "Request must include a signed 'sts_token' object.")

        account_id = str(body.get("account_id") or "").strip()
        if not account_id:
            raise CliRequestError(400, "missing_account_id", "Request must include 'account_id'.")

        permission_set_name = str(body.get("permission_set_name") or "").strip()
        if not permission_set_name:
            raise CliRequestError(400, "missing_permission_set", "Request must include 'permission_set_name'.")

        reason = str(body.get("reason") or "").strip() or _DEFAULT_REASON

        # Clamp the requested duration to the elevator's configured maximum.
        max_seconds = cfg.max_permissions_duration_time * 3600
        raw_duration = body.get("duration_seconds")
        if raw_duration is None:
            requested_seconds = 3600
        else:
            try:
                requested_seconds = int(raw_duration)
            except (TypeError, ValueError) as e:
                raise CliRequestError(400, "invalid_duration", "'duration_seconds' must be an integer.") from e
        if requested_seconds <= 0:
            requested_seconds = 3600
        duration = datetime.timedelta(seconds=min(requested_seconds, max_seconds))

        # 1) Verify identity (server-side, never trusting a self-reported email).
        requester_email = verify_sts_token(token)

        # 2) Resolve the Slack user (needed for approval routing, DMs, and the audit trail).
        client = slack_sdk.WebClient(token=cfg.slack_bot_token)
        try:
            requester = slack_helpers.get_user_by_email(client, requester_email)
        except Exception as e:
            logger.warning("Could not resolve Slack user by email", extra={"email": requester_email, "error": str(e)})
            raise CliRequestError(
                404,
                "slack_user_not_found",
                "Could not find your Slack account by email. Use the /awsaccess Slack flow instead.",
            ) from e

        # 3) Resolve SSO identity + group memberships for eligibility filtering.
        identity_store_id = sso.get_identity_store_id(cfg, sso_client)
        try:
            user_principal_id, _ = sso.get_user_principal_id_by_email(
                identity_store_client=identity_store_client,
                identity_store_id=identity_store_id,
                email=requester_email,
                cfg=cfg,
            )
        except SSOUserNotFound as e:
            raise CliRequestError(404, "sso_user_not_found", "Your user was not found in AWS SSO.") from e
        user_group_ids = sso.get_user_group_ids(
            identity_store_client=identity_store_client,
            identity_store_id=identity_store_id,
            user_principal_id=user_principal_id,
        )

        # 4) Run the shared request pipeline (decision → approval message / auto-grant → schedule
        #    revoke). Imported lazily so this module has no load-time dependency on `main`.
        request = slack_helpers.RequestForAccess(
            permission_set_name=permission_set_name,
            account_id=account_id,
            reason=reason,
            requester_slack_id=requester.id,
            permission_duration=duration,
        )
        is_user_in_channel = slack_helpers.check_if_user_is_in_channel(client, cfg.slack_channel_id, requester.id)

        import main  # noqa: PLC0415  (lazy import avoids a load-time cycle: main imports cli_handler)

        decision = main._process_single_access_request(
            request=request,
            requester=requester,
            user_group_ids=user_group_ids,
            client=client,
            is_user_in_channel=is_user_in_channel,
        )
        return _decision_response(decision, account_id, permission_set_name, duration)

    except CliRequestError as e:
        logger.info("CLI access request rejected", extra={"status": e.status, "detail": e.message})
        return e.response()
    except Exception:
        logger.exception("Unhandled error in CLI access handler")
        return _response(500, {"status": "error", "message": "Internal error. Check the SSO Elevator logs."})
