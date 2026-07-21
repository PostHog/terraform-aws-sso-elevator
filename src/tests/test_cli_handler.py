"""Tests for the CLI access-request handler (cli_handler.py)."""

import json
import sys
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import cli_handler
import entities
from access_control import DecisionReason

STS_RESPONSE_XML = """<?xml version="1.0"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::169684386827:assumed-role/AWSReservedSSO_secrets-editor_abc123/user@posthog.com</Arn>
    <UserId>AROAEXAMPLE:user@posthog.com</UserId>
    <Account>169684386827</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>"""


def _fresh_amz_date() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _valid_token(**overrides) -> dict:
    token = {
        "method": "POST",
        "url": "https://sts.amazonaws.com/",
        "headers": {
            "Authorization": "AWS4-HMAC-SHA256 Credential=AKIA/20240101/us-east-1/sts/aws4_request, "
            "SignedHeaders=host;x-amz-date;x-sso-elevator-audience, Signature=deadbeef",
            "X-Amz-Date": _fresh_amz_date(),
            "X-SSO-Elevator-Audience": "sso-elevator",
            "Host": "sts.amazonaws.com",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "body": "Action=GetCallerIdentity&Version=2011-06-15",
    }
    token.update(overrides)
    return token


# --- _email_from_arn -------------------------------------------------------------------------


def test_email_from_arn_extracts_session_name():
    arn = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_secrets-editor_abc/user@posthog.com"
    assert cli_handler._email_from_arn(arn) == "user@posthog.com"


def test_email_from_arn_rejects_non_sso_identity():
    with pytest.raises(cli_handler.CliRequestError):
        cli_handler._email_from_arn("arn:aws:iam::123456789012:user/service-account")


# --- verify_sts_token ------------------------------------------------------------------------


def _urlopen_returning(xml: str):
    cm = MagicMock()
    cm.__enter__.return_value = MagicMock(read=lambda: xml.encode("utf-8"))
    cm.__exit__.return_value = False
    return cm


def test_verify_sts_token_happy_path():
    with patch("cli_handler.urllib.request.urlopen", return_value=_urlopen_returning(STS_RESPONSE_XML)):
        assert cli_handler.verify_sts_token(_valid_token()) == "user@posthog.com"


def test_verify_sts_token_rejects_non_sts_host():
    with pytest.raises(cli_handler.CliRequestError):
        cli_handler.verify_sts_token(_valid_token(url="https://evil.example.com/"))


def test_verify_sts_token_rejects_missing_audience_header():
    token = _valid_token()
    del token["headers"]["X-SSO-Elevator-Audience"]
    with pytest.raises(cli_handler.CliRequestError):
        cli_handler.verify_sts_token(token)


def test_verify_sts_token_rejects_unsigned_audience_header():
    # Audience header is present but NOT in the signature's SignedHeaders — attacker could have
    # appended it to a token signed for another purpose.
    token = _valid_token()
    token["headers"]["Authorization"] = (
        "AWS4-HMAC-SHA256 Credential=AKIA/20240101/us-east-1/sts/aws4_request, "
        "SignedHeaders=host;x-amz-date, Signature=deadbeef"
    )
    with pytest.raises(cli_handler.CliRequestError):
        cli_handler.verify_sts_token(token)


def test_verify_sts_token_rejects_non_getcalleridentity_action():
    with pytest.raises(cli_handler.CliRequestError):
        cli_handler.verify_sts_token(_valid_token(body="Action=AssumeRole&Version=2011-06-15"))


def test_verify_sts_token_rejects_stale_token():
    token = _valid_token()
    token["headers"]["X-Amz-Date"] = "20200101T000000Z"
    with pytest.raises(cli_handler.CliRequestError):
        cli_handler.verify_sts_token(token)


# --- handle ----------------------------------------------------------------------------------


def _event(body: dict) -> dict:
    return {"routeKey": cli_handler.ROUTE_KEY, "body": json.dumps(body)}


@pytest.fixture
def wired(monkeypatch):
    """Patch identity + Slack + SSO resolution so handle() reaches the decision step."""
    monkeypatch.setattr(cli_handler, "verify_sts_token", lambda token: "user@posthog.com")
    monkeypatch.setattr(cli_handler.slack_sdk, "WebClient", lambda token: MagicMock())
    monkeypatch.setattr(
        cli_handler.slack_helpers,
        "get_user_by_email",
        lambda client, email: entities.slack.User(id="U1", email=email, real_name="User"),
    )
    monkeypatch.setattr(cli_handler.slack_helpers, "check_if_user_is_in_channel", lambda *a, **k: True)
    monkeypatch.setattr(cli_handler.sso, "get_identity_store_id", lambda cfg, client: "d-123")
    monkeypatch.setattr(cli_handler.sso, "get_user_principal_id_by_email", lambda **k: ("principal-1", False))
    monkeypatch.setattr(cli_handler.sso, "get_user_group_ids", lambda **k: {"group-1"})


def _run_with_decision(event, decision):
    fake_main = MagicMock()
    fake_main._process_single_access_request.return_value = decision
    with patch.dict(sys.modules, {"main": fake_main}):
        return cli_handler.handle(event, None), fake_main


def test_handle_granted(wired):
    decision = SimpleNamespace(grant=True, reason=DecisionReason.ApprovalNotRequired)
    resp, fake_main = _run_with_decision(
        _event({"sts_token": {}, "account_id": "169684386827", "permission_set_name": "secrets-editor", "reason": "edit"}),
        decision,
    )
    assert resp["statusCode"] == 200
    payload = json.loads(resp["body"])
    assert payload["status"] == "granted"
    assert payload["permission_set"] == "secrets-editor"
    assert payload["account_id"] == "169684386827"
    assert "expires_at" in payload
    # The shared pipeline was invoked with a properly-built request.
    call = fake_main._process_single_access_request.call_args.kwargs
    assert call["request"].account_id == "169684386827"
    assert call["request"].requester_slack_id == "U1"


def test_handle_pending_approval(wired):
    decision = SimpleNamespace(grant=False, reason=DecisionReason.RequiresApproval)
    resp, _ = _run_with_decision(
        _event({"sts_token": {}, "account_id": "169684386827", "permission_set_name": "AdministratorAccess"}),
        decision,
    )
    assert resp["statusCode"] == 202
    assert json.loads(resp["body"])["status"] == "pending_approval"


def test_handle_not_eligible(wired):
    decision = SimpleNamespace(grant=False, reason=DecisionReason.NoStatements)
    resp, _ = _run_with_decision(
        _event({"sts_token": {}, "account_id": "169684386827", "permission_set_name": "secrets-editor"}),
        decision,
    )
    assert resp["statusCode"] == 403
    assert json.loads(resp["body"])["status"] == "not_eligible"


def test_handle_clamps_duration_to_max(wired):
    # conftest sets max_permissions_duration_time = 24 hours.
    decision = SimpleNamespace(grant=True, reason=DecisionReason.ApprovalNotRequired)
    resp, _ = _run_with_decision(
        _event(
            {
                "sts_token": {},
                "account_id": "169684386827",
                "permission_set_name": "secrets-editor",
                "duration_seconds": 999999,
            }
        ),
        decision,
    )
    assert json.loads(resp["body"])["duration_seconds"] == 24 * 3600


def test_handle_missing_sts_token():
    resp = cli_handler.handle(_event({"account_id": "169684386827", "permission_set_name": "secrets-editor"}), None)
    assert resp["statusCode"] == 400
    assert json.loads(resp["body"])["status"] == "missing_sts_token"


def test_handle_missing_account_id(wired):
    resp = cli_handler.handle(_event({"sts_token": {}, "permission_set_name": "secrets-editor"}), None)
    # sts_token present (a dict), but account_id missing.
    assert resp["statusCode"] == 400
    assert json.loads(resp["body"])["status"] == "missing_account_id"


def test_handle_slack_user_not_found(monkeypatch):
    monkeypatch.setattr(cli_handler, "verify_sts_token", lambda token: "ghost@posthog.com")
    monkeypatch.setattr(cli_handler.slack_sdk, "WebClient", lambda token: MagicMock())

    def _raise(client, email):
        raise Exception("users_not_found")

    monkeypatch.setattr(cli_handler.slack_helpers, "get_user_by_email", _raise)
    resp = cli_handler.handle(
        _event({"sts_token": {}, "account_id": "169684386827", "permission_set_name": "secrets-editor"}),
        None,
    )
    assert resp["statusCode"] == 404
    assert json.loads(resp["body"])["status"] == "slack_user_not_found"
