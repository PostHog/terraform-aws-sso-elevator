# ruff: noqa: ARG002, PLR0913
"""Tests for EventBridge event publishing."""

import json
import os
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

import event_publisher


class TestPublishAccessEvent:
    """Unit tests for the publish_access_event function."""

    SAMPLE_KWARGS = {
        "action": "grant",
        "account_id": "123456789012",
        "permission_set_name": "eks-developer",
        "permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
        "user_principal_id": "user-principal-abc",
    }

    def setup_method(self):
        # Reset the cached client between tests
        event_publisher._events_client = None

    @patch.dict(os.environ, {"EVENT_BUS_ARN": "arn:aws:events:us-east-1:111111111111:event-bus/sso-elevator-events"})
    @patch("event_publisher._get_events_client")
    def test_publishes_grant_event(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{"EventId": "abc"}]}
        mock_get_client.return_value = mock_client

        event_publisher.publish_access_event(**self.SAMPLE_KWARGS)

        mock_client.put_events.assert_called_once()
        call_args = mock_client.put_events.call_args
        entry = call_args[1]["Entries"][0] if "Entries" in call_args[1] else call_args[0][0]["Entries"][0]

        # Handle both positional and keyword args
        entries = call_args.kwargs.get("Entries") or call_args.args[0] if call_args.args else None
        if entries is None:
            entries = call_args[1]["Entries"]
        entry = entries[0]

        assert entry["Source"] == "sso-elevator"
        assert entry["DetailType"] == "AccessChange"
        assert entry["EventBusArn"] == "arn:aws:events:us-east-1:111111111111:event-bus/sso-elevator-events"

        detail = json.loads(entry["Detail"])
        assert detail["action"] == "grant"
        assert detail["account_id"] == "123456789012"

    @patch.dict(os.environ, {"EVENT_BUS_ARN": "arn:aws:events:us-east-1:111111111111:event-bus/test"})
    @patch("event_publisher._get_events_client")
    def test_publishes_revoke_event(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{"EventId": "def"}]}
        mock_get_client.return_value = mock_client

        kwargs = {**self.SAMPLE_KWARGS, "action": "revoke"}
        event_publisher.publish_access_event(**kwargs)

        entry = mock_client.put_events.call_args.kwargs["Entries"][0]
        detail = json.loads(entry["Detail"])
        assert detail["action"] == "revoke"

    @patch.dict(os.environ, {"EVENT_BUS_ARN": ""})
    @patch("event_publisher._get_events_client")
    def test_noop_when_bus_arn_empty(self, mock_get_client):
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        event_publisher.publish_access_event(**self.SAMPLE_KWARGS)

        mock_client.put_events.assert_not_called()

    @patch.dict(os.environ, {}, clear=False)
    @patch("event_publisher._get_events_client")
    def test_noop_when_bus_arn_unset(self, mock_get_client):
        # Ensure EVENT_BUS_ARN is not set
        os.environ.pop("EVENT_BUS_ARN", None)
        mock_client = MagicMock()
        mock_get_client.return_value = mock_client

        event_publisher.publish_access_event(**self.SAMPLE_KWARGS)

        mock_client.put_events.assert_not_called()

    @patch.dict(os.environ, {"EVENT_BUS_ARN": "arn:aws:events:us-east-1:111111111111:event-bus/test"})
    @patch("event_publisher._get_events_client")
    def test_event_detail_contains_all_fields(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.put_events.return_value = {"FailedEntryCount": 0, "Entries": [{"EventId": "ghi"}]}
        mock_get_client.return_value = mock_client

        event_publisher.publish_access_event(**self.SAMPLE_KWARGS)

        entry = mock_client.put_events.call_args.kwargs["Entries"][0]
        detail = json.loads(entry["Detail"])

        expected_keys = {"action", "account_id", "permission_set_name", "permission_set_arn", "user_principal_id"}
        assert set(detail.keys()) == expected_keys

    @patch.dict(os.environ, {"EVENT_BUS_ARN": "arn:aws:events:us-east-1:111111111111:event-bus/test"})
    @patch("event_publisher._get_events_client")
    def test_handles_put_events_error_gracefully(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.put_events.side_effect = ClientError(
            {"Error": {"Code": "InternalException", "Message": "Service error"}},
            "PutEvents",
        )
        mock_get_client.return_value = mock_client

        # Should not raise
        event_publisher.publish_access_event(**self.SAMPLE_KWARGS)

    @patch.dict(os.environ, {"EVENT_BUS_ARN": "arn:aws:events:us-east-1:111111111111:event-bus/test"})
    @patch("event_publisher._get_events_client")
    def test_logs_warning_on_failed_entry(self, mock_get_client):
        mock_client = MagicMock()
        mock_client.put_events.return_value = {
            "FailedEntryCount": 1,
            "Entries": [{"ErrorCode": "InternalFailure", "ErrorMessage": "Something went wrong"}],
        }
        mock_get_client.return_value = mock_client

        # Should not raise, but should log error
        event_publisher.publish_access_event(**self.SAMPLE_KWARGS)


class TestIntegrationWithAccessControl:
    """Tests that access_control.execute_decision publishes events."""

    @patch("access_control.event_publisher")
    @patch("access_control.schedule")
    @patch("access_control.s3")
    @patch("access_control.organizations")
    @patch("access_control.sso")
    @patch("access_control.config")
    def test_grant_publishes_event(self, mock_config, mock_sso, mock_orgs, mock_s3, mock_schedule, mock_event_pub):
        import access_control
        from entities.slack import User as SlackUser
        from statement import Statement

        # Configure mocks
        cfg = MagicMock()
        cfg.sso_instance_arn = "arn:aws:sso:::instance/ssoins-1234"
        mock_config.get_config.return_value = cfg

        permission_set_mock = MagicMock()
        permission_set_mock.name = "eks-developer"
        permission_set_mock.arn = "arn:aws:sso:::permissionSet/ps-1234"
        mock_sso.describe_permission_set.return_value = permission_set_mock
        mock_sso.get_permission_set.return_value = permission_set_mock
        mock_sso.get_user_principal_id_by_email.return_value = ("user-principal-123", False)

        assignment_status = MagicMock()
        assignment_status.request_id = "req-abc"
        mock_sso.create_account_assignment_and_wait_for_result.return_value = assignment_status

        mock_orgs.describe_account.return_value = MagicMock(name="dev")
        mock_schedule.schedule_revoke_event.return_value = ("schedule-arn", "schedule-name")

        statement = MagicMock(spec=Statement)
        statement.can_extend_expired_grant = False
        decision = MagicMock()
        decision.grant = True
        decision.based_on_statements = [statement]
        decision.permission_set = "arn:aws:sso:::permissionSet/ps-1234"
        decision.account_id = "123456789012"

        approver = SlackUser(id="U_APPROVER", email="approver@example.com", real_name="Approver")
        requester = SlackUser(id="U_REQUESTER", email="requester@example.com", real_name="Requester")

        import datetime

        access_control.execute_decision(
            decision=decision,
            permission_set_name="eks-developer",
            account_id="123456789012",
            permission_duration=datetime.timedelta(hours=1),
            approver=approver,
            requester=requester,
            reason="need eks access",
        )

        mock_event_pub.publish_access_event.assert_called_once()
        call_kwargs = mock_event_pub.publish_access_event.call_args.kwargs
        assert call_kwargs["action"] == "grant"
        assert call_kwargs["account_id"] == "123456789012"
        assert call_kwargs["permission_set_name"] == "eks-developer"


class TestIntegrationWithRevoker:
    """Tests that revoker functions publish events."""

    @patch("revoker.event_publisher")
    @patch("revoker.analytics")
    @patch("revoker.s3")
    @patch("revoker.schedule")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    def test_early_revoke_publishes_event(self, mock_sh, mock_sso, mock_schedule, mock_s3, mock_analytics, mock_event_pub):
        import revoker
        import sso as sso_module

        assignment = sso_module.UserAccountAssignment(
            instance_arn="arn:aws:sso:::instance/ssoins-1234",
            account_id="123456789012",
            permission_set_arn="arn:aws:sso:::permissionSet/ps-5678",
            user_principal_id="user-principal-123",
        )

        mock_sso.describe_permission_set.return_value = MagicMock(name="eks-developer")
        mock_sso.delete_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-123")
        mock_sso.get_user_email.return_value = "requester@example.com"

        cfg = MagicMock()
        cfg.post_update_to_slack = False

        revoker.handle_early_account_revocation(
            user_account_assignment=assignment,
            schedule_name="schedule-123",
            revoker_slack_id="U_REVOKER",
            requester_slack_id="U_REQUESTER",
            reason="no longer needed",
            sso_client=MagicMock(),
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=MagicMock(),
            identitystore_client=MagicMock(),
            cfg=cfg,
        )

        mock_event_pub.publish_access_event.assert_called_once()
        call_kwargs = mock_event_pub.publish_access_event.call_args.kwargs
        assert call_kwargs["action"] == "revoke"
        assert call_kwargs["account_id"] == "123456789012"

    @patch("revoker.event_publisher")
    @patch("revoker.s3")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    @patch("revoker.organizations")
    def test_inconsistency_revoke_publishes_event(self, mock_orgs, mock_sh, mock_sso, mock_s3, mock_event_pub):
        import revoker
        import sso as sso_module

        assignment = sso_module.UserAccountAssignment(
            instance_arn="arn:aws:sso:::instance/ssoins-1234",
            account_id="123456789012",
            permission_set_arn="arn:aws:sso:::permissionSet/ps-5678",
            user_principal_id="user-principal-123",
        )

        mock_sso.describe_permission_set.return_value = MagicMock(name="eks-developer")
        mock_sso.delete_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-456")

        cfg = MagicMock()
        cfg.post_update_to_slack = False

        revoker.handle_account_assignment_deletion(
            account_assignment=assignment,
            cfg=cfg,
            sso_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=MagicMock(),
            identitystore_client=MagicMock(),
        )

        mock_event_pub.publish_access_event.assert_called_once()
        call_kwargs = mock_event_pub.publish_access_event.call_args.kwargs
        assert call_kwargs["action"] == "revoke"
        assert call_kwargs["permission_set_arn"] == "arn:aws:sso:::permissionSet/ps-5678"

    @patch("revoker.event_publisher")
    @patch("revoker.s3")
    @patch("revoker.schedule")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    @patch("revoker.organizations")
    def test_scheduled_revoke_publishes_event(self, mock_orgs, mock_sh, mock_sso, mock_schedule, mock_s3, mock_event_pub):
        import revoker
        import sso as sso_module

        assignment = sso_module.UserAccountAssignment(
            instance_arn="arn:aws:sso:::instance/ssoins-1234",
            account_id="123456789012",
            permission_set_arn="arn:aws:sso:::permissionSet/ps-5678",
            user_principal_id="user-principal-123",
        )

        mock_sso.describe_permission_set.return_value = MagicMock(name="eks-developer")
        mock_sso.delete_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-789")

        # Don't use spec=RevokeEvent — Pydantic models don't expose fields to MagicMock spec
        revoke_event = MagicMock()
        revoke_event.user_account_assignment = assignment
        revoke_event.requester = MagicMock(id="U_REQ", email="req@example.com")
        revoke_event.approver = MagicMock(id="U_APP", email="app@example.com")
        revoke_event.permission_duration = "1:00:00"
        revoke_event.schedule_name = "schedule-789"
        revoke_event.permission_set_name = "eks-developer"
        revoke_event.account_name = "dev"
        revoke_event.can_extend_expired_grant = False
        revoke_event.extensions_count = 0

        cfg = MagicMock()
        cfg.post_update_to_slack = False

        revoker.handle_scheduled_account_assignment_deletion(
            revoke_event=revoke_event,
            sso_client=MagicMock(),
            cfg=cfg,
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=MagicMock(),
            identitystore_client=MagicMock(),
        )

        mock_event_pub.publish_access_event.assert_called_once()
        call_kwargs = mock_event_pub.publish_access_event.call_args.kwargs
        assert call_kwargs["action"] == "revoke"
        assert call_kwargs["account_id"] == "123456789012"
        assert call_kwargs["user_principal_id"] == "user-principal-123"
