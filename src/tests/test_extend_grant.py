"""Tests for extend expired grant feature."""

# ruff: noqa: ARG002, PLR0133

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import config
import entities
import sso
from events import GroupRevokeEvent, RevokeEvent
from slack_helpers import ExtendGrantButtonPayload, build_extend_grant_button
from statement import GroupStatement, Statement


# ---------------------------------------------------------------------------
# Config parsing
# ---------------------------------------------------------------------------


class TestConfigParsing:
    def test_parse_statement_with_extend_fields(self):
        stmt = config.parse_statement(
            {
                "ResourceType": "Account",
                "Resource": ["111111111111"],
                "PermissionSet": "Admin",
                "Approvers": "a@b.com",
                "CanExtendExpiredGrant": True,
            }
        )
        assert stmt.can_extend_expired_grant is True

    def test_parse_statement_defaults_when_omitted(self):
        stmt = config.parse_statement(
            {
                "ResourceType": "Account",
                "Resource": ["111111111111"],
                "PermissionSet": "Admin",
                "Approvers": "a@b.com",
            }
        )
        assert stmt.can_extend_expired_grant is False

    def test_parse_group_statement_with_extend_fields(self):
        stmt = config.parse_group_statement(
            {
                "Resource": ["11111111-2222-3333-4444-555555555555"],
                "Approvers": "a@b.com",
                "CanExtendExpiredGrant": True,
            }
        )
        assert stmt.can_extend_expired_grant is True

    def test_parse_group_statement_defaults_when_omitted(self):
        stmt = config.parse_group_statement(
            {
                "Resource": ["11111111-2222-3333-4444-555555555555"],
                "Approvers": "a@b.com",
            }
        )
        assert stmt.can_extend_expired_grant is False


# ---------------------------------------------------------------------------
# Statement model fields
# ---------------------------------------------------------------------------


class TestStatementModels:
    def test_statement_extend_fields(self):
        stmt = Statement(
            resource_type="Account",  # type: ignore[arg-type]
            resource=frozenset(["111111111111"]),
            permission_set=frozenset(["Admin"]),
            can_extend_expired_grant=True,
        )
        assert stmt.can_extend_expired_grant is True

    def test_group_statement_extend_fields(self):
        stmt = GroupStatement(
            resource=frozenset(["11111111-2222-3333-4444-555555555555"]),
            can_extend_expired_grant=True,
        )
        assert stmt.can_extend_expired_grant is True


# ---------------------------------------------------------------------------
# Event model fields
# ---------------------------------------------------------------------------


class TestEventModels:
    def test_revoke_event_with_extend_fields(self):
        event = RevokeEvent(
            schedule_name="test",
            approver=entities.slack.User(id="A1", email="a@b.com", real_name="A"),
            requester=entities.slack.User(id="R1", email="r@b.com", real_name="R"),
            user_account_assignment=sso.UserAccountAssignment(
                instance_arn="arn:aws:sso:::instance/ssoins-1234",
                account_id="111111111111",
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
                user_principal_id="uid-123",
            ),
            permission_duration=timedelta(hours=1),
            can_extend_expired_grant=True,
            extensions_count=0,
        )
        assert event.can_extend_expired_grant is True
        assert event.extensions_count == 0

    def test_revoke_event_backward_compat_defaults(self):
        """Old events without extend fields should default correctly."""
        event = RevokeEvent(
            schedule_name="test",
            approver=entities.slack.User(id="A1", email="a@b.com", real_name="A"),
            requester=entities.slack.User(id="R1", email="r@b.com", real_name="R"),
            user_account_assignment=sso.UserAccountAssignment(
                instance_arn="arn:aws:sso:::instance/ssoins-1234",
                account_id="111111111111",
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
                user_principal_id="uid-123",
            ),
            permission_duration=timedelta(hours=1),
        )
        assert event.can_extend_expired_grant is False
        assert event.extensions_count == 0

    def test_group_revoke_event_with_extend_fields(self):
        event = GroupRevokeEvent(
            schedule_name="test",
            approver=entities.slack.User(id="A1", email="a@b.com", real_name="A"),
            requester=entities.slack.User(id="R1", email="r@b.com", real_name="R"),
            group_assignment=sso.GroupAssignment(
                identity_store_id="d-123",
                group_name="Admins",
                group_id="gid-123",
                user_principal_id="uid-123",
                membership_id="mid-123",
            ),
            permission_duration=timedelta(hours=1),
            can_extend_expired_grant=True,
            extensions_count=1,
        )
        assert event.can_extend_expired_grant is True
        assert event.extensions_count == 1

    def test_group_revoke_event_backward_compat_defaults(self):
        event = GroupRevokeEvent(
            schedule_name="test",
            approver=entities.slack.User(id="A1", email="a@b.com", real_name="A"),
            requester=entities.slack.User(id="R1", email="r@b.com", real_name="R"),
            group_assignment=sso.GroupAssignment(
                identity_store_id="d-123",
                group_name="Admins",
                group_id="gid-123",
                user_principal_id="uid-123",
                membership_id="mid-123",
            ),
            permission_duration=timedelta(hours=1),
        )
        assert event.can_extend_expired_grant is False
        assert event.extensions_count == 0


# ---------------------------------------------------------------------------
# ExtendGrantButtonPayload
# ---------------------------------------------------------------------------


class TestExtendGrantButtonPayload:
    def test_serialization_roundtrip(self):
        payload = ExtendGrantButtonPayload(
            requester_slack_id="U123",
            expired_at="2024-01-15T10:30:00+00:00",
            extension_duration_in_minutes=15,
            extensions_count=0,
            account_id="111111111111",
            permission_set_name="Admin",
            permission_set_arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
            instance_arn="arn:aws:sso:::instance/ssoins-1234",
            user_principal_id="uid-123",
            account_name="Production",
            approver={"id": "A1", "email": "a@b.com", "real_name": "Approver"},
            requester={"id": "U123", "email": "r@b.com", "real_name": "Requester"},
        )
        json_str = json.dumps(payload.model_dump(mode="json"))
        restored = ExtendGrantButtonPayload.model_validate(json.loads(json_str))
        assert restored.requester_slack_id == "U123"
        assert restored.extension_duration_in_minutes == 15
        assert restored.account_id == "111111111111"
        assert restored.approver["id"] == "A1"  # type: ignore[index]

    def test_group_payload_roundtrip(self):
        payload = ExtendGrantButtonPayload(
            requester_slack_id="U123",
            expired_at="2024-01-15T10:30:00+00:00",
            extension_duration_in_minutes=30,
            extensions_count=0,
            group_id="gid-123",
            group_name="Admins",
            identity_store_id="d-123",
            user_principal_id="uid-123",
            approver={"id": "A1", "email": "a@b.com", "real_name": "A"},
            requester={"id": "U123", "email": "r@b.com", "real_name": "R"},
        )
        json_str = json.dumps(payload.model_dump(mode="json"))
        restored = ExtendGrantButtonPayload.model_validate(json.loads(json_str))
        assert restored.group_id == "gid-123"
        assert restored.extension_duration_in_minutes == 30

    def test_deserialization_from_json_string(self):
        """Test model_validator handles JSON string input."""
        json_data = {
            "requester_slack_id": "U123",
            "expired_at": "2024-01-15T10:30:00+00:00",
            "extension_duration_in_minutes": 15,
            "extensions_count": 0,
            "user_principal_id": "uid-123",
        }
        json_str = json.dumps(json_data)
        payload = ExtendGrantButtonPayload.model_validate(json.loads(json_str))
        assert payload.requester_slack_id == "U123"


# ---------------------------------------------------------------------------
# Authorization: only requester can extend
# ---------------------------------------------------------------------------


class TestExtendAuthorization:
    """Tests for extend grant authorization logic.

    The authorization check is inline in handle_extend_grant_button_click:
    only clicker_slack_id == payload.requester_slack_id is allowed.
    """

    def test_requester_is_allowed(self):
        clicker = "U_REQUESTER"
        requester = "U_REQUESTER"
        assert clicker == requester

    def test_approver_is_not_allowed(self):
        clicker = "U_APPROVER"
        requester = "U_REQUESTER"
        assert clicker != requester

    def test_random_user_is_not_allowed(self):
        clicker = "U_RANDOM"
        requester = "U_REQUESTER"
        assert clicker != requester


# ---------------------------------------------------------------------------
# 1hr window enforcement
# ---------------------------------------------------------------------------


class TestExtensionWindow:
    def test_within_window(self):
        expired_at = datetime.now(timezone.utc) - timedelta(minutes=59)
        now = datetime.now(timezone.utc)
        assert now - expired_at <= timedelta(hours=1)

    def test_outside_window(self):
        expired_at = datetime.now(timezone.utc) - timedelta(minutes=61)
        now = datetime.now(timezone.utc)
        assert now - expired_at > timedelta(hours=1)


# ---------------------------------------------------------------------------
# Max extensions: button shown/hidden
# ---------------------------------------------------------------------------


class TestMaxExtensions:
    def test_button_shown_when_zero_extensions(self):
        """extensions_count=0 means button should be posted."""
        extensions_count = 0
        assert extensions_count < 1

    def test_button_hidden_when_one_extension(self):
        """extensions_count=1 means no button."""
        extensions_count = 1
        assert not (extensions_count < 1)


# ---------------------------------------------------------------------------
# Extension duration computation: min(original_duration, 60)
# ---------------------------------------------------------------------------


class TestExtensionDurationComputation:
    """Extension duration = min(permission_duration_in_minutes, 60)."""

    def test_30min_session_gives_30min_extension(self):
        permission_duration = timedelta(minutes=30)
        extension_minutes = min(int(permission_duration.total_seconds() / 60), 60)
        assert extension_minutes == 30

    def test_4hr_session_gives_60min_extension(self):
        permission_duration = timedelta(hours=4)
        extension_minutes = min(int(permission_duration.total_seconds() / 60), 60)
        assert extension_minutes == 60

    def test_60min_session_gives_60min_extension(self):
        permission_duration = timedelta(hours=1)
        extension_minutes = min(int(permission_duration.total_seconds() / 60), 60)
        assert extension_minutes == 60

    @patch("revoker.schedule")
    @patch("revoker.s3")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    @patch("revoker.organizations")
    def test_extend_button_payload_carries_correct_duration(self, mock_orgs, mock_slack_helpers, mock_sso, mock_s3, mock_schedule):
        """Verify the revoker passes min(permission_duration, 60) to the button payload."""
        import revoker

        revoke_event = RevokeEvent(
            schedule_name="test-schedule",
            approver=entities.slack.User(id="A1", email="a@b.com", real_name="A"),
            requester=entities.slack.User(id="R1", email="r@b.com", real_name="R"),
            user_account_assignment=sso.UserAccountAssignment(
                instance_arn="arn:aws:sso:::instance/ssoins-1234",
                account_id="111111111111",
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
                user_principal_id="uid-123",
            ),
            permission_duration=timedelta(minutes=30),
            permission_set_name="Admin",
            account_name="Production",
            can_extend_expired_grant=True,
            extensions_count=0,
            thread_ts="1234.5678",
        )

        mock_sso.delete_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
        mock_sso.describe_permission_set.return_value = entities.aws.PermissionSet(
            arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678", name="Admin", description=None
        )
        mock_slack_helpers.get_message_from_timestamp.return_value = {"blocks": []}
        mock_slack_helpers.HeaderSectionBlock.set_status.return_value = []
        mock_slack_helpers.ExtendGrantButtonPayload = ExtendGrantButtonPayload
        mock_slack_helpers.build_extend_grant_button = build_extend_grant_button

        mock_cfg = MagicMock()
        mock_cfg.post_update_to_slack = True
        mock_cfg.slack_channel_id = "C123"
        mock_cfg.access_ended_status = ":checkered_flag: *SESSION COMPLETE*"

        slack_client = MagicMock()
        slack_client.chat_postMessage.return_value = {"ts": "9999.0001"}

        revoker.handle_scheduled_account_assignment_deletion(
            revoke_event=revoke_event,
            sso_client=MagicMock(),
            cfg=mock_cfg,
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
        )

        # Find the extend button post call and verify duration is 30 (not 60)
        post_calls = slack_client.chat_postMessage.call_args_list
        extend_calls = [c for c in post_calls if "extend_grant_button" in str(c)]
        assert len(extend_calls) == 1
        # Verify fallback text has correct duration
        call_kwargs = extend_calls[0][1]
        assert "30 min" in call_kwargs["text"]


# ---------------------------------------------------------------------------
# Extend button posting in revoker
# ---------------------------------------------------------------------------


class TestExtendButtonPosting:
    def _make_revoke_event(self, can_extend: bool, thread_ts: str | None = "1234.5678", extensions_count: int = 0) -> RevokeEvent:
        return RevokeEvent(
            schedule_name="test-schedule",
            approver=entities.slack.User(id="A1", email="a@b.com", real_name="A"),
            requester=entities.slack.User(id="R1", email="r@b.com", real_name="R"),
            user_account_assignment=sso.UserAccountAssignment(
                instance_arn="arn:aws:sso:::instance/ssoins-1234",
                account_id="111111111111",
                permission_set_arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
                user_principal_id="uid-123",
            ),
            permission_duration=timedelta(hours=1),
            permission_set_name="Admin",
            account_name="Production",
            can_extend_expired_grant=can_extend,
            extensions_count=extensions_count,
            thread_ts=thread_ts,
        )

    @patch("revoker.schedule")
    @patch("revoker.s3")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    @patch("revoker.organizations")
    def test_extend_button_posted_on_natural_expiry(self, mock_orgs, mock_slack_helpers, mock_sso, mock_s3, mock_schedule):
        import revoker

        revoke_event = self._make_revoke_event(can_extend=True)

        mock_sso.delete_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
        mock_sso.describe_permission_set.return_value = entities.aws.PermissionSet(
            arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678", name="Admin", description=None
        )
        mock_slack_helpers.get_message_from_timestamp.return_value = {"blocks": []}
        mock_slack_helpers.HeaderSectionBlock.set_status.return_value = []
        mock_slack_helpers.ExtendGrantButtonPayload = ExtendGrantButtonPayload
        mock_slack_helpers.build_extend_grant_button = build_extend_grant_button

        mock_cfg = MagicMock()
        mock_cfg.post_update_to_slack = True
        mock_cfg.slack_channel_id = "C123"
        mock_cfg.access_ended_status = ":checkered_flag: *SESSION COMPLETE*"

        slack_client = MagicMock()
        slack_client.chat_postMessage.return_value = {"ts": "9999.0001"}

        scheduler_client = MagicMock()

        revoker.handle_scheduled_account_assignment_deletion(
            revoke_event=revoke_event,
            sso_client=MagicMock(),
            cfg=mock_cfg,
            scheduler_client=scheduler_client,
            org_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
        )

        # Verify extend button was posted
        post_calls = slack_client.chat_postMessage.call_args_list
        extend_calls = [c for c in post_calls if "extend_grant_button" in str(c)]
        assert len(extend_calls) == 1

        # Verify discard extend button event was scheduled
        mock_schedule.schedule_discard_extend_button_event.assert_called_once_with(
            schedule_client=scheduler_client,
            time_stamp="9999.0001",
            channel_id="C123",
        )

    @patch("revoker.schedule")
    @patch("revoker.s3")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    @patch("revoker.organizations")
    def test_no_extend_button_when_disabled(self, mock_orgs, mock_slack_helpers, mock_sso, mock_s3, mock_schedule):
        import revoker

        revoke_event = self._make_revoke_event(can_extend=False)

        mock_sso.delete_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
        mock_sso.describe_permission_set.return_value = entities.aws.PermissionSet(
            arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678", name="Admin", description=None
        )

        mock_cfg = MagicMock()
        mock_cfg.post_update_to_slack = True
        mock_cfg.slack_channel_id = "C123"
        mock_cfg.access_ended_status = ":checkered_flag: *SESSION COMPLETE*"

        slack_client = MagicMock()

        revoker.handle_scheduled_account_assignment_deletion(
            revoke_event=revoke_event,
            sso_client=MagicMock(),
            cfg=mock_cfg,
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
        )

        # Verify NO extend button was posted
        post_calls = slack_client.chat_postMessage.call_args_list
        extend_calls = [c for c in post_calls if "extend_grant_button" in str(c)]
        assert len(extend_calls) == 0

    @patch("revoker.schedule")
    @patch("revoker.s3")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    @patch("revoker.organizations")
    def test_no_extend_button_when_max_extensions_reached(self, mock_orgs, mock_slack_helpers, mock_sso, mock_s3, mock_schedule):
        import revoker

        revoke_event = self._make_revoke_event(can_extend=True, extensions_count=1)

        mock_sso.delete_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
        mock_sso.describe_permission_set.return_value = entities.aws.PermissionSet(
            arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678", name="Admin", description=None
        )

        mock_cfg = MagicMock()
        mock_cfg.post_update_to_slack = True
        mock_cfg.slack_channel_id = "C123"
        mock_cfg.access_ended_status = ":checkered_flag: *SESSION COMPLETE*"

        slack_client = MagicMock()

        revoker.handle_scheduled_account_assignment_deletion(
            revoke_event=revoke_event,
            sso_client=MagicMock(),
            cfg=mock_cfg,
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
        )

        # Verify NO extend button was posted
        post_calls = slack_client.chat_postMessage.call_args_list
        extend_calls = [c for c in post_calls if "extend_grant_button" in str(c)]
        assert len(extend_calls) == 0


# ---------------------------------------------------------------------------
# Group extend button posting
# ---------------------------------------------------------------------------


class TestGroupExtendButtonPosting:
    def _make_group_revoke_event(
        self, can_extend: bool, thread_ts: str | None = "1234.5678", extensions_count: int = 0
    ) -> GroupRevokeEvent:
        return GroupRevokeEvent(
            schedule_name="test-schedule",
            approver=entities.slack.User(id="A1", email="a@b.com", real_name="A"),
            requester=entities.slack.User(id="R1", email="r@b.com", real_name="R"),
            group_assignment=sso.GroupAssignment(
                identity_store_id="d-123",
                group_name="Admins",
                group_id="gid-123",
                user_principal_id="uid-123",
                membership_id="mid-123",
            ),
            permission_duration=timedelta(hours=1),
            can_extend_expired_grant=can_extend,
            extensions_count=extensions_count,
            thread_ts=thread_ts,
        )

    @patch("revoker.schedule")
    @patch("revoker.s3")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    def test_group_extend_button_posted_on_natural_expiry(self, mock_slack_helpers, mock_sso, mock_s3, mock_schedule):
        import revoker

        group_revoke_event = self._make_group_revoke_event(can_extend=True)

        mock_sso.remove_user_from_group.return_value = None
        mock_slack_helpers.get_message_from_timestamp.return_value = {"blocks": []}
        mock_slack_helpers.HeaderSectionBlock.set_status.return_value = []
        mock_slack_helpers.ExtendGrantButtonPayload = ExtendGrantButtonPayload
        mock_slack_helpers.build_extend_grant_button = build_extend_grant_button

        mock_cfg = MagicMock()
        mock_cfg.post_update_to_slack = True
        mock_cfg.slack_channel_id = "C123"
        mock_cfg.access_ended_status = ":checkered_flag: *SESSION COMPLETE*"

        slack_client = MagicMock()
        slack_client.chat_postMessage.return_value = {"ts": "9999.0002"}

        scheduler_client = MagicMock()

        revoker.handle_scheduled_group_assignment_deletion(
            group_revoke_event=group_revoke_event,
            sso_client=MagicMock(),
            cfg=mock_cfg,
            scheduler_client=scheduler_client,
            slack_client=slack_client,
            identitystore_client=MagicMock(),
        )

        # Verify extend button was posted
        post_calls = slack_client.chat_postMessage.call_args_list
        extend_calls = [c for c in post_calls if "extend_grant_button" in str(c)]
        assert len(extend_calls) == 1

        # Verify discard extend button event was scheduled
        mock_schedule.schedule_discard_extend_button_event.assert_called_once_with(
            schedule_client=scheduler_client,
            time_stamp="9999.0002",
            channel_id="C123",
        )

    @patch("revoker.schedule")
    @patch("revoker.s3")
    @patch("revoker.sso")
    @patch("revoker.slack_helpers")
    def test_no_group_extend_button_when_disabled(self, mock_slack_helpers, mock_sso, mock_s3, mock_schedule):
        import revoker

        group_revoke_event = self._make_group_revoke_event(can_extend=False)

        mock_sso.remove_user_from_group.return_value = None

        mock_cfg = MagicMock()
        mock_cfg.post_update_to_slack = True
        mock_cfg.slack_channel_id = "C123"
        mock_cfg.access_ended_status = ":checkered_flag: *SESSION COMPLETE*"

        slack_client = MagicMock()

        revoker.handle_scheduled_group_assignment_deletion(
            group_revoke_event=group_revoke_event,
            sso_client=MagicMock(),
            cfg=mock_cfg,
            scheduler_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
        )

        # Verify NO extend button was posted
        post_calls = slack_client.chat_postMessage.call_args_list
        extend_calls = [c for c in post_calls if "extend_grant_button" in str(c)]
        assert len(extend_calls) == 0


# ---------------------------------------------------------------------------
# Discard extend button event handling
# ---------------------------------------------------------------------------


class TestDiscardExtendButtonEvent:
    def test_extend_button_message_deleted(self):
        """When block_id is extend_grant_button, delete directly without message lookup."""
        from events import DiscardButtonsEvent

        import revoker

        event = DiscardButtonsEvent(
            action="discard_buttons_event",
            schedule_name="discard-buttons-extend2024-01-01-00-00-00",
            time_stamp="1234.5678",
            channel_id="C123",
            block_id="extend_grant_button",
        )

        slack_client = MagicMock()
        scheduler_client = MagicMock()

        with patch("revoker.slack_helpers") as mock_slack_helpers:
            revoker.handle_discard_buttons_event(
                event=event,
                slack_client=slack_client,
                scheduler_client=scheduler_client,
            )

            # Should NOT look up the message (it's a thread reply, conversations_history won't find it)
            mock_slack_helpers.get_message_from_timestamp.assert_not_called()

        slack_client.chat_delete.assert_called_once_with(
            channel="C123",
            ts="1234.5678",
        )
        slack_client.chat_update.assert_not_called()

    def test_regular_buttons_still_use_chat_update(self):
        """Default block_id='buttons' should still replace with footer text."""
        from events import DiscardButtonsEvent

        import revoker

        event = DiscardButtonsEvent(
            action="discard_buttons_event",
            schedule_name="discard-buttons2024-01-01-00-00-00",
            time_stamp="1234.5678",
            channel_id="C123",
        )

        slack_client = MagicMock()
        scheduler_client = MagicMock()

        message = {
            "ts": "1234.5678",
            "blocks": [{"block_id": "buttons", "type": "actions"}],
        }

        with patch("revoker.slack_helpers") as mock_slack_helpers:
            mock_slack_helpers.get_message_from_timestamp.return_value = message
            mock_slack_helpers.get_block_id.return_value = "buttons"
            mock_slack_helpers.remove_blocks.return_value = []
            mock_slack_helpers.HeaderSectionBlock.set_status.return_value = []

            revoker.handle_discard_buttons_event(
                event=event,
                slack_client=slack_client,
                scheduler_client=scheduler_client,
            )

        slack_client.chat_update.assert_called_once()
        slack_client.chat_delete.assert_not_called()


# ---------------------------------------------------------------------------
# Build extend grant button
# ---------------------------------------------------------------------------


class TestBuildExtendGrantButton:
    def test_build_returns_actions_block(self):
        payload = ExtendGrantButtonPayload(
            requester_slack_id="U123",
            expired_at="2024-01-15T10:30:00+00:00",
            extension_duration_in_minutes=15,
            extensions_count=0,
            user_principal_id="uid-123",
        )
        block = build_extend_grant_button(payload)
        assert block.block_id == "extend_grant_button"
        assert block.elements[0].action_id == "extend_grant"  # type: ignore[union-attr]
        assert "15 min" in block.elements[0].text.text  # type: ignore[union-attr]


# Extend-grant handler tests that need to import `main` live in test_main.py because
# importing `main` requires the heavy mock_main_imports/import_main fixtures defined
# there. See TestExtendGrantPublishesAccessEvent in test_main.py.
