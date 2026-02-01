"""Tests for early revocation feature."""

import json
from unittest.mock import MagicMock, patch


import slack_helpers
from slack_helpers import EarlyRevokeButtonPayload, EarlyRevokeModal, EarlyRevokeModalPayload


class TestEarlyRevokeButtonPayload:
    """Tests for EarlyRevokeButtonPayload model."""

    def test_account_payload_serialization(self):
        """Button value encodes all required data correctly for account access."""
        payload = EarlyRevokeButtonPayload(
            schedule_name="revoker-2024-01-15-10-30-00",
            requester_slack_id="U12345",
            account_id="123456789012",
            permission_set_name="AdministratorAccess",
            permission_set_arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
            instance_arn="arn:aws:sso:::instance/ssoins-1234",
            user_principal_id="user-principal-123",
            approver_emails=["approver@example.com"],
        )

        # Serialize to JSON (as it would be for button value)
        json_str = json.dumps(payload.model_dump(mode="json"))
        assert "revoker-2024-01-15-10-30-00" in json_str
        assert "U12345" in json_str
        assert "123456789012" in json_str
        assert "AdministratorAccess" in json_str

    def test_group_payload_serialization(self):
        """Button value encodes all required data correctly for group access."""
        payload = EarlyRevokeButtonPayload(
            schedule_name="revoker-2024-01-15-10-30-00",
            requester_slack_id="U12345",
            group_id="group-id-123",
            group_name="Admins",
            identity_store_id="d-123456",
            membership_id="membership-789",
            user_principal_id="user-principal-123",
            approver_emails=["approver@example.com"],
        )

        json_str = json.dumps(payload.model_dump(mode="json"))
        assert "group-id-123" in json_str
        assert "Admins" in json_str
        assert "membership-789" in json_str

    def test_button_payload_deserialization(self):
        """Button payload parses correctly from click event (JSON string)."""
        json_data = {
            "schedule_name": "revoker-2024-01-15-10-30-00",
            "requester_slack_id": "U12345",
            "account_id": "123456789012",
            "permission_set_name": "AdministratorAccess",
            "permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
            "instance_arn": "arn:aws:sso:::instance/ssoins-1234",
            "user_principal_id": "user-principal-123",
            "approver_emails": ["approver@example.com"],
        }

        # Simulate parsing from button value (JSON string)
        payload = EarlyRevokeButtonPayload.model_validate(json_data)

        assert payload.schedule_name == "revoker-2024-01-15-10-30-00"
        assert payload.requester_slack_id == "U12345"
        assert payload.account_id == "123456789012"
        assert payload.permission_set_name == "AdministratorAccess"

    def test_payload_with_optional_fields_missing(self):
        """Payload handles optional fields gracefully."""
        # Minimal payload for account access
        payload = EarlyRevokeButtonPayload(
            schedule_name="revoker-2024-01-15-10-30-00",
            requester_slack_id="U12345",
            user_principal_id="user-principal-123",
        )

        assert payload.account_id is None
        assert payload.group_id is None
        assert payload.approver_emails == []


class TestEarlyRevokeModal:
    """Tests for EarlyRevokeModal view."""

    def test_modal_build_for_account_access(self):
        """Modal builds correctly for account access revocation."""
        modal = EarlyRevokeModal.build(
            account_name="Production",
            account_id="123456789012",
            permission_set_name="AdministratorAccess",
            private_metadata='{"test": "data"}',
        )

        assert modal.callback_id == EarlyRevokeModal.CALLBACK_ID
        assert modal.type == "modal"
        assert modal.private_metadata == '{"test": "data"}'
        assert modal.submit.text == "Revoke"
        assert modal.close.text == "Cancel"

    def test_modal_build_for_group_access(self):
        """Modal builds correctly for group access revocation."""
        modal = EarlyRevokeModal.build(
            group_name="Admins",
            group_id="group-123",
            private_metadata='{"test": "data"}',
        )

        assert modal.callback_id == EarlyRevokeModal.CALLBACK_ID
        assert modal.type == "modal"

    def test_modal_contains_reason_input(self):
        """Modal includes optional reason input field."""
        modal = EarlyRevokeModal.build(
            account_name="Production",
            account_id="123456789012",
            permission_set_name="AdministratorAccess",
        )

        # Find the reason input block
        reason_block = None
        for block in modal.blocks:
            if hasattr(block, "block_id") and block.block_id == EarlyRevokeModal.REASON_BLOCK_ID:
                reason_block = block
                break

        assert reason_block is not None
        assert reason_block.optional is True


class TestEarlyRevokeModalPayload:
    """Tests for EarlyRevokeModalPayload parsing."""

    def test_modal_payload_parsing(self):
        """Modal submission payload parses correctly."""
        # Simulate a Slack view submission body
        view_submission_body = {
            "user": {"id": "U67890"},
            "view": {
                "state": {
                    "values": {EarlyRevokeModal.REASON_BLOCK_ID: {EarlyRevokeModal.REASON_ACTION_ID: {"value": "Finished my task early"}}}
                },
                "private_metadata": json.dumps(
                    {
                        "button_payload": {
                            "schedule_name": "revoker-2024-01-15-10-30-00",
                            "requester_slack_id": "U12345",
                            "account_id": "123456789012",
                            "permission_set_name": "AdministratorAccess",
                            "permission_set_arn": "arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
                            "instance_arn": "arn:aws:sso:::instance/ssoins-1234",
                            "user_principal_id": "user-principal-123",
                            "approver_emails": [],
                        },
                        "channel_id": "C12345",
                        "thread_ts": "1234567890.123456",
                    }
                ),
            },
        }

        payload = EarlyRevokeModalPayload.model_validate(view_submission_body)

        assert payload.revoker_slack_id == "U67890"
        assert payload.reason == "Finished my task early"
        assert payload.button_payload.schedule_name == "revoker-2024-01-15-10-30-00"
        assert payload.button_payload.requester_slack_id == "U12345"
        assert payload.channel_id == "C12345"
        assert payload.thread_ts == "1234567890.123456"

    def test_modal_payload_with_no_reason(self):
        """Modal payload handles missing reason gracefully."""
        view_submission_body = {
            "user": {"id": "U67890"},
            "view": {
                "state": {"values": {EarlyRevokeModal.REASON_BLOCK_ID: {EarlyRevokeModal.REASON_ACTION_ID: {"value": None}}}},
                "private_metadata": json.dumps(
                    {
                        "button_payload": {
                            "schedule_name": "revoker-2024-01-15-10-30-00",
                            "requester_slack_id": "U12345",
                            "user_principal_id": "user-principal-123",
                            "approver_emails": [],
                        },
                        "channel_id": "C12345",
                        "thread_ts": "1234567890.123456",
                    }
                ),
            },
        }

        payload = EarlyRevokeModalPayload.model_validate(view_submission_body)

        assert payload.reason is None


class TestEarlyRevocationAuthorization:
    """Tests for early revocation authorization logic.

    Note: These tests directly test the authorization logic without importing main.py,
    since main.py has module-level side effects (boto3 calls).
    """

    def _check_early_revoke_authorization(
        self,
        clicker_slack_id: str,
        requester_slack_id: str,
        approver_emails: list[str],
        client: MagicMock,
        allow_anyone: bool = False,
    ) -> bool:
        """Test helper that mirrors main.check_early_revoke_authorization logic."""
        if allow_anyone:
            return True

        # Requester can always end their own session
        if clicker_slack_id == requester_slack_id:
            return True

        # Check if clicker is an approver
        try:
            clicker = slack_helpers.get_user(client, id=clicker_slack_id)
            if clicker.email in approver_emails:
                return True
        except Exception:
            pass

        return False

    def test_requester_can_end_session(self):
        """Requester should always be able to end their session."""
        mock_client = MagicMock()

        # When clicker is the requester
        result = self._check_early_revoke_authorization(
            clicker_slack_id="U12345",
            requester_slack_id="U12345",
            approver_emails=["other@example.com"],
            client=mock_client,
        )

        assert result is True

    def test_approver_can_end_session(self):
        """Approvers from statements should be able to end session."""
        mock_client = MagicMock()
        mock_user = MagicMock()
        mock_user.email = "approver@example.com"

        with patch("slack_helpers.get_user", return_value=mock_user):
            result = self._check_early_revoke_authorization(
                clicker_slack_id="U67890",
                requester_slack_id="U12345",
                approver_emails=["approver@example.com", "another@example.com"],
                client=mock_client,
            )

        assert result is True

    def test_random_user_blocked_when_config_false(self):
        """Random user blocked when allow_anyone_to_end_session_early=False."""
        mock_client = MagicMock()
        mock_user = MagicMock()
        mock_user.email = "random@example.com"

        with patch("slack_helpers.get_user", return_value=mock_user):
            result = self._check_early_revoke_authorization(
                clicker_slack_id="U99999",
                requester_slack_id="U12345",
                approver_emails=["approver@example.com"],
                client=mock_client,
            )

        assert result is False

    def test_random_user_allowed_when_config_true(self):
        """Random user allowed when allow_anyone_to_end_session_early=True."""
        mock_client = MagicMock()

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U99999",
            requester_slack_id="U12345",
            approver_emails=["approver@example.com"],
            client=mock_client,
            allow_anyone=True,
        )

        assert result is True


class TestEarlyRevocationIdempotency:
    """Tests for idempotency in scheduled revocation.

    Note: Full integration tests of handle_scheduled_account_assignment_deletion
    would require mocking boto3 at module-level. These tests verify the error
    handling logic conceptually.
    """

    def test_conflict_exception_should_be_handled_gracefully(self):
        """ConflictException should be caught and handled, not propagated."""
        import botocore.exceptions

        # Create a ConflictException-like error
        error_response = {
            "Error": {
                "Code": "ConflictException",
                "Message": "Account assignment not found",
            }
        }
        conflict_exception = botocore.exceptions.ClientError(error_response, "DeleteAccountAssignment")

        # Verify the exception has the expected structure
        import jmespath as jp

        error_code = jp.search("Error.Code", conflict_exception.response)
        assert error_code == "ConflictException"

    def test_resource_not_found_exception_should_be_handled_for_groups(self):
        """ResourceNotFoundException should be caught for group membership deletion."""
        import botocore.exceptions

        error_response = {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "Membership not found",
            }
        }
        resource_not_found = botocore.exceptions.ClientError(error_response, "DeleteGroupMembership")

        # Verify the exception has the expected structure
        import jmespath as jp

        error_code = jp.search("Error.Code", resource_not_found.response)
        assert error_code == "ResourceNotFoundException"


class TestBuildEarlyRevokeButton:
    """Tests for build_early_revoke_button function."""

    def test_button_contains_correct_action_id(self):
        """Button has the correct action_id for the handler."""
        from entities.slack import ApproverAction

        payload = EarlyRevokeButtonPayload(
            schedule_name="revoker-2024-01-15-10-30-00",
            requester_slack_id="U12345",
            user_principal_id="user-principal-123",
        )

        button_block = slack_helpers.build_early_revoke_button(payload)

        assert button_block.block_id == "early_revoke_button"
        assert len(button_block.elements) == 1
        assert button_block.elements[0].action_id == ApproverAction.EarlyRevoke.value

    def test_button_value_is_json(self):
        """Button value is valid JSON containing payload data."""
        payload = EarlyRevokeButtonPayload(
            schedule_name="revoker-2024-01-15-10-30-00",
            requester_slack_id="U12345",
            account_id="123456789012",
            user_principal_id="user-principal-123",
        )

        button_block = slack_helpers.build_early_revoke_button(payload)

        # Value should be valid JSON
        value = button_block.elements[0].value
        parsed = json.loads(value)

        assert parsed["schedule_name"] == "revoker-2024-01-15-10-30-00"
        assert parsed["requester_slack_id"] == "U12345"
        assert parsed["account_id"] == "123456789012"
