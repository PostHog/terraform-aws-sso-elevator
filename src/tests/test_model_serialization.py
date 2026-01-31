"""Tests for model serialization, particularly handling frozensets with nested Pydantic models."""

from datetime import timedelta

import entities
import sso
from access_control import AccessRequestDecision, ApproveRequestDecision, DecisionReason
from events import (
    Event,
    GroupRevokeEvent,
    RevokeEvent,
    ScheduledGroupRevokeEvent,
    ScheduledRevokeEvent,
)
from statement import Statement, GroupStatement


class TestModelSerialization:
    """Test that Pydantic models can be serialized to dict without errors."""

    def test_access_request_decision_with_statements_dict_serialization(self):
        """Test that AccessRequestDecision.dict() works with frozenset of Statement objects."""
        statement = Statement.model_validate(
            {
                "resource_type": "Account",
                "resource": ["123456789012"],
                "permission_set": ["AdminAccess"],
                "approvers": ["approver@example.com"],
                "allow_self_approval": True,
            }
        )

        decision = AccessRequestDecision(
            grant=True,
            reason=DecisionReason.SelfApproval,
            based_on_statements=frozenset([statement]),
            approvers=frozenset(["approver@example.com"]),
        )

        # This should not raise TypeError: unhashable type: 'dict'
        result = decision.dict()

        assert isinstance(result, dict)
        assert result["grant"] is True
        assert result["reason"] == DecisionReason.SelfApproval.value
        assert "based_on_statements" in result
        # Frozensets are converted to lists for JSON serialization
        assert isinstance(result["based_on_statements"], list)
        assert len(result["based_on_statements"]) == 1

    def test_approve_request_decision_with_statements_dict_serialization(self):
        """Test that ApproveRequestDecision.dict() works with frozenset of Statement objects."""
        statement = Statement.model_validate(
            {
                "resource_type": "Account",
                "resource": ["123456789012"],
                "permission_set": ["AdminAccess"],
                "approvers": ["approver@example.com"],
                "allow_self_approval": False,
            }
        )

        decision = ApproveRequestDecision(
            grant=True,
            permit=True,
            based_on_statements=frozenset([statement]),
        )

        # This should not raise TypeError: unhashable type: 'dict'
        result = decision.dict()

        assert isinstance(result, dict)
        assert result["grant"] is True
        assert result["permit"] is True
        assert "based_on_statements" in result
        assert isinstance(result["based_on_statements"], list)
        assert len(result["based_on_statements"]) == 1

    def test_access_request_decision_with_group_statements_dict_serialization(self):
        """Test that AccessRequestDecision.dict() works with frozenset of GroupStatement objects."""
        group_statement = GroupStatement.model_validate(
            {
                "resource": ["11111111-2222-3333-4444-555555555555"],
                "approvers": ["approver@example.com"],
                "allow_self_approval": True,
            }
        )

        decision = AccessRequestDecision(
            grant=False,
            reason=DecisionReason.RequiresApproval,
            based_on_statements=frozenset([group_statement]),
            approvers=frozenset(["approver@example.com"]),
        )

        # This should not raise TypeError: unhashable type: 'dict'
        result = decision.dict()

        assert isinstance(result, dict)
        assert result["grant"] is False
        assert result["reason"] == DecisionReason.RequiresApproval.value
        assert "based_on_statements" in result
        assert isinstance(result["based_on_statements"], list)
        assert len(result["based_on_statements"]) == 1

    def test_access_request_decision_with_multiple_statements(self):
        """Test serialization with multiple statements in the frozenset."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["123456789012"],
                        "permission_set": ["AdminAccess"],
                        "approvers": ["approver1@example.com"],
                        "allow_self_approval": True,
                    }
                ),
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["987654321098"],
                        "permission_set": ["ReadOnlyAccess"],
                        "approvers": ["approver2@example.com"],
                        "allow_self_approval": False,
                    }
                ),
            ]
        )

        decision = AccessRequestDecision(
            grant=False,
            reason=DecisionReason.RequiresApproval,
            based_on_statements=statements,
            approvers=frozenset(["approver1@example.com", "approver2@example.com"]),
        )

        # This should not raise TypeError: unhashable type: 'dict'
        result = decision.dict()

        assert isinstance(result, dict)
        assert isinstance(result["based_on_statements"], list)
        assert len(result["based_on_statements"]) == 2
        assert isinstance(result["approvers"], list)
        assert len(result["approvers"]) == 2

    def test_statement_dict_serialization(self):
        """Test that Statement.dict() works correctly."""
        statement = Statement.model_validate(
            {
                "resource_type": "Account",
                "resource": ["123456789012", "*"],
                "permission_set": ["AdminAccess", "PowerUserAccess"],
                "approvers": ["approver@example.com", "admin@example.com"],
                "allow_self_approval": True,
                "approval_is_not_required": False,
            }
        )

        result = statement.dict()

        assert isinstance(result, dict)
        assert result["resource_type"] == "Account"
        assert isinstance(result["resource"], list)
        assert isinstance(result["permission_set"], list)
        assert isinstance(result["approvers"], list)
        assert result["allow_self_approval"] is True
        assert result["approval_is_not_required"] is False

    def test_group_statement_dict_serialization(self):
        """Test that GroupStatement.dict() works correctly."""
        group_statement = GroupStatement.model_validate(
            {
                "resource": ["11111111-2222-3333-4444-555555555555"],
                "approvers": ["approver@example.com"],
                "allow_self_approval": False,
                "approval_is_not_required": True,
            }
        )

        result = group_statement.dict()

        assert isinstance(result, dict)
        assert isinstance(result["resource"], list)
        assert isinstance(result["approvers"], list)
        assert result["allow_self_approval"] is False
        assert result["approval_is_not_required"] is True


class TestRevokeEventSerialization:
    """Test that RevokeEvent and GroupRevokeEvent serialize thread_ts correctly through EventBridge payload."""

    def _sample_user(self):
        return entities.slack.User(email="user@example.com", id="U123", real_name="Test User")

    def _sample_user_account_assignment(self):
        return sso.UserAccountAssignment(
            instance_arn="arn:aws:sso:::instance/ssoins-123",
            account_id="123456789012",
            permission_set_arn="arn:aws:sso:::permissionSet/ssoins-123/ps-123",
            user_principal_id="user-principal-123",
        )

    def _sample_group_assignment(self):
        return sso.GroupAssignment(
            identity_store_id="d-123456789",
            group_name="TestGroup",
            group_id="group-123",
            user_principal_id="user-principal-123",
            membership_id="membership-123",
        )

    def test_revoke_event_with_thread_ts_json_roundtrip(self):
        """Test RevokeEvent preserves thread_ts through JSON serialization (EventBridge payload)."""
        event = RevokeEvent(
            schedule_name="test-schedule",
            approver=self._sample_user(),
            requester=self._sample_user(),
            user_account_assignment=self._sample_user_account_assignment(),
            permission_duration=timedelta(hours=1),
            thread_ts="1234567890.123456",
        )

        # Serialize to JSON (mimics EventBridge payload)
        json_str = event.json()

        # Deserialize back
        restored = RevokeEvent.model_validate_json(json_str)

        assert restored.thread_ts == "1234567890.123456"

    def test_revoke_event_without_thread_ts_backward_compat(self):
        """Test RevokeEvent works without thread_ts (older scheduled jobs)."""
        # JSON without thread_ts field (simulates older scheduled jobs)
        event = RevokeEvent(
            schedule_name="test-schedule",
            approver=self._sample_user(),
            requester=self._sample_user(),
            user_account_assignment=self._sample_user_account_assignment(),
            permission_duration=timedelta(hours=1),
        )

        json_str = event.json()
        restored = RevokeEvent.model_validate_json(json_str)

        assert restored.thread_ts is None

    def test_group_revoke_event_with_thread_ts_json_roundtrip(self):
        """Test GroupRevokeEvent preserves thread_ts through JSON serialization."""
        event = GroupRevokeEvent(
            schedule_name="test-schedule",
            approver=self._sample_user(),
            requester=self._sample_user(),
            group_assignment=self._sample_group_assignment(),
            permission_duration=timedelta(hours=1),
            thread_ts="1234567890.654321",
        )

        json_str = event.json()
        restored = GroupRevokeEvent.model_validate_json(json_str)

        assert restored.thread_ts == "1234567890.654321"

    def test_group_revoke_event_without_thread_ts_backward_compat(self):
        """Test GroupRevokeEvent works without thread_ts (older scheduled jobs)."""
        event = GroupRevokeEvent(
            schedule_name="test-schedule",
            approver=self._sample_user(),
            requester=self._sample_user(),
            group_assignment=self._sample_group_assignment(),
            permission_duration=timedelta(hours=1),
        )

        json_str = event.json()
        restored = GroupRevokeEvent.model_validate_json(json_str)

        assert restored.thread_ts is None

    def test_scheduled_revoke_event_parses_thread_ts_from_nested_json(self):
        """Test ScheduledRevokeEvent model_validator preserves thread_ts from JSON string."""
        revoke_event = RevokeEvent(
            schedule_name="test-schedule",
            approver=self._sample_user(),
            requester=self._sample_user(),
            user_account_assignment=self._sample_user_account_assignment(),
            permission_duration=timedelta(hours=1),
            thread_ts="1234567890.999999",
        )

        # This mimics the EventBridge payload structure where revoke_event is a JSON string
        payload = {
            "action": "event_bridge_revoke",
            "revoke_event": revoke_event.json(),
        }

        # Parse using Event (the root model used in revoker.py)
        parsed = Event.model_validate(payload)

        assert isinstance(parsed.root, ScheduledRevokeEvent)
        assert parsed.root.revoke_event.thread_ts == "1234567890.999999"

    def test_scheduled_group_revoke_event_parses_thread_ts_from_nested_json(self):
        """Test ScheduledGroupRevokeEvent model_validator preserves thread_ts from JSON string."""
        group_revoke_event = GroupRevokeEvent(
            schedule_name="test-schedule",
            approver=self._sample_user(),
            requester=self._sample_user(),
            group_assignment=self._sample_group_assignment(),
            permission_duration=timedelta(hours=1),
            thread_ts="1234567890.111111",
        )

        # This mimics the EventBridge payload structure
        payload = {
            "action": "event_bridge_group_revoke",
            "revoke_event": group_revoke_event.json(),
        }

        parsed = Event.model_validate(payload)

        assert isinstance(parsed.root, ScheduledGroupRevokeEvent)
        assert parsed.root.revoke_event.thread_ts == "1234567890.111111"
