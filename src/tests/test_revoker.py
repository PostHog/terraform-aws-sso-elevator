"""Tests for revoker.py — inconsistency check."""

# ruff: noqa: ARG002

from unittest.mock import MagicMock, patch

import revoker
import sso


def _account_assignment(account_id: str = "111111111111") -> sso.AccountAssignment:
    return sso.AccountAssignment(
        account_id=account_id,
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-x",
        principal_id="user-x",
        principal_type="USER",
    )


def _group_assignment(group_id: str = "g-1") -> sso.GroupAssignment:
    return sso.GroupAssignment(
        group_name="g",
        group_id=group_id,
        user_principal_id="user-x",
        membership_id="m-1",
        identity_store_id="d-x",
    )


class TestAccountInconsistencyCheck:
    @patch("revoker._list_orphan_account_assignments")
    def test_returns_zero_and_does_not_alert_when_no_orphans(self, mock_list):
        mock_list.return_value = []
        slack_client = MagicMock()

        result = revoker.handle_check_on_inconsistency(
            sso_client=MagicMock(),
            cfg=MagicMock(),
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
            events_client=MagicMock(),
        )

        assert result == 0
        slack_client.chat_postMessage.assert_not_called()

    @patch("revoker.schedule")
    @patch("revoker.slack_helpers")
    @patch("revoker.organizations")
    @patch("revoker._list_orphan_account_assignments")
    def test_alerts_on_each_orphan(self, mock_list, mock_orgs, mock_slack_helpers, mock_schedule):
        mock_list.return_value = [_account_assignment("a"), _account_assignment("b")]
        mock_orgs.describe_account.return_value = MagicMock(id="a", name="acct")
        mock_slack_helpers.create_slack_mention_by_principal_id.return_value = "<@U1>"
        mock_schedule.get_event_bridge_rule.return_value = MagicMock()
        mock_schedule.check_rule_expression_and_get_next_run.return_value = None
        slack_client = MagicMock()
        cfg = MagicMock()
        cfg.slack_channel_id = "C1"

        result = revoker.handle_check_on_inconsistency(
            sso_client=MagicMock(),
            cfg=cfg,
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
            events_client=MagicMock(),
        )

        assert result == 2
        assert slack_client.chat_postMessage.call_count == 2
        first_text = slack_client.chat_postMessage.call_args_list[0].kwargs["text"]
        # Toned-down wording — should not include the alarming legacy phrasing.
        assert "Untracked SSO assignment" in first_text
        assert "outside Elevator" in first_text
        assert "Inconsistent" not in first_text
        assert "unidentified" not in first_text


class TestGroupInconsistencyCheck:
    @patch("revoker._list_orphan_group_assignments")
    def test_returns_zero_and_does_not_alert_when_no_orphans(self, mock_list):
        mock_list.return_value = []
        slack_client = MagicMock()

        result = revoker.check_on_groups_inconsistency(
            identity_store_client=MagicMock(),
            sso_client=MagicMock(),
            scheduler_client=MagicMock(),
            events_client=MagicMock(),
            cfg=MagicMock(),
            slack_client=slack_client,
        )

        assert result == 0
        slack_client.chat_postMessage.assert_not_called()

    @patch("revoker.schedule")
    @patch("revoker.slack_helpers")
    @patch("revoker._list_orphan_group_assignments")
    def test_alerts_on_each_orphan(self, mock_list, mock_slack_helpers, mock_schedule):
        mock_list.return_value = [_group_assignment("g1"), _group_assignment("g2")]
        mock_slack_helpers.create_slack_mention_by_principal_id.return_value = "<@U1>"
        mock_schedule.get_event_bridge_rule.return_value = MagicMock()
        mock_schedule.check_rule_expression_and_get_next_run.return_value = None
        slack_client = MagicMock()
        cfg = MagicMock()
        cfg.slack_channel_id = "C1"

        result = revoker.check_on_groups_inconsistency(
            identity_store_client=MagicMock(),
            sso_client=MagicMock(),
            scheduler_client=MagicMock(),
            events_client=MagicMock(),
            cfg=cfg,
            slack_client=slack_client,
        )

        assert result == 2
        assert slack_client.chat_postMessage.call_count == 2
        first_text = slack_client.chat_postMessage.call_args_list[0].kwargs["text"]
        assert "Untracked SSO group membership" in first_text
        assert "outside Elevator" in first_text
        assert "Inconsistent" not in first_text
        assert "unidentified" not in first_text
