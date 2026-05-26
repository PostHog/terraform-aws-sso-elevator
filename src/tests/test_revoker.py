"""Tests for revoker.py — inconsistency check + concurrent-revoke handling."""

# ruff: noqa: ARG002

from unittest.mock import MagicMock, patch

import botocore.exceptions

import entities
import revoker
import sso


def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "boom"}},  # type: ignore[arg-type]
        "SomeOperation",
    )


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


class TestConcurrentEarlyGroupRevocation:
    """handle_early_group_revocation must short-circuit on ConflictException (another
    revoker is already deleting the membership) and on ResourceNotFoundException (the
    membership is already gone) — same shape as the account-side handler."""

    def _group_assignment(self) -> sso.GroupAssignment:
        return sso.GroupAssignment(group_name="g", group_id="g-1", user_principal_id="u-1", membership_id="m-1", identity_store_id="d-1")

    @patch("revoker.sso.remove_user_from_group", side_effect=_client_error("ConflictException"))
    def test_conflict_exception_returns_none_without_raising(self, mock_remove):
        result = revoker.handle_early_group_revocation(
            group_assignment=self._group_assignment(),
            schedule_name="sched-1",
            revoker_slack_id="U_REV",
            requester_slack_id="U_REQ",
            reason=None,
            sso_client=MagicMock(),
            scheduler_client=MagicMock(),
            slack_client=MagicMock(),
            identitystore_client=MagicMock(),
            cfg=MagicMock(),
            thread_ts="t1",
        )
        assert result is None

    @patch("revoker.s3.log_operation")
    @patch("revoker.slack_helpers")
    @patch("revoker.schedule.delete_schedule")
    @patch("revoker.sso.remove_user_from_group", side_effect=_client_error("ResourceNotFoundException"))
    def test_resource_not_found_proceeds_as_already_revoked(self, mock_remove, mock_del, mock_slack, mock_log):
        mock_slack.get_user.return_value = MagicMock(id="U_REV", email="r@r")
        mock_slack.get_message_from_timestamp.return_value = None  # skips chat_update branch
        cfg = MagicMock()
        cfg.post_update_to_slack = True
        cfg.slack_channel_id = "C1"
        slack_client = MagicMock()

        revoker.handle_early_group_revocation(
            group_assignment=self._group_assignment(),
            schedule_name="sched-1",
            revoker_slack_id="U_REV",
            requester_slack_id="U_REQ",
            reason=None,
            sso_client=MagicMock(),
            scheduler_client=MagicMock(),
            slack_client=slack_client,
            identitystore_client=MagicMock(),
            cfg=cfg,
            thread_ts="t1",
        )

        # Schedule cleanup and audit log STILL run on the already-revoked path.
        mock_del.assert_called_once()
        mock_log.assert_called_once()
        text = slack_client.chat_postMessage.call_args.kwargs["text"]
        assert "already was revoked" in text or "already revoked" in text


class TestConcurrentScheduledGroupDeletion:
    @patch("revoker.s3.log_operation")
    @patch("revoker.schedule.delete_schedule")
    @patch("revoker.sso.remove_user_from_group", side_effect=_client_error("ConflictException"))
    def test_conflict_short_circuits_without_audit_or_schedule_delete(self, mock_remove, mock_del, mock_log):
        from datetime import timedelta

        from events import GroupRevokeEvent

        revoke_event = GroupRevokeEvent(
            schedule_name="sched-g-1",
            approver=entities.slack.User(id="U_A", email="a@a", real_name="A"),
            requester=entities.slack.User(id="U_R", email="r@r", real_name="R"),
            group_assignment=sso.GroupAssignment(
                group_name="g", group_id="g-1", user_principal_id="u-1", membership_id="m-1", identity_store_id="d-1"
            ),
            permission_duration=timedelta(hours=1),
        )

        result = revoker.handle_scheduled_group_assignment_deletion(
            group_revoke_event=revoke_event,
            sso_client=MagicMock(),
            cfg=MagicMock(),
            scheduler_client=MagicMock(),
            slack_client=MagicMock(),
            identitystore_client=MagicMock(),
        )

        assert result is None
        # Conflict means another invocation owns the cleanup — don't double-audit and don't
        # touch the schedule (the winning invocation will delete it).
        mock_log.assert_not_called()
        mock_del.assert_not_called()


class TestSchedulerSweepKeepsGoingOnError:
    """The daily revocation sweep must NOT abort just because one assignment hits a race
    condition — remaining assignments should still get processed."""

    def _make_assignment(self, account_id: str) -> sso.AccountAssignment:
        return sso.AccountAssignment(
            account_id=account_id,
            permission_set_arn="arn:aws:sso:::permissionSet/ssoins-x/ps-x",
            principal_id="u-1",
            principal_type="USER",
        )

    @patch("revoker.handle_account_assignment_deletion")
    @patch("revoker.schedule.get_scheduled_events", return_value=[])
    @patch("revoker.sso.get_account_assignment_information")
    def test_conflict_on_one_assignment_does_not_abort_remaining(self, mock_get_assignments, mock_get_scheduled, mock_handle):
        a1 = self._make_assignment("111111111111")
        a2 = self._make_assignment("222222222222")
        a3 = self._make_assignment("333333333333")
        mock_get_assignments.return_value = [a1, a2, a3]
        # Middle assignment hits a concurrent-revoke conflict.
        mock_handle.side_effect = [None, _client_error("ConflictException"), None]
        cfg = MagicMock()
        cfg.sso_instance_arn = "arn:aws:sso:::instance/ssoins-x"

        revoker.handle_sso_elevator_scheduled_revocation(
            sso_client=MagicMock(),
            cfg=cfg,
            scheduler_client=MagicMock(),
            org_client=MagicMock(),
            slack_client=MagicMock(),
            identitystore_client=MagicMock(),
        )

        # All three assignments were attempted — the middle one's failure didn't stop the sweep.
        assert mock_handle.call_count == 3

    @patch("revoker.s3.log_operation")
    @patch("revoker.sso.remove_user_from_group")
    @patch("revoker.schedule.get_scheduled_events", return_value=[])
    @patch("revoker.sso.get_group_assignments")
    @patch("revoker.sso.get_identity_store_id", return_value="d-1")
    def test_group_sweep_continues_on_conflict_per_assignment(
        self, mock_idstore, mock_get_groups, mock_get_scheduled, mock_remove, mock_log
    ):
        g1 = sso.GroupAssignment(group_name="g1", group_id="g-1", user_principal_id="u-1", membership_id="m-1", identity_store_id="d-1")
        g2 = sso.GroupAssignment(group_name="g2", group_id="g-2", user_principal_id="u-1", membership_id="m-2", identity_store_id="d-1")
        g3 = sso.GroupAssignment(group_name="g3", group_id="g-3", user_principal_id="u-1", membership_id="m-3", identity_store_id="d-1")
        mock_get_groups.return_value = [g1, g2, g3]
        mock_remove.side_effect = [None, _client_error("ConflictException"), None]
        cfg = MagicMock()
        cfg.post_update_to_slack = False

        revoker.handle_sso_elevator_group_scheduled_revocation(
            identity_store_client=MagicMock(),
            sso_client=MagicMock(),
            scheduler_client=MagicMock(),
            cfg=cfg,
            slack_client=MagicMock(),
        )

        assert mock_remove.call_count == 3
        # Conflict assignment must NOT generate an audit entry; the other two must.
        assert mock_log.call_count == 2
