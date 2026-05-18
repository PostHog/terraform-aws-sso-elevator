"""Tests for schedule name generation, ConflictException retry, and supersession."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

import entities
import schedule
import sso
from events import GroupRevokeEvent, RevokeEvent, ScheduledGroupRevokeEvent, ScheduledRevokeEvent


def _make_user(slack_id: str = "U1", email: str = "alice@example.com") -> entities.slack.User:
    return entities.slack.User(id=slack_id, email=email, real_name="Alice")


def _make_account_assignment(
    account_id: str = "111111111111",
    permission_set_arn: str = "arn:aws:sso:::permissionSet/ssoins-x/ps-y",
    user_principal_id: str = "u-1",
    instance_arn: str = "arn:aws:sso:::instance/ssoins-x",
) -> sso.UserAccountAssignment:
    return sso.UserAccountAssignment(
        instance_arn=instance_arn,
        account_id=account_id,
        permission_set_arn=permission_set_arn,
        user_principal_id=user_principal_id,
    )


def _make_group_assignment(
    group_id: str = "g-1",
    group_name: str = "developers",
    user_principal_id: str = "u-1",
    membership_id: str = "m-1",
    identity_store_id: str = "d-x",
) -> sso.GroupAssignment:
    return sso.GroupAssignment(
        group_name=group_name,
        group_id=group_id,
        user_principal_id=user_principal_id,
        membership_id=membership_id,
        identity_store_id=identity_store_id,
    )


def _make_scheduled_revoke_event(
    assignment: sso.UserAccountAssignment,
    schedule_name: str = "sched-1",
    thread_ts: str | None = "1700000000.123456",
) -> ScheduledRevokeEvent:
    return ScheduledRevokeEvent(
        action="event_bridge_revoke",
        revoke_event=RevokeEvent(
            schedule_name=schedule_name,
            approver=_make_user(),
            requester=_make_user(),
            user_account_assignment=assignment,
            permission_duration=timedelta(hours=4),
            thread_ts=thread_ts,
        ),
    )


def _make_scheduled_group_revoke_event(
    assignment: sso.GroupAssignment,
    schedule_name: str = "sched-g-1",
    thread_ts: str | None = "1700000000.123456",
) -> ScheduledGroupRevokeEvent:
    return ScheduledGroupRevokeEvent(
        action="event_bridge_group_revoke",
        revoke_event=GroupRevokeEvent(
            schedule_name=schedule_name,
            approver=_make_user(),
            requester=_make_user(),
            group_assignment=assignment,
            permission_duration=timedelta(hours=4),
            thread_ts=thread_ts,
        ),
    )


class TestScheduleNameBuilder:
    def test_consecutive_calls_in_same_second_yield_unique_names(self):
        """UUID suffix makes same-second collisions statistically impossible."""
        frozen = "2026-04-21-17-11-01"
        fake_now = MagicMock()
        fake_now.strftime.return_value = frozen

        with patch("schedule.datetime") as mock_datetime:
            mock_datetime.now.return_value = fake_now
            name_a = schedule._build_schedule_name("sso-elevator-revoker")
            name_b = schedule._build_schedule_name("sso-elevator-revoker")

        assert name_a != name_b
        assert name_a.startswith(f"sso-elevator-revoker{frozen}-")
        assert name_b.startswith(f"sso-elevator-revoker{frozen}-")

    def test_name_length_stays_under_aws_cap(self):
        """AWS EventBridge schedule names max at 64 chars."""
        name = schedule._build_schedule_name("sso-elevator-revoker")
        assert len(name) <= 64


class TestCreateScheduleWithRetry:
    def _make_kwargs(self):
        return {
            "ActionAfterCompletion": "DELETE",
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "GroupName": "grp",
            "ScheduleExpression": "at(2026-04-21T17:11:01)",
            "State": "ENABLED",
            "Target": {"Arn": "arn:x", "RoleArn": "arn:r", "Input": ""},
        }

    def _conflict_error(self):
        return botocore.exceptions.ClientError(
            {"Error": {"Code": "ConflictException", "Message": "Schedule already exists"}},  # type: ignore[arg-type]
            "CreateSchedule",
        )

    def test_success_on_first_attempt(self):
        client = MagicMock()
        client.create_schedule.return_value = {"ScheduleArn": "arn:s"}

        build_input = MagicMock(return_value='{"k":"v"}')
        result, name = schedule._create_schedule_with_retry(
            client, name_prefix="pfx", build_input=build_input, create_kwargs=self._make_kwargs()
        )

        assert result == {"ScheduleArn": "arn:s"}
        assert name.startswith("pfx")
        client.create_schedule.assert_called_once()
        # Input is populated from build_input with the actual name used.
        call_kwargs = client.create_schedule.call_args.kwargs
        assert call_kwargs["Name"] == name
        assert call_kwargs["Target"]["Input"] == '{"k":"v"}'
        build_input.assert_called_once_with(name)

    def test_retries_on_conflict_then_succeeds(self):
        client = MagicMock()
        client.create_schedule.side_effect = [self._conflict_error(), {"ScheduleArn": "arn:s"}]

        build_input = MagicMock(side_effect=lambda n: f'{{"name":"{n}"}}')
        result, name = schedule._create_schedule_with_retry(
            client, name_prefix="pfx", build_input=build_input, create_kwargs=self._make_kwargs()
        )

        assert result == {"ScheduleArn": "arn:s"}
        assert client.create_schedule.call_count == 2
        # Both attempts used distinct names (fresh roll per retry).
        call_names = [c.kwargs["Name"] for c in client.create_schedule.call_args_list]
        assert call_names[0] != call_names[1]
        # Winning input embeds the winning name.
        assert client.create_schedule.call_args_list[1].kwargs["Target"]["Input"] == f'{{"name":"{name}"}}'

    def test_exhausts_retries_and_raises(self):
        client = MagicMock()
        client.create_schedule.side_effect = [self._conflict_error()] * 3
        build_input = MagicMock(return_value='{"k":"v"}')

        with pytest.raises(RuntimeError, match="after 3 attempts"):
            schedule._create_schedule_with_retry(client, name_prefix="pfx", build_input=build_input, create_kwargs=self._make_kwargs())
        assert client.create_schedule.call_count == 3

    def test_non_conflict_error_raises_immediately(self):
        """Only ConflictException triggers retry; other errors bubble up."""
        client = MagicMock()
        other_error = botocore.exceptions.ClientError(
            {"Error": {"Code": "ValidationException", "Message": "bad input"}},  # type: ignore[arg-type]
            "CreateSchedule",
        )
        client.create_schedule.side_effect = other_error
        build_input = MagicMock(return_value='{"k":"v"}')

        with pytest.raises(botocore.exceptions.ClientError):
            schedule._create_schedule_with_retry(client, name_prefix="pfx", build_input=build_input, create_kwargs=self._make_kwargs())
        client.create_schedule.assert_called_once()


class TestGetAndDeleteScheduledRevokeReturn:
    """Behavior of get_and_delete_scheduled_revoke_event_if_already_exist."""

    def test_returns_empty_when_no_schedules_exist(self):
        client = MagicMock()
        assignment = _make_account_assignment()

        with patch("schedule.get_scheduled_events", return_value=[]):
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, assignment)

        assert result == []
        client.delete_schedule.assert_not_called()

    def test_returns_empty_when_assignment_does_not_match(self):
        client = MagicMock()
        target = _make_account_assignment(account_id="111111111111")
        unrelated = _make_scheduled_revoke_event(_make_account_assignment(account_id="222222222222"))

        with patch("schedule.get_scheduled_events", return_value=[unrelated]):
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, target)

        assert result == []
        client.delete_schedule.assert_not_called()

    def test_returns_thread_ts_and_deletes_when_account_assignment_matches(self):
        client = MagicMock()
        target = _make_account_assignment()
        existing = _make_scheduled_revoke_event(target, schedule_name="old-sched", thread_ts="1700000000.111")

        with patch("schedule.get_scheduled_events", return_value=[existing]), patch("schedule.delete_schedule") as mock_delete:
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, target)

        assert result == ["1700000000.111"]
        mock_delete.assert_called_once_with(client, "old-sched")

    def test_returns_thread_ts_and_deletes_when_group_assignment_matches(self):
        client = MagicMock()
        target = _make_group_assignment()
        existing = _make_scheduled_group_revoke_event(target, schedule_name="old-g-sched", thread_ts="1700000000.222")

        with patch("schedule.get_scheduled_events", return_value=[existing]), patch("schedule.delete_schedule") as mock_delete:
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, target)

        assert result == ["1700000000.222"]
        mock_delete.assert_called_once_with(client, "old-g-sched")

    def test_skips_schedules_with_null_thread_ts(self):
        """Old schedules created before thread_ts existed shouldn't contribute orphan ts."""
        client = MagicMock()
        target = _make_account_assignment()
        existing = _make_scheduled_revoke_event(target, schedule_name="legacy", thread_ts=None)

        with patch("schedule.get_scheduled_events", return_value=[existing]), patch("schedule.delete_schedule") as mock_delete:
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, target)

        # Schedule still gets deleted, but nothing to mark superseded.
        assert result == []
        mock_delete.assert_called_once_with(client, "legacy")

    def test_returns_all_matches_when_multiple_orphans_exist(self):
        """Defensive: if duplicates somehow exist, we report all of them."""
        client = MagicMock()
        target = _make_account_assignment()
        a = _make_scheduled_revoke_event(target, schedule_name="dup-a", thread_ts="100.001")
        b = _make_scheduled_revoke_event(target, schedule_name="dup-b", thread_ts="100.002")

        with patch("schedule.get_scheduled_events", return_value=[a, b]), patch("schedule.delete_schedule"):
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, target)

        assert result == ["100.001", "100.002"]

    def test_group_event_ignored_when_querying_account_assignment(self):
        """Account-assignment query must not match group events even if user_principal_id is same."""
        client = MagicMock()
        target = _make_account_assignment(user_principal_id="u-1")
        group_event = _make_scheduled_group_revoke_event(_make_group_assignment(user_principal_id="u-1"))

        with patch("schedule.get_scheduled_events", return_value=[group_event]), patch("schedule.delete_schedule") as mock_delete:
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, target)

        assert result == []
        mock_delete.assert_not_called()

    def test_account_event_ignored_when_querying_group_assignment(self):
        client = MagicMock()
        target = _make_group_assignment(user_principal_id="u-1")
        account_event = _make_scheduled_revoke_event(_make_account_assignment(user_principal_id="u-1"))

        with patch("schedule.get_scheduled_events", return_value=[account_event]), patch("schedule.delete_schedule") as mock_delete:
            result = schedule.get_and_delete_scheduled_revoke_event_if_already_exist(client, target)

        assert result == []
        mock_delete.assert_not_called()


class TestMarkSuperseded:
    """Behavior of mark_superseded."""

    def test_flips_header_to_superseded_status(self):
        slack_client = MagicMock()
        existing_blocks = [{"block_id": "header"}, {"block_id": "content"}]
        new_blocks = [{"block_id": "header", "new": True}, {"block_id": "content"}]

        with (
            patch("schedule.slack_helpers.get_message_from_timestamp", return_value={"blocks": existing_blocks}),
            patch("schedule.slack_helpers.HeaderSectionBlock.set_status", return_value=new_blocks) as mock_set,
            patch("schedule.slack_helpers.delete_early_revoke_button"),
        ):
            schedule.mark_superseded(slack_client, "1700000000.111")

        # Set status was called with the configured superseded status
        mock_set.assert_called_once()
        assert mock_set.call_args.kwargs["status_text"] == schedule.cfg.superseded_status
        # chat_update was invoked with the new blocks at the right ts
        slack_client.chat_update.assert_called_once()
        kwargs = slack_client.chat_update.call_args.kwargs
        assert kwargs["ts"] == "1700000000.111"
        assert kwargs["blocks"] == new_blocks

    def test_uses_configured_channel_id(self):
        slack_client = MagicMock()
        with (
            patch("schedule.slack_helpers.get_message_from_timestamp", return_value={"blocks": []}),
            patch("schedule.slack_helpers.HeaderSectionBlock.set_status", return_value=[]),
            patch("schedule.slack_helpers.delete_early_revoke_button") as mock_delete_btn,
        ):
            schedule.mark_superseded(slack_client, "1700000000.111")

        assert slack_client.chat_update.call_args.kwargs["channel"] == schedule.cfg.slack_channel_id
        mock_delete_btn.assert_called_once_with(slack_client, schedule.cfg.slack_channel_id, "1700000000.111")

    def test_deletes_early_revoke_button(self):
        slack_client = MagicMock()
        with (
            patch("schedule.slack_helpers.get_message_from_timestamp", return_value={"blocks": []}),
            patch("schedule.slack_helpers.HeaderSectionBlock.set_status", return_value=[]),
            patch("schedule.slack_helpers.delete_early_revoke_button") as mock_delete_btn,
        ):
            schedule.mark_superseded(slack_client, "1700000000.111")

        mock_delete_btn.assert_called_once()

    def test_no_op_when_message_not_found(self):
        """If the original message is gone (deleted or outside the 100-msg history window),
        skip the update gracefully — don't crash and don't post anything."""
        slack_client = MagicMock()
        with (
            patch("schedule.slack_helpers.get_message_from_timestamp", return_value=None),
            patch("schedule.slack_helpers.HeaderSectionBlock.set_status") as mock_set,
            patch("schedule.slack_helpers.delete_early_revoke_button") as mock_delete_btn,
        ):
            schedule.mark_superseded(slack_client, "1700000000.111")

        slack_client.chat_update.assert_not_called()
        mock_set.assert_not_called()
        mock_delete_btn.assert_not_called()


class TestScheduleRevokeEventSupersedesOrphan:
    """schedule_revoke_event should mark orphaned old-grant messages as SUPERSEDED."""

    def _common_patches(self):
        """Patch the heavy IO away so we can focus on supersession behavior."""
        return (patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),)

    def test_orphan_with_different_thread_ts_is_marked_superseded(self):
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_account_assignment()

        with (
            patch.object(
                schedule,
                "get_and_delete_scheduled_revoke_event_if_already_exist",
                return_value=["old.111"],
            ),
            patch.object(schedule, "mark_superseded") as mock_mark,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
        ):
            schedule.schedule_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                user_account_assignment=assignment,
                slack_client=slack_client,
                thread_ts="new.999",
            )

        mock_mark.assert_called_once_with(slack_client, "old.111")

    def test_orphan_matching_new_thread_ts_is_not_marked_superseded(self):
        """Extend-grant flow reuses the original thread_ts — the message must NOT be flipped."""
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_account_assignment()
        same_ts = "shared.123"

        with (
            patch.object(
                schedule,
                "get_and_delete_scheduled_revoke_event_if_already_exist",
                return_value=[same_ts],
            ),
            patch.object(schedule, "mark_superseded") as mock_mark,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
        ):
            schedule.schedule_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                user_account_assignment=assignment,
                slack_client=slack_client,
                thread_ts=same_ts,
            )

        mock_mark.assert_not_called()

    def test_no_orphans_means_no_supersession_calls(self):
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_account_assignment()

        with (
            patch.object(
                schedule,
                "get_and_delete_scheduled_revoke_event_if_already_exist",
                return_value=[],
            ),
            patch.object(schedule, "mark_superseded") as mock_mark,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
        ):
            schedule.schedule_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                user_account_assignment=assignment,
                slack_client=slack_client,
                thread_ts="new.999",
            )

        mock_mark.assert_not_called()

    def test_mixed_orphans_only_superseded_ones_get_marked(self):
        """If multiple orphans exist and one matches new ts, only the other gets marked."""
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_account_assignment()

        with (
            patch.object(
                schedule,
                "get_and_delete_scheduled_revoke_event_if_already_exist",
                return_value=["other.001", "shared.123", "other.002"],
            ),
            patch.object(schedule, "mark_superseded") as mock_mark,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
        ):
            schedule.schedule_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                user_account_assignment=assignment,
                slack_client=slack_client,
                thread_ts="shared.123",
            )

        called_ts = [c.args[1] for c in mock_mark.call_args_list]
        assert called_ts == ["other.001", "other.002"]


class TestScheduleGroupRevokeEventSupersedesOrphan:
    """schedule_group_revoke_event should mark orphaned old-grant messages as SUPERSEDED."""

    def test_orphan_with_different_thread_ts_is_marked_superseded(self):
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_group_assignment()

        with (
            patch.object(
                schedule,
                "get_and_delete_scheduled_revoke_event_if_already_exist",
                return_value=["old.222"],
            ),
            patch.object(schedule, "mark_superseded") as mock_mark,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-g-sched")),
        ):
            schedule.schedule_group_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                group_assignment=assignment,
                slack_client=slack_client,
                thread_ts="new.999",
            )

        mock_mark.assert_called_once_with(slack_client, "old.222")

    def test_orphan_matching_new_thread_ts_is_not_marked_superseded(self):
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_group_assignment()
        same_ts = "shared.456"

        with (
            patch.object(
                schedule,
                "get_and_delete_scheduled_revoke_event_if_already_exist",
                return_value=[same_ts],
            ),
            patch.object(schedule, "mark_superseded") as mock_mark,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-g-sched")),
        ):
            schedule.schedule_group_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                group_assignment=assignment,
                slack_client=slack_client,
                thread_ts=same_ts,
            )

        mock_mark.assert_not_called()

    def test_no_orphans_means_no_supersession_calls(self):
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_group_assignment()

        with (
            patch.object(
                schedule,
                "get_and_delete_scheduled_revoke_event_if_already_exist",
                return_value=[],
            ),
            patch.object(schedule, "mark_superseded") as mock_mark,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-g-sched")),
        ):
            schedule.schedule_group_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                group_assignment=assignment,
                slack_client=slack_client,
                thread_ts="new.999",
            )

        mock_mark.assert_not_called()


class TestSupersessionEndToEnd:
    """Integration-ish: exercise the full schedule_revoke_event path with realistic mocks
    to catch wiring regressions between get_and_delete..., mark_superseded, and the Slack calls."""

    def test_reproduces_orphaned_grant_bug_fix(self):
        """The exact scenario from the May 8 incident: an existing schedule (different
        thread_ts) gets superseded, the old message's header is flipped, new schedule
        is created."""
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_account_assignment()
        existing = _make_scheduled_revoke_event(assignment, schedule_name="old-sched", thread_ts="old.111")

        with (
            patch.object(schedule, "get_scheduled_events", return_value=[existing]),
            patch.object(schedule, "delete_schedule") as mock_delete,
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
            patch("schedule.slack_helpers.get_message_from_timestamp", return_value={"blocks": []}),
            patch("schedule.slack_helpers.HeaderSectionBlock.set_status", return_value=[{"block_id": "header"}]),
            patch("schedule.slack_helpers.delete_early_revoke_button") as mock_del_btn,
        ):
            schedule.schedule_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                user_account_assignment=assignment,
                slack_client=slack_client,
                thread_ts="new.999",
            )

        # Old schedule deleted
        mock_delete.assert_called_once_with(schedule_client, "old-sched")
        # Old message header was updated and early-revoke button removed
        slack_client.chat_update.assert_called_once()
        assert slack_client.chat_update.call_args.kwargs["ts"] == "old.111"
        mock_del_btn.assert_called_once_with(slack_client, schedule.cfg.slack_channel_id, "old.111")

    def test_extend_grant_path_does_not_flip_its_own_message(self):
        """The extend-grant flow passes the same thread_ts as the existing schedule's
        thread_ts. The message must stay GRANTED, not flip to SUPERSEDED."""
        schedule_client = MagicMock()
        slack_client = MagicMock()
        assignment = _make_account_assignment()
        same_ts = "shared.123"
        existing = _make_scheduled_revoke_event(assignment, schedule_name="old-sched", thread_ts=same_ts)

        with (
            patch.object(schedule, "get_scheduled_events", return_value=[existing]),
            patch.object(schedule, "delete_schedule"),
            patch.object(schedule, "_create_schedule_with_retry", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
            patch("schedule.slack_helpers.get_message_from_timestamp") as mock_get_msg,
            patch("schedule.slack_helpers.delete_early_revoke_button") as mock_del_btn,
        ):
            schedule.schedule_revoke_event(
                schedule_client=schedule_client,
                permission_duration=timedelta(hours=4),
                approver=_make_user(),
                requester=_make_user(),
                user_account_assignment=assignment,
                slack_client=slack_client,
                thread_ts=same_ts,
            )

        # mark_superseded never ran, so the slack lookup helper was not called either
        mock_get_msg.assert_not_called()
        mock_del_btn.assert_not_called()
        slack_client.chat_update.assert_not_called()
