"""Tests for schedule name generation and ConflictException retry."""

from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

import schedule


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
            schedule._create_schedule_with_retry(
                client, name_prefix="pfx", build_input=build_input, create_kwargs=self._make_kwargs()
            )
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
            schedule._create_schedule_with_retry(
                client, name_prefix="pfx", build_input=build_input, create_kwargs=self._make_kwargs()
            )
        client.create_schedule.assert_called_once()
