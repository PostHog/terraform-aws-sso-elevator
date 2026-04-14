"""Tests for slack_helpers module."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
import slack_sdk.errors
from entities.aws import PermissionSet

from slack_helpers import (
    ButtonClickedPayload,
    ButtonGroupClickedPayload,
    RequestForAccessView,
    build_approver_group_mentions,
    get_max_duration_block,
    get_usergroup_members,
    resolve_approver_groups,
)


def _make_config(max_hours: int, override: list[str] | None = None) -> MagicMock:
    """Create a mock config with specified max_permissions_duration_time."""
    cfg = MagicMock()
    cfg.max_permissions_duration_time = max_hours
    cfg.permission_duration_list_override = override
    return cfg


class TestGetMaxDurationBlock:
    def test_default_durations_with_24h_max(self):
        """All 8 base durations returned when max is 24h."""
        cfg = _make_config(max_hours=24)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00", "08:00", "12:00", "24:00"]

    def test_filters_durations_exceeding_max(self):
        """Durations > max_permissions_duration_time are excluded."""
        cfg = _make_config(max_hours=4)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00"]
        assert "08:00" not in values
        assert "12:00" not in values
        assert "24:00" not in values

    def test_includes_max_when_not_in_base_set(self):
        """If max is 6h, includes 6h even though not in base set."""
        cfg = _make_config(max_hours=6)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert "06:00" in values
        # Should be sorted correctly
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00", "06:00"]

    def test_max_already_in_base_set_not_duplicated(self):
        """If max is 8h (in base set), no duplicate."""
        cfg = _make_config(max_hours=8)
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values.count("08:00") == 1
        assert values == ["00:15", "00:30", "01:00", "02:00", "04:00", "08:00"]

    def test_display_text_is_human_readable(self):
        """Display shows '15 min', '1 hour', '2 hours' etc."""
        cfg = _make_config(max_hours=24)
        options = get_max_duration_block(cfg)

        # Option.text can be a PlainTextObject or string depending on slack-sdk version
        texts = [_opt_text(opt) for opt in options]
        assert texts == ["15 min", "30 min", "1 hour", "2 hours", "4 hours", "8 hours", "12 hours", "24 hours"]

    def test_value_is_hhmm_format(self):
        """Value is HH:MM format for backend parsing."""
        cfg = _make_config(max_hours=24)
        options = get_max_duration_block(cfg)

        for opt in options:
            # Value should match HH:MM format
            assert len(opt.value) == 5
            assert opt.value[2] == ":"
            hours, minutes = opt.value.split(":")
            assert hours.isdigit() and len(hours) == 2
            assert minutes.isdigit() and len(minutes) == 2

    def test_override_list_used_when_provided(self):
        """permission_duration_list_override takes precedence."""
        cfg = _make_config(max_hours=24, override=["01:00", "02:00", "03:00"])
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert values == ["01:00", "02:00", "03:00"]

    def test_small_max_includes_at_least_max(self):
        """Even with small max like 0.5h, max is included."""
        cfg = _make_config(max_hours=0.5)  # type: ignore[arg-type]
        options = get_max_duration_block(cfg)

        values = [opt.value for opt in options]
        assert "00:30" in values


class TestFindInFields:
    """Tests for find_in_fields static method."""

    def test_parses_key_value_format(self):
        """Parses *Key*\\nValue format correctly."""
        fields = [{"text": "*Requester*\n<@U12345>"}]
        result = ButtonClickedPayload.find_in_fields(fields, "Requester")
        assert result == "<@U12345>"

    def test_strips_whitespace_from_value(self):
        """Strips leading/trailing whitespace from parsed value."""
        fields = [{"text": "*Duration*\n  0h 15m  "}]
        result = ButtonClickedPayload.find_in_fields(fields, "Duration")
        assert result == "0h 15m"

    def test_handles_multiline_values(self):
        """Handles values that contain newlines (only splits on first)."""
        fields = [{"text": "*Reason*\nLine 1\nLine 2"}]
        result = ButtonClickedPayload.find_in_fields(fields, "Reason")
        assert result == "Line 1\nLine 2"

    def test_raises_value_error_for_missing_key(self):
        """Raises ValueError when key not found."""
        fields = [{"text": "*Requester*\n<@U12345>"}]
        with pytest.raises(ValueError, match="Could not find MissingKey"):
            ButtonClickedPayload.find_in_fields(fields, "MissingKey")

    def test_finds_key_among_multiple_fields(self):
        """Finds correct key when multiple fields present."""
        fields = [
            {"text": "*Requester*\n<@U12345>"},
            {"text": "*Account*\nMyAccount (123456789012)"},
            {"text": "*Duration*\n1h 00m"},
        ]
        assert ButtonClickedPayload.find_in_fields(fields, "Account") == "MyAccount (123456789012)"
        assert ButtonClickedPayload.find_in_fields(fields, "Duration") == "1h 00m"


class TestButtonClickedPayload:
    """Tests for ButtonClickedPayload validation."""

    def _make_payload(self, **overrides: str) -> dict:
        """Create a realistic Slack button click payload with optional field overrides."""
        defaults = {
            "action": "approve",
            "requester": "<@U_REQUESTER>",
            "account": "TestAccount (123456789012)",
            "permission_set": "AdminAccess",
            "duration": "0h 15m",
            "reason": "Testing",
        }
        fields = {**defaults, **overrides}
        return {
            "actions": [{"value": fields["action"]}],
            "user": {"id": "U_APPROVER"},
            "message": {
                "ts": "1234567890.123456",
                "blocks": [
                    {
                        "block_id": "content",
                        "fields": [
                            {"text": f"*Requester*\n{fields['requester']}"},
                            {"text": f"*Account*\n{fields['account']}"},
                            {"text": f"*Permission Set*\n{fields['permission_set']}"},
                            {"text": f"*Duration*\n{fields['duration']}"},
                            {"text": f"*Reason*\n{fields['reason']}"},
                        ],
                    }
                ],
            },
            "channel": {"id": "C_CHANNEL"},
        }

    def test_parses_approve_action(self):
        """Parses approve action from payload."""
        payload = ButtonClickedPayload.model_validate(self._make_payload(action="approve"))
        assert payload.action.value == "approve"

    def test_parses_deny_action(self):
        """Parses deny action from payload."""
        payload = ButtonClickedPayload.model_validate(self._make_payload(action="deny"))
        assert payload.action.value == "deny"

    def test_extracts_requester_slack_id(self):
        """Extracts requester ID from <@ID> format."""
        payload = ButtonClickedPayload.model_validate(self._make_payload(requester="<@U_REQUESTER>"))
        assert payload.request.requester_slack_id == "U_REQUESTER"

    def test_extracts_account_id_from_parentheses_format(self):
        """Extracts account ID from Name (ID) format."""
        payload = ButtonClickedPayload.model_validate(self._make_payload(account="Root (795637471508)"))
        assert payload.request.account_id == "795637471508"

    def test_extracts_permission_set_name(self):
        """Extracts permission set name from field."""
        payload = ButtonClickedPayload.model_validate(self._make_payload(permission_set="AdminAccess"))
        assert payload.request.permission_set_name == "AdminAccess"

    def test_parses_duration(self):
        """Parses humanized duration into timedelta."""
        payload = ButtonClickedPayload.model_validate(self._make_payload(duration="1h 30m"))
        assert payload.request.permission_duration == timedelta(hours=1, minutes=30)

    def test_extracts_reason(self):
        """Extracts reason from field."""
        payload = ButtonClickedPayload.model_validate(self._make_payload(reason="Need to debug production"))
        assert payload.request.reason == "Need to debug production"

    def test_extracts_approver_and_channel(self):
        """Extracts approver ID and channel ID."""
        payload = ButtonClickedPayload.model_validate(self._make_payload())
        assert payload.approver_slack_id == "U_APPROVER"
        assert payload.channel_id == "C_CHANNEL"

    def test_raises_on_missing_permission_set_field(self):
        """Raises ValueError if Permission Set field is missing."""
        bad_payload = self._make_payload()
        # Remove the Permission Set field
        bad_payload["message"]["blocks"][0]["fields"] = [
            f for f in bad_payload["message"]["blocks"][0]["fields"] if "Permission Set" not in f["text"]
        ]
        with pytest.raises(ValueError, match="Could not find Permission Set"):
            ButtonClickedPayload.model_validate(bad_payload)


class TestButtonGroupClickedPayload:
    """Tests for ButtonGroupClickedPayload validation."""

    def _make_payload(
        self,
        action: str = "approve",
        requester: str = "<@U_REQUESTER>",
        group: str = "TestGroup (group-123)",
        duration: str = "0h 15m",
        reason: str = "Testing",
    ) -> dict:
        """Create a realistic Slack button click payload for group access."""
        return {
            "actions": [{"value": action}],
            "user": {"id": "U_APPROVER"},
            "message": {
                "ts": "1234567890.123456",
                "blocks": [
                    {
                        "block_id": "content",
                        "fields": [
                            {"text": f"*Requester*\n{requester}"},
                            {"text": f"*Group*\n{group}"},
                            {"text": f"*Duration*\n{duration}"},
                            {"text": f"*Reason*\n{reason}"},
                        ],
                    }
                ],
            },
            "channel": {"id": "C_CHANNEL"},
        }

    def test_parses_approve_action(self):
        """Parses approve action from payload."""
        payload = ButtonGroupClickedPayload.model_validate(self._make_payload(action="approve"))
        assert payload.action.value == "approve"

    def test_extracts_group_id_from_parentheses_format(self):
        """Extracts group ID from Name (ID) format."""
        payload = ButtonGroupClickedPayload.model_validate(self._make_payload(group="MyGroup (group-123)"))
        assert payload.request.group_id == "group-123"

    def test_parses_duration(self):
        """Parses humanized duration into timedelta."""
        payload = ButtonGroupClickedPayload.model_validate(self._make_payload(duration="2h 00m"))
        assert payload.request.permission_duration == timedelta(hours=2)

    def test_raises_on_missing_group_field(self):
        """Raises ValueError if Group field is missing."""
        bad_payload = self._make_payload()
        bad_payload["message"]["blocks"][0]["fields"] = [
            f for f in bad_payload["message"]["blocks"][0]["fields"] if "Group" not in f["text"]
        ]
        with pytest.raises(ValueError, match="Could not find Group"):
            ButtonGroupClickedPayload.model_validate(bad_payload)


class TestGetUsergroupMembers:
    """Tests for get_usergroup_members function."""

    def test_successful_retrieval(self):
        """Successfully retrieves member IDs from a usergroup."""
        mock_client = MagicMock()
        mock_client.usergroups_users_list.return_value = {"users": ["U123", "U456", "U789"]}

        result = get_usergroup_members(mock_client, "SAZ94GDB8")

        assert result == ["U123", "U456", "U789"]
        mock_client.usergroups_users_list.assert_called_once_with(usergroup="SAZ94GDB8")

    def test_empty_usergroup_returns_empty_list(self):
        """Usergroup with no members returns empty list."""
        mock_client = MagicMock()
        mock_client.usergroups_users_list.return_value = {"users": []}

        result = get_usergroup_members(mock_client, "SAZ94GDB8")

        assert result == []

    def test_no_such_subteam_error_returns_empty_list(self):
        """no_such_subteam error returns empty list instead of raising."""
        mock_client = MagicMock()
        error_response = MagicMock()
        error_response.__getitem__ = MagicMock(return_value="no_such_subteam")
        mock_client.usergroups_users_list.side_effect = slack_sdk.errors.SlackApiError(
            message="no_such_subteam",
            response=error_response,
        )

        result = get_usergroup_members(mock_client, "NONEXISTENT")

        assert result == []

    def test_rate_limiting_with_retry(self):
        """Rate limiting triggers retry after sleep."""
        mock_client = MagicMock()
        error_response = MagicMock()
        error_response.__getitem__ = MagicMock(return_value="ratelimited")
        rate_limit_error = slack_sdk.errors.SlackApiError(
            message="ratelimited",
            response=error_response,
        )
        # First call raises rate limit, second succeeds
        mock_client.usergroups_users_list.side_effect = [
            rate_limit_error,
            {"users": ["U123"]},
        ]

        with patch("slack_helpers.time.sleep") as mock_sleep:
            result = get_usergroup_members(mock_client, "SAZ94GDB8")

        assert result == ["U123"]
        mock_sleep.assert_called_once_with(3)
        assert mock_client.usergroups_users_list.call_count == 2

    def test_other_errors_are_raised(self):
        """Non-rate-limit, non-no_such_subteam errors are re-raised."""
        mock_client = MagicMock()
        error_response = MagicMock()
        error_response.__getitem__ = MagicMock(return_value="invalid_auth")
        mock_client.usergroups_users_list.side_effect = slack_sdk.errors.SlackApiError(
            message="invalid_auth",
            response=error_response,
        )

        with pytest.raises(slack_sdk.errors.SlackApiError):
            get_usergroup_members(mock_client, "SAZ94GDB8")


class TestResolveApproverGroups:
    """Tests for resolve_approver_groups function."""

    def test_resolves_multiple_groups(self):
        """Resolves users from multiple usergroups."""
        mock_client = MagicMock()

        # Mock get_usergroup_members behavior
        def mock_usergroups_users_list(usergroup):
            groups = {
                "GROUP1": {"users": ["U1", "U2"]},
                "GROUP2": {"users": ["U3", "U4"]},
            }
            return groups.get(usergroup, {"users": []})

        mock_client.usergroups_users_list.side_effect = mock_usergroups_users_list

        # Mock get_user behavior
        def mock_users_info(user):
            users = {
                "U1": {"user": {"id": "U1", "profile": {"email": "u1@test.com"}, "real_name": "User 1"}},
                "U2": {"user": {"id": "U2", "profile": {"email": "u2@test.com"}, "real_name": "User 2"}},
                "U3": {"user": {"id": "U3", "profile": {"email": "u3@test.com"}, "real_name": "User 3"}},
                "U4": {"user": {"id": "U4", "profile": {"email": "u4@test.com"}, "real_name": "User 4"}},
            }
            response = MagicMock()
            response.data = users.get(user, {})
            return response

        mock_client.users_info.side_effect = mock_users_info

        users, failed_groups = resolve_approver_groups(mock_client, frozenset(["GROUP1", "GROUP2"]))

        assert len(users) == 4
        user_ids = {u.id for u in users}
        assert user_ids == {"U1", "U2", "U3", "U4"}
        assert failed_groups == []

    def test_deduplicates_users_across_groups(self):
        """Users appearing in multiple groups are only returned once."""
        mock_client = MagicMock()

        # User U2 appears in both groups
        def mock_usergroups_users_list(usergroup):
            groups = {
                "GROUP1": {"users": ["U1", "U2"]},
                "GROUP2": {"users": ["U2", "U3"]},
            }
            return groups.get(usergroup, {"users": []})

        mock_client.usergroups_users_list.side_effect = mock_usergroups_users_list

        def mock_users_info(user):
            users = {
                "U1": {"user": {"id": "U1", "profile": {"email": "u1@test.com"}, "real_name": "User 1"}},
                "U2": {"user": {"id": "U2", "profile": {"email": "u2@test.com"}, "real_name": "User 2"}},
                "U3": {"user": {"id": "U3", "profile": {"email": "u3@test.com"}, "real_name": "User 3"}},
            }
            response = MagicMock()
            response.data = users.get(user, {})
            return response

        mock_client.users_info.side_effect = mock_users_info

        users, failed_groups = resolve_approver_groups(mock_client, frozenset(["GROUP1", "GROUP2"]))

        assert len(users) == 3
        user_ids = {u.id for u in users}
        assert user_ids == {"U1", "U2", "U3"}
        # users_info should only be called 3 times (U2 is deduplicated)
        assert mock_client.users_info.call_count == 3

    def test_handles_failed_group_resolution(self):
        """Groups that fail to resolve are tracked in failed_groups."""
        mock_client = MagicMock()

        error_response = MagicMock()
        error_response.__getitem__ = MagicMock(return_value="invalid_auth")

        def mock_usergroups_users_list(usergroup):
            if usergroup == "GOOD_GROUP":
                return {"users": ["U1"]}
            raise slack_sdk.errors.SlackApiError(message="invalid_auth", response=error_response)

        mock_client.usergroups_users_list.side_effect = mock_usergroups_users_list

        def mock_users_info(user):
            response = MagicMock()
            response.data = {"user": {"id": user, "profile": {"email": f"{user}@test.com"}, "real_name": f"User {user}"}}
            return response

        mock_client.users_info.side_effect = mock_users_info

        users, failed_groups = resolve_approver_groups(mock_client, frozenset(["GOOD_GROUP", "BAD_GROUP"]))

        assert len(users) == 1
        assert users[0].id == "U1"
        assert failed_groups == ["BAD_GROUP"]

    def test_empty_group_is_not_failure(self):
        """Empty usergroups don't count as failures."""
        mock_client = MagicMock()

        def mock_usergroups_users_list(usergroup):
            if usergroup == "EMPTY_GROUP":
                return {"users": []}
            return {"users": ["U1"]}

        mock_client.usergroups_users_list.side_effect = mock_usergroups_users_list

        def mock_users_info(user):
            response = MagicMock()
            response.data = {"user": {"id": user, "profile": {"email": f"{user}@test.com"}, "real_name": f"User {user}"}}
            return response

        mock_client.users_info.side_effect = mock_users_info

        users, failed_groups = resolve_approver_groups(mock_client, frozenset(["EMPTY_GROUP", "NON_EMPTY_GROUP"]))

        assert len(users) == 1
        assert failed_groups == []


class TestBuildApproverGroupMentions:
    """Tests for build_approver_group_mentions function."""

    def test_builds_single_group_mention(self):
        """Builds correct mention format for single group."""
        result = build_approver_group_mentions(frozenset(["SAZ94GDB8"]))
        assert result == "<!subteam^SAZ94GDB8>"

    def test_builds_multiple_group_mentions(self):
        """Builds space-separated mentions for multiple groups."""
        result = build_approver_group_mentions(frozenset(["GROUP1", "GROUP2"]))
        # Order may vary due to frozenset, check both mentions are present
        assert "<!subteam^GROUP1>" in result
        assert "<!subteam^GROUP2>" in result
        assert result.count("<!subteam^") == 2

    def test_empty_groups_returns_empty_string(self):
        """Empty frozenset returns empty string."""
        result = build_approver_group_mentions(frozenset())
        assert result == ""


class TestParseMulti:
    """Tests for RequestForAccessView.parse_multi."""

    def _make_submission(self, account_values: list[str]) -> dict:
        """Create a realistic Slack view submission payload with multi-select accounts."""
        return {
            "user": {"id": "U_REQUESTER"},
            "view": {
                "state": {
                    "values": {
                        RequestForAccessView.DURATION_BLOCK_ID: {
                            RequestForAccessView.DURATION_ACTION_ID: {
                                "selected_option": {"value": "01:00"},
                            },
                        },
                        RequestForAccessView.ACCOUNT_BLOCK_ID: {
                            RequestForAccessView.ACCOUNT_ACTION_ID: {
                                "selected_options": [{"value": v} for v in account_values],
                            },
                        },
                        RequestForAccessView.PERMISSION_SET_BLOCK_ID: {
                            RequestForAccessView.PERMISSION_SET_ACTION_ID: {
                                "selected_option": {"value": "arn:aws:sso:::permissionSet/ssoins-abc/ps-123"},
                            },
                        },
                        RequestForAccessView.REASON_BLOCK_ID: {
                            RequestForAccessView.REASON_ACTION_ID: {
                                "value": "Testing multi-account",
                            },
                        },
                    },
                },
            },
        }

    def test_single_account(self):
        """Single account returns one request."""
        obj = self._make_submission(["111111111111"])
        results = RequestForAccessView.parse_multi(obj)
        assert len(results) == 1
        assert results[0].account_id == "111111111111"
        assert results[0].requester_slack_id == "U_REQUESTER"
        assert results[0].reason == "Testing multi-account"
        assert results[0].permission_duration == timedelta(hours=1)

    def test_multiple_accounts(self):
        """Multiple accounts return one request per account."""
        obj = self._make_submission(["111111111111", "222222222222", "333333333333"])
        results = RequestForAccessView.parse_multi(obj)
        assert len(results) == 3
        account_ids = [r.account_id for r in results]
        assert account_ids == ["111111111111", "222222222222", "333333333333"]
        # All share the same permission set and reason
        for r in results:
            assert r.permission_set_name == "arn:aws:sso:::permissionSet/ssoins-abc/ps-123"
            assert r.reason == "Testing multi-account"

    def test_empty_selection_returns_empty(self):
        """No accounts selected returns empty list."""
        obj = self._make_submission([])
        results = RequestForAccessView.parse_multi(obj)
        assert results == []

    def test_none_permission_set_returns_empty(self):
        """Modal submitted before permission set selected returns empty list."""
        obj = self._make_submission(["111111111111"])
        # Simulate permission set dropdown not yet selected (selected_option is None)
        obj["view"]["state"]["values"][RequestForAccessView.PERMISSION_SET_BLOCK_ID][RequestForAccessView.PERMISSION_SET_ACTION_ID][
            "selected_option"
        ] = None
        results = RequestForAccessView.parse_multi(obj)
        assert results == []


def _ps(name: str, arn: str = "") -> PermissionSet:
    """Create a PermissionSet for testing."""
    return PermissionSet(name=name, arn=arn or f"arn:aws:sso:::permissionSet/ssoins-abc/{name}", description=None)


def _opt_text(opt) -> str:  # noqa: ANN001
    """Extract display text from a Slack Option (handles str or PlainTextObject)."""
    return opt.text if isinstance(opt.text, str) else opt.text.text


def _group_label(group) -> str:  # noqa: ANN001
    """Extract label text from a Slack OptionGroup (handles str or PlainTextObject)."""
    return group.label if isinstance(group.label, str) else group.label.text


class TestGetPermissionSetDisplayName:
    """Tests for RequestForAccessView._get_permission_set_display_name."""

    def test_no_display_names_returns_aws_name(self):
        ps = _ps("AdminAccess")
        assert RequestForAccessView._get_permission_set_display_name(ps) == "AdminAccess"

    def test_none_display_names_returns_aws_name(self):
        ps = _ps("AdminAccess")
        assert RequestForAccessView._get_permission_set_display_name(ps, display_names=None) == "AdminAccess"

    def test_empty_dict_returns_aws_name(self):
        ps = _ps("AdminAccess")
        assert RequestForAccessView._get_permission_set_display_name(ps, display_names={}) == "AdminAccess"

    def test_match_by_name(self):
        ps = _ps("eks-developer")
        result = RequestForAccessView._get_permission_set_display_name(ps, display_names={"eks-developer": "EKS/kubectl access"})
        assert result == "EKS/kubectl access"

    def test_match_by_arn(self):
        ps = _ps("AdminAccess", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-admin")
        result = RequestForAccessView._get_permission_set_display_name(
            ps, display_names={"arn:aws:sso:::permissionSet/ssoins-abc/ps-admin": "Full Admin"}
        )
        assert result == "Full Admin"

    def test_name_takes_priority_over_arn(self):
        ps = _ps("AdminAccess", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-admin")
        result = RequestForAccessView._get_permission_set_display_name(
            ps,
            display_names={
                "AdminAccess": "By Name",
                "arn:aws:sso:::permissionSet/ssoins-abc/ps-admin": "By ARN",
            },
        )
        assert result == "By Name"

    def test_no_match_falls_back_to_aws_name(self):
        ps = _ps("ReadOnly")
        result = RequestForAccessView._get_permission_set_display_name(ps, display_names={"SomethingElse": "Nope"})
        assert result == "ReadOnly"

    def test_long_name_truncated_to_75_chars(self):
        ps = _ps("AdminAccess")
        long_label = "A" * 100
        result = RequestForAccessView._get_permission_set_display_name(ps, display_names={"AdminAccess": long_label})
        assert len(result) == 75


class TestBuildSelectPermissionSetInputBlock:
    """Tests for RequestForAccessView.build_select_permission_set_input_block."""

    def test_options_use_display_names(self):
        psets = [_ps("AdminAccess"), _ps("ReadOnly")]
        display = {"AdminAccess": "Full Admin", "ReadOnly": "Read-Only Access"}
        block = RequestForAccessView.build_select_permission_set_input_block(psets, display_names=display)
        texts = [_opt_text(opt) for opt in block.element.options]  # type: ignore[union-attr]
        assert "Full Admin" in texts
        assert "Read-Only Access" in texts

    def test_options_sorted_by_display_name(self):
        psets = [_ps("ZZZ-admin"), _ps("AAA-readonly")]
        display = {"ZZZ-admin": "Alpha", "AAA-readonly": "Beta"}
        block = RequestForAccessView.build_select_permission_set_input_block(psets, display_names=display)
        texts = [_opt_text(opt) for opt in block.element.options]  # type: ignore[union-attr]
        assert texts == ["Alpha", "Beta"]

    def test_options_sorted_by_aws_name_without_display_names(self):
        psets = [_ps("Zebra"), _ps("Alpha")]
        block = RequestForAccessView.build_select_permission_set_input_block(psets)
        texts = [_opt_text(opt) for opt in block.element.options]  # type: ignore[union-attr]
        assert texts == ["Alpha", "Zebra"]

    def test_value_is_arn_not_display_name(self):
        psets = [_ps("Admin", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-123")]
        display = {"Admin": "Friendly Label"}
        block = RequestForAccessView.build_select_permission_set_input_block(psets, display_names=display)
        assert block.element.options[0].value == "arn:aws:sso:::permissionSet/ssoins-abc/ps-123"  # type: ignore[union-attr]
        assert _opt_text(block.element.options[0]) == "Friendly Label"  # type: ignore[union-attr]

    def test_mixed_matched_and_unmatched(self):
        psets = [_ps("Mapped"), _ps("Unmapped")]
        display = {"Mapped": "Custom Label"}
        block = RequestForAccessView.build_select_permission_set_input_block(psets, display_names=display)
        text_map = {_opt_text(opt) for opt in block.element.options}  # type: ignore[union-attr]
        assert text_map == {"Custom Label", "Unmapped"}

    def test_auto_approved_arns_none_uses_flat_options(self):
        psets = [_ps("Admin"), _ps("ReadOnly")]
        block = RequestForAccessView.build_select_permission_set_input_block(psets, auto_approved_arns=None)
        assert block.element.options is not None  # type: ignore[union-attr]
        assert block.element.option_groups is None  # type: ignore[union-attr]

    def test_all_auto_approved_single_group(self):
        psets = [_ps("Admin"), _ps("ReadOnly")]
        arns = {ps.arn for ps in psets}
        block = RequestForAccessView.build_select_permission_set_input_block(psets, auto_approved_arns=arns)
        groups = block.element.option_groups  # type: ignore[union-attr]
        assert len(groups) == 1
        assert _group_label(groups[0]) == "Auto approved"

    def test_all_require_approval_single_group(self):
        psets = [_ps("Admin"), _ps("ReadOnly")]
        block = RequestForAccessView.build_select_permission_set_input_block(psets, auto_approved_arns=set())
        groups = block.element.option_groups  # type: ignore[union-attr]
        assert len(groups) == 1
        assert _group_label(groups[0]) == "Requires approval"

    def test_mixed_auto_and_requires_approval(self):
        ps_auto = _ps("AutoRole")
        ps_manual = _ps("ManualRole")
        block = RequestForAccessView.build_select_permission_set_input_block(
            [ps_auto, ps_manual],
            auto_approved_arns={ps_auto.arn},
        )
        groups = block.element.option_groups  # type: ignore[union-attr]
        assert len(groups) == 2
        assert _group_label(groups[0]) == "Auto approved"
        assert _group_label(groups[1]) == "Requires approval"
        assert [_opt_text(o) for o in groups[0].options] == ["AutoRole"]
        assert [_opt_text(o) for o in groups[1].options] == ["ManualRole"]

    def test_option_groups_sorted_by_display_name(self):
        psets = [_ps("ZZZ"), _ps("AAA"), _ps("MMM")]
        display = {"ZZZ": "alpha", "AAA": "charlie", "MMM": "bravo"}
        block = RequestForAccessView.build_select_permission_set_input_block(
            psets,
            display_names=display,
            auto_approved_arns=set(),
        )
        groups = block.element.option_groups  # type: ignore[union-attr]
        texts = [_opt_text(o) for o in groups[0].options]
        assert texts == ["alpha", "bravo", "charlie"]

    def test_option_groups_use_display_names(self):
        ps = _ps("eks-developer")
        display = {"eks-developer": "EKS/kubectl access"}
        block = RequestForAccessView.build_select_permission_set_input_block(
            [ps],
            display_names=display,
            auto_approved_arns={ps.arn},
        )
        groups = block.element.option_groups  # type: ignore[union-attr]
        assert _opt_text(groups[0].options[0]) == "EKS/kubectl access"

    def test_option_groups_value_is_arn(self):
        ps = _ps("Admin", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-123")
        block = RequestForAccessView.build_select_permission_set_input_block(
            [ps],
            display_names={"Admin": "Friendly"},
            auto_approved_arns={ps.arn},
        )
        groups = block.element.option_groups  # type: ignore[union-attr]
        assert groups[0].options[0].value == "arn:aws:sso:::permissionSet/ssoins-abc/ps-123"


class TestUpdateWithPermissionSets:
    """Tests for RequestForAccessView.update_with_permission_sets."""

    def _make_view_blocks(self) -> list:
        """Build a view and return its blocks after account selection (with placeholder)."""
        from entities.aws import Account

        accounts = [Account(id="111111111111", name="Test")]
        view = RequestForAccessView.update_with_accounts(accounts)
        return view.blocks

    def test_display_names_passed_through(self):
        blocks = self._make_view_blocks()
        psets = [_ps("Admin"), _ps("ReadOnly")]
        display = {"Admin": "Administrator", "ReadOnly": "Viewer"}
        view = RequestForAccessView.update_with_permission_sets(blocks, psets, display_names=display)
        # Find the permission set block options
        ps_block = next(b for b in view.blocks if getattr(b, "block_id", None) == RequestForAccessView.PERMISSION_SET_BLOCK_ID)
        texts = [_opt_text(opt) for opt in ps_block.element.options]  # type: ignore[union-attr]
        assert "Administrator" in texts
        assert "Viewer" in texts

    def test_none_display_names_uses_aws_names(self):
        blocks = self._make_view_blocks()
        psets = [_ps("Admin"), _ps("ReadOnly")]
        view = RequestForAccessView.update_with_permission_sets(blocks, psets, display_names=None)
        ps_block = next(b for b in view.blocks if getattr(b, "block_id", None) == RequestForAccessView.PERMISSION_SET_BLOCK_ID)
        texts = [_opt_text(opt) for opt in ps_block.element.options]  # type: ignore[union-attr]
        assert "Admin" in texts
        assert "ReadOnly" in texts

    def test_auto_approved_arns_passed_through(self):
        blocks = self._make_view_blocks()
        ps_auto = _ps("AutoRole")
        ps_manual = _ps("ManualRole")
        view = RequestForAccessView.update_with_permission_sets(
            blocks,
            [ps_auto, ps_manual],
            auto_approved_arns={ps_auto.arn},
        )
        ps_block = next(b for b in view.blocks if getattr(b, "block_id", None) == RequestForAccessView.PERMISSION_SET_BLOCK_ID)
        groups = ps_block.element.option_groups  # type: ignore[union-attr]
        assert len(groups) == 2
        assert _group_label(groups[0]) == "Auto approved"
        assert _group_label(groups[1]) == "Requires approval"
