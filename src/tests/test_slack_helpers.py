"""Tests for slack_helpers module."""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
import slack_sdk.errors
import slack_helpers
from entities.aws import Account, PermissionSet, SSOGroup

from slack_helpers import (
    ButtonClickedPayload,
    ButtonGroupClickedPayload,
    RequestForAccessView,
    RequestForGroupAccessView,
    build_approver_group_mentions,
    build_approvers_preview_text,
    format_approver_mentions,
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

    def test_skips_bot_app_and_deleted_users(self):
        """Bot users, app users, and deactivated users are silently skipped."""
        mock_client = MagicMock()

        mock_client.usergroups_users_list.return_value = {"users": ["U_HUMAN", "U_BOT", "U_APP", "U_DELETED"]}

        def mock_users_info(user):
            users = {
                "U_HUMAN": {"user": {"id": "U_HUMAN", "profile": {"email": "human@test.com"}, "real_name": "Human"}},
                "U_BOT": {"user": {"id": "U_BOT", "is_bot": True, "profile": {}, "real_name": "Bot"}},
                "U_APP": {"user": {"id": "U_APP", "is_app_user": True, "profile": {}, "real_name": "App"}},
                "U_DELETED": {"user": {"id": "U_DELETED", "deleted": True, "profile": {}, "real_name": "Gone"}},
            }
            response = MagicMock()
            response.data = users.get(user, {})
            return response

        mock_client.users_info.side_effect = mock_users_info

        users, failed_groups = resolve_approver_groups(mock_client, frozenset(["GROUP1"]))

        assert len(users) == 1
        assert users[0].id == "U_HUMAN"
        assert failed_groups == []

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


class TestFormatApproverMentions:
    """Tests for format_approver_mentions function."""

    def _client_with_emails(self, email_to_id: dict[str, str]) -> MagicMock:
        client = MagicMock()

        def lookup(email):
            uid = email_to_id.get(email)
            if uid is None:
                raise slack_sdk.errors.SlackApiError(message="users_not_found", response=MagicMock())
            response = MagicMock()
            response.data = {"user": {"id": uid, "profile": {"email": email}, "real_name": uid}}
            return response

        client.users_lookupByEmail.side_effect = lookup
        return client

    def test_resolves_users_and_groups(self):
        client = self._client_with_emails({"a@test.com": "U_A", "b@test.com": "U_B"})
        mention_str, unresolved = format_approver_mentions(
            client=client,
            approver_emails=frozenset(["a@test.com", "b@test.com"]),
            approver_group_ids=frozenset(["GRP1"]),
            separator=", ",
        )
        assert "<@U_A>" in mention_str
        assert "<@U_B>" in mention_str
        assert "<!subteam^GRP1>" in mention_str
        assert ", " in mention_str
        assert unresolved == []

    def test_tracks_unresolved_emails(self):
        client = self._client_with_emails({"a@test.com": "U_A"})
        mention_str, unresolved = format_approver_mentions(
            client=client,
            approver_emails=frozenset(["a@test.com", "missing@test.com"]),
            approver_group_ids=frozenset(),
            separator=", ",
        )
        assert "<@U_A>" in mention_str
        assert "missing@test.com" not in mention_str
        assert unresolved == ["missing@test.com"]

    def test_uses_email_cache_to_skip_lookup(self):
        client = self._client_with_emails({"a@test.com": "U_A"})
        cache = {"a@test.com": "U_CACHED"}
        mention_str, _ = format_approver_mentions(
            client=client,
            approver_emails=frozenset(["a@test.com"]),
            approver_group_ids=frozenset(),
            email_cache=cache,
        )
        assert "<@U_CACHED>" in mention_str
        client.users_lookupByEmail.assert_not_called()

    def test_writes_back_to_email_cache(self):
        client = self._client_with_emails({"a@test.com": "U_A"})
        cache: dict[str, str] = {}
        format_approver_mentions(
            client=client,
            approver_emails=frozenset(["a@test.com"]),
            approver_group_ids=frozenset(),
            email_cache=cache,
        )
        assert cache == {"a@test.com": "U_A"}


class TestBuildApproversPreviewText:
    """Tests for build_approvers_preview_text — drives the modal preview block."""

    def _make_decision(
        self,
        reason_name: str,
        grant: bool,
        approvers: frozenset[str] = frozenset(),
        approver_groups: frozenset[str] = frozenset(),
    ):
        import access_control

        return access_control.AccessRequestDecision(
            grant=grant,
            reason=getattr(access_control.DecisionReason, reason_name),
            based_on_statements=frozenset(),
            approvers=approvers,
            approver_groups=approver_groups,
        )

    def _client_with_emails(self, email_to_id: dict[str, str]) -> MagicMock:
        client = MagicMock()

        def lookup(email):
            uid = email_to_id.get(email)
            if uid is None:
                raise slack_sdk.errors.SlackApiError(message="users_not_found", response=MagicMock())
            response = MagicMock()
            response.data = {"user": {"id": uid, "profile": {"email": email}, "real_name": uid}}
            return response

        client.users_lookupByEmail.side_effect = lookup
        return client

    def test_empty_decisions_returns_no_approvers_warning(self):
        text = build_approvers_preview_text(MagicMock(), [])
        assert ":warning:" in text
        assert "No approvers" in text

    def test_all_approval_not_required_is_auto_approved(self):
        decision = self._make_decision("ApprovalNotRequired", grant=True)
        text = build_approvers_preview_text(MagicMock(), [decision])
        assert ":white_check_mark:" in text
        assert "Auto-approved" in text

    def test_all_self_approval_returns_self_approve_text(self):
        decision = self._make_decision("SelfApproval", grant=True)
        text = build_approvers_preview_text(MagicMock(), [decision])
        assert ":white_check_mark:" in text
        assert "self-approve" in text

    def test_no_statements_returns_no_approvers_warning(self):
        decision = self._make_decision("NoStatements", grant=False)
        text = build_approvers_preview_text(MagicMock(), [decision])
        assert ":warning:" in text
        assert "No approvers" in text

    def test_no_approvers_reason_returns_warning(self):
        decision = self._make_decision("NoApprovers", grant=False)
        text = build_approvers_preview_text(MagicMock(), [decision])
        assert ":warning:" in text

    def test_requires_approval_renders_mentions(self):
        client = self._client_with_emails({"alice@test.com": "U_ALICE", "bob@test.com": "U_BOB"})
        decision = self._make_decision(
            "RequiresApproval",
            grant=False,
            approvers=frozenset(["alice@test.com", "bob@test.com"]),
            approver_groups=frozenset(["GRP_SEC"]),
        )
        text = build_approvers_preview_text(client, [decision])
        assert ":information_source:" in text
        assert "<@U_ALICE>" in text
        assert "<@U_BOB>" in text
        assert "<!subteam^GRP_SEC>" in text

    def test_requires_approval_appends_unresolved_note(self):
        client = self._client_with_emails({"alice@test.com": "U_ALICE"})
        decision = self._make_decision(
            "RequiresApproval",
            grant=False,
            approvers=frozenset(["alice@test.com", "missing@test.com"]),
        )
        text = build_approvers_preview_text(client, [decision])
        assert "<@U_ALICE>" in text
        assert "could not match in Slack" in text
        assert "missing@test.com" in text

    def test_union_across_multiple_account_decisions(self):
        """Multi-account selection — preview text unions approvers from each account's decision."""
        client = self._client_with_emails(
            {
                "alice@test.com": "U_ALICE",
                "bob@test.com": "U_BOB",
                "carol@test.com": "U_CAROL",
            }
        )
        decision_a = self._make_decision(
            "RequiresApproval",
            grant=False,
            approvers=frozenset(["alice@test.com", "bob@test.com"]),
        )
        decision_b = self._make_decision(
            "RequiresApproval",
            grant=False,
            approvers=frozenset(["bob@test.com", "carol@test.com"]),
            approver_groups=frozenset(["GRP_SEC"]),
        )
        text = build_approvers_preview_text(client, [decision_a, decision_b])
        assert "<@U_ALICE>" in text
        assert "<@U_BOB>" in text
        assert "<@U_CAROL>" in text
        assert "<!subteam^GRP_SEC>" in text

    def test_mixed_grant_and_requires_approval_falls_through_to_approvers(self):
        """If one account auto-approves and another requires approval, preview shows approvers (not auto-approve text)."""
        client = self._client_with_emails({"alice@test.com": "U_ALICE"})
        decision_auto = self._make_decision("ApprovalNotRequired", grant=True)
        decision_req = self._make_decision(
            "RequiresApproval",
            grant=False,
            approvers=frozenset(["alice@test.com"]),
        )
        text = build_approvers_preview_text(client, [decision_auto, decision_req])
        assert ":information_source:" in text
        assert "<@U_ALICE>" in text


class TestApprovalRequestViewPreviewBlocks:
    """Tests for the new preview-block classmethods on RequestForAccessView."""

    def test_show_approvers_loading_inserts_loading_after_permission_set(self):
        permission_set = PermissionSet(name="Admin", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-123", description=None)
        view = RequestForAccessView.update_with_permission_sets(
            view_blocks=[
                {"type": "input", "block_id": RequestForAccessView.ACCOUNT_BLOCK_ID},
                {"type": "actions", "block_id": RequestForAccessView.LOAD_PS_BUTTON_BLOCK_ID},
                {"type": "input", "block_id": RequestForAccessView.PERMISSION_SET_PLACEHOLDER_BLOCK_ID},
            ],
            permission_sets=[permission_set],
        )
        view_with_loading = RequestForAccessView.show_approvers_loading(view.blocks)
        block_ids = [getattr(b, "block_id", None) or (b.get("block_id") if isinstance(b, dict) else None) for b in view_with_loading.blocks]
        assert RequestForAccessView.APPROVERS_LOADING_BLOCK_ID in block_ids
        # loading block should come after permission set block
        assert block_ids.index(RequestForAccessView.APPROVERS_LOADING_BLOCK_ID) > block_ids.index(
            RequestForAccessView.PERMISSION_SET_BLOCK_ID
        )

    def test_update_with_approvers_replaces_loading_block(self):
        permission_set = PermissionSet(name="Admin", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-123", description=None)
        view = RequestForAccessView.update_with_permission_sets(
            view_blocks=[
                {"type": "input", "block_id": RequestForAccessView.ACCOUNT_BLOCK_ID},
                {"type": "actions", "block_id": RequestForAccessView.LOAD_PS_BUTTON_BLOCK_ID},
                {"type": "input", "block_id": RequestForAccessView.PERMISSION_SET_PLACEHOLDER_BLOCK_ID},
            ],
            permission_sets=[permission_set],
        )
        view_with_loading = RequestForAccessView.show_approvers_loading(view.blocks)
        view_with_approvers = RequestForAccessView.update_with_approvers(view_with_loading.blocks, "*hello*")
        block_ids = [
            getattr(b, "block_id", None) or (b.get("block_id") if isinstance(b, dict) else None) for b in view_with_approvers.blocks
        ]
        assert RequestForAccessView.APPROVERS_BLOCK_ID in block_ids
        assert RequestForAccessView.APPROVERS_LOADING_BLOCK_ID not in block_ids

    def test_update_with_permission_sets_strips_stale_approver_preview(self):
        """Changing the account selection should clear an existing approver preview."""
        permission_set = PermissionSet(name="Admin", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-123", description=None)
        # Start with a view that has an existing approver preview block
        view = RequestForAccessView.update_with_permission_sets(
            view_blocks=[
                {"type": "input", "block_id": RequestForAccessView.ACCOUNT_BLOCK_ID},
                {"type": "actions", "block_id": RequestForAccessView.LOAD_PS_BUTTON_BLOCK_ID},
                {"type": "input", "block_id": RequestForAccessView.PERMISSION_SET_PLACEHOLDER_BLOCK_ID},
            ],
            permission_sets=[permission_set],
        )
        view_with_preview = RequestForAccessView.update_with_approvers(view.blocks, "*old preview*")
        # Now simulate updating permission sets again (new account selected)
        view_after = RequestForAccessView.update_with_permission_sets(
            view_blocks=view_with_preview.blocks,
            permission_sets=[permission_set],
        )
        block_ids = [getattr(b, "block_id", None) or (b.get("block_id") if isinstance(b, dict) else None) for b in view_after.blocks]
        assert RequestForAccessView.APPROVERS_BLOCK_ID not in block_ids


class TestGroupAccessViewPreviewBlocks:
    """Tests for the new preview-block classmethods on RequestForGroupAccessView."""

    def test_show_approvers_loading_inserts_after_group(self):
        view = RequestForGroupAccessView.show_approvers_loading([{"type": "input", "block_id": RequestForGroupAccessView.GROUP_BLOCK_ID}])
        block_ids = [getattr(b, "block_id", None) or (b.get("block_id") if isinstance(b, dict) else None) for b in view.blocks]
        assert RequestForGroupAccessView.APPROVERS_LOADING_BLOCK_ID in block_ids

    def test_update_with_approvers_replaces_loading(self):
        view = RequestForGroupAccessView.show_approvers_loading([{"type": "input", "block_id": RequestForGroupAccessView.GROUP_BLOCK_ID}])
        updated = RequestForGroupAccessView.update_with_approvers(view.blocks, "*hello*")
        block_ids = [getattr(b, "block_id", None) or (b.get("block_id") if isinstance(b, dict) else None) for b in updated.blocks]
        assert RequestForGroupAccessView.APPROVERS_BLOCK_ID in block_ids
        assert RequestForGroupAccessView.APPROVERS_LOADING_BLOCK_ID not in block_ids


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

    def test_none_duration_returns_empty(self):
        """Modal submitted before the duration field was rendered returns empty list (does not crash).

        The duration block is only inserted once accounts finish loading, so a fast submit can
        arrive with no duration value. Parsing must not raise.
        """
        obj = self._make_submission(["111111111111"])
        # Simulate the duration block not yet present in the view (submitted before accounts loaded)
        del obj["view"]["state"]["values"][RequestForAccessView.DURATION_BLOCK_ID]
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


def _acct(id_: str, name: str):  # noqa: ANN001, ANN201
    """Create an Account for testing."""

    return Account(id=id_, name=name)


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
        assert result == "EKS/kubectl access (eks-developer)"

    def test_match_by_arn(self):
        ps = _ps("AdminAccess", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-admin")
        result = RequestForAccessView._get_permission_set_display_name(
            ps, display_names={"arn:aws:sso:::permissionSet/ssoins-abc/ps-admin": "Full Admin"}
        )
        assert result == "Full Admin (AdminAccess)"

    def test_name_takes_priority_over_arn(self):
        ps = _ps("AdminAccess", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-admin")
        result = RequestForAccessView._get_permission_set_display_name(
            ps,
            display_names={
                "AdminAccess": "By Name",
                "arn:aws:sso:::permissionSet/ssoins-abc/ps-admin": "By ARN",
            },
        )
        assert result == "By Name (AdminAccess)"

    def test_no_match_falls_back_to_aws_name(self):
        ps = _ps("ReadOnly")
        result = RequestForAccessView._get_permission_set_display_name(ps, display_names={"SomethingElse": "Nope"})
        assert result == "ReadOnly"

    def test_display_name_equal_to_aws_name_not_duplicated(self):
        ps = _ps("AdminAccess")
        result = RequestForAccessView._get_permission_set_display_name(ps, display_names={"AdminAccess": "AdminAccess"})
        assert result == "AdminAccess"

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
        assert "Full Admin (AdminAccess)" in texts
        assert "Read-Only Access (ReadOnly)" in texts

    def test_options_sorted_by_display_name(self):
        psets = [_ps("ZZZ-admin"), _ps("AAA-readonly")]
        display = {"ZZZ-admin": "Alpha", "AAA-readonly": "Beta"}
        block = RequestForAccessView.build_select_permission_set_input_block(psets, display_names=display)
        texts = [_opt_text(opt) for opt in block.element.options]  # type: ignore[union-attr]
        assert texts == ["Alpha (ZZZ-admin)", "Beta (AAA-readonly)"]

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
        assert _opt_text(block.element.options[0]) == "Friendly Label (Admin)"  # type: ignore[union-attr]

    def test_mixed_matched_and_unmatched(self):
        psets = [_ps("Mapped"), _ps("Unmapped")]
        display = {"Mapped": "Custom Label"}
        block = RequestForAccessView.build_select_permission_set_input_block(psets, display_names=display)
        text_map = {_opt_text(opt) for opt in block.element.options}  # type: ignore[union-attr]
        assert text_map == {"Custom Label (Mapped)", "Unmapped"}

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
        assert texts == ["alpha (ZZZ)", "bravo (MMM)", "charlie (AAA)"]

    def test_option_groups_use_display_names(self):
        ps = _ps("eks-developer")
        display = {"eks-developer": "EKS/kubectl access"}
        block = RequestForAccessView.build_select_permission_set_input_block(
            [ps],
            display_names=display,
            auto_approved_arns={ps.arn},
        )
        groups = block.element.option_groups  # type: ignore[union-attr]
        assert _opt_text(groups[0].options[0]) == "EKS/kubectl access (eks-developer)"

    def test_option_groups_value_is_arn(self):
        ps = _ps("Admin", arn="arn:aws:sso:::permissionSet/ssoins-abc/ps-123")
        block = RequestForAccessView.build_select_permission_set_input_block(
            [ps],
            display_names={"Admin": "Friendly"},
            auto_approved_arns={ps.arn},
        )
        groups = block.element.option_groups  # type: ignore[union-attr]
        assert groups[0].options[0].value == "arn:aws:sso:::permissionSet/ssoins-abc/ps-123"


class TestBuildSelectAccountInputBlockSections:
    """Sectioning of the AWS account multi-select via the account_sections config."""

    def _build(self, accounts, sections):  # noqa: ANN001, ANN202
        return RequestForAccessView.build_select_account_input_block(accounts, account_sections=sections)

    def test_none_sections_uses_flat_sorted_options(self):
        accounts = [_acct("111111111111", "b"), _acct("222222222222", "a")]
        block = RequestForAccessView.build_select_account_input_block(accounts, account_sections=None)
        assert block.element.option_groups is None  # type: ignore[union-attr]
        assert block.element.options is not None  # type: ignore[union-attr]
        # Existing behavior preserved: flat list, alphabetical by name.
        assert [_opt_text(o) for o in block.element.options] == ["222222222222 - a", "111111111111 - b"]  # type: ignore[union-attr]

    def test_empty_sections_uses_flat_options(self):
        accounts = [_acct("111111111111", "a")]
        block = RequestForAccessView.build_select_account_input_block(accounts, account_sections=[])
        assert block.element.option_groups is None  # type: ignore[union-attr]
        assert block.element.options is not None  # type: ignore[union-attr]

    def test_groups_render_in_config_order(self):
        accounts = [
            _acct("111111111111", "prod-us"),
            _acct("333333333333", "infra-dev"),
            _acct("444444444444", "sandbox-a"),
        ]
        sections = [
            {"name": "Production", "accounts": ["111111111111"]},
            {"name": "Dev / Infra", "accounts": ["333333333333"]},
            {"name": "Sandbox", "accounts": ["444444444444"]},
        ]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        assert [_group_label(g) for g in groups] == ["Production", "Dev / Infra", "Sandbox"]

    def test_alphabetical_within_section(self):
        accounts = [
            _acct("111111111111", "zebra"),
            _acct("222222222222", "alpha"),
            _acct("333333333333", "mango"),
        ]
        sections = [{"name": "All", "accounts": ["111111111111", "222222222222", "333333333333"]}]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        assert [_opt_text(o) for o in groups[0].options] == [
            "222222222222 - alpha",
            "333333333333 - mango",
            "111111111111 - zebra",
        ]

    def test_unmapped_accounts_go_to_trailing_other_group(self):
        accounts = [_acct("111111111111", "prod"), _acct("999999999999", "mystery")]
        sections = [{"name": "Production", "accounts": ["111111111111"]}]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        assert [_group_label(g) for g in groups] == ["Production", "Other"]
        assert [_opt_text(o) for o in groups[1].options] == ["999999999999 - mystery"]

    def test_duplicate_id_first_section_wins(self):
        accounts = [_acct("111111111111", "shared")]
        sections = [
            {"name": "First", "accounts": ["111111111111"]},
            {"name": "Second", "accounts": ["111111111111"]},
        ]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        # Second section ends up empty and is omitted.
        assert [_group_label(g) for g in groups] == ["First"]
        assert [o.value for o in groups[0].options] == ["111111111111"]

    def test_ineligible_id_in_section_skipped(self):
        accounts = [_acct("111111111111", "prod")]
        sections = [{"name": "Production", "accounts": ["111111111111", "222222222222"]}]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        assert [_group_label(g) for g in groups] == ["Production"]
        assert [o.value for o in groups[0].options] == ["111111111111"]

    def test_empty_section_omitted(self):
        accounts = [_acct("111111111111", "prod")]
        sections = [
            {"name": "Empty", "accounts": ["888888888888"]},
            {"name": "Production", "accounts": ["111111111111"]},
        ]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        assert [_group_label(g) for g in groups] == ["Production"]

    def test_no_configured_section_matches_falls_back_to_flat(self):
        accounts = [_acct("111111111111", "prod")]
        sections = [{"name": "Nope", "accounts": ["888888888888"]}]
        block = self._build(accounts, sections)
        # No configured section produced members, so we avoid a lone "Other" header.
        assert block.element.option_groups is None  # type: ignore[union-attr]
        assert [o.value for o in block.element.options] == ["111111111111"]  # type: ignore[union-attr]

    def test_option_value_and_text_format(self):
        accounts = [_acct("111111111111", "prod-us")]
        sections = [{"name": "Production", "accounts": ["111111111111"]}]
        opt = self._build(accounts, sections).element.option_groups[0].options[0]  # type: ignore[union-attr]
        assert opt.value == "111111111111"
        assert _opt_text(opt) == "111111111111 - prod-us"

    def test_update_with_accounts_threads_sections(self):
        accounts = [_acct("111111111111", "prod"), _acct("999999999999", "x")]
        sections = [{"name": "Production", "accounts": ["111111111111"]}]
        view = RequestForAccessView.update_with_accounts(accounts, account_sections=sections)
        acct_block = next(b for b in view.blocks if getattr(b, "block_id", None) == RequestForAccessView.ACCOUNT_BLOCK_ID)
        assert [_group_label(g) for g in acct_block.element.option_groups] == ["Production", "Other"]  # type: ignore[union-attr]

    def test_grouped_view_serializes_to_valid_slack_json(self):
        # slack_sdk's JsonValidators only fire at serialization, so attribute asserts alone don't
        # prove the block is valid. Render the whole view to catch invalid labels/options.
        accounts = [_acct("111111111111", "prod"), _acct("999999999999", "mystery")]
        sections = [{"name": "Production", "accounts": ["111111111111"]}]
        view = RequestForAccessView.update_with_accounts(accounts, account_sections=sections)
        rendered = view.to_dict()  # raises SlackObjectFormationError if any block is invalid
        block = next(b for b in rendered["blocks"] if b.get("block_id") == RequestForAccessView.ACCOUNT_BLOCK_ID)
        labels = [g["label"]["text"] for g in block["element"]["option_groups"]]
        assert labels == ["Production", "Other"]
        # Every option-group label must carry non-empty text (Slack rejects a textless plain_text).
        for group in block["element"]["option_groups"]:
            assert group["label"]["text"]

    def test_blank_section_name_is_skipped_not_rendered_empty(self):
        # Empty/whitespace names can only reach the builder off the Terraform-validated path
        # (hand-edited S3 / env). They must be dropped, never emitted as an empty-text label.
        accounts = [_acct("111111111111", "prod")]
        sections = [{"name": "   ", "accounts": ["111111111111"]}]
        block = self._build(accounts, sections)
        # No configured section survived, so it falls back to a flat list (no empty-label group).
        assert block.element.option_groups is None  # type: ignore[union-attr]
        assert [o.value for o in block.element.options] == ["111111111111"]  # type: ignore[union-attr]
        block.element.to_dict()  # type: ignore[union-attr]  # must serialize cleanly

    def test_blank_name_with_other_valid_section_still_serializes(self):
        accounts = [_acct("111111111111", "prod"), _acct("222222222222", "dev")]
        sections = [{"name": "", "accounts": ["111111111111"]}, {"name": "Dev", "accounts": ["222222222222"]}]
        block = self._build(accounts, sections)
        groups = block.element.option_groups  # type: ignore[union-attr]
        # Blank-named section dropped; its account falls to Other. Dev renders normally.
        assert [_group_label(g) for g in groups] == ["Dev", "Other"]
        block.element.to_dict()  # type: ignore[union-attr]

    def test_non_dict_section_is_skipped(self):
        accounts = [_acct("111111111111", "prod")]
        sections = ["not-a-dict", {"name": "Production", "accounts": ["111111111111"]}]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        assert [_group_label(g) for g in groups] == ["Production"]

    def test_numeric_account_id_is_coerced_and_matched(self):
        # Hand-edited/env JSON may carry unquoted (int) ids; they should still group, not silently drop.
        accounts = [_acct("111111111111", "prod")]
        sections = [{"name": "Production", "accounts": [111111111111]}]
        groups = self._build(accounts, sections).element.option_groups  # type: ignore[union-attr]
        assert [_group_label(g) for g in groups] == ["Production"]
        assert [o.value for o in groups[0].options] == ["111111111111"]

    def test_non_list_accounts_field_is_skipped(self):
        accounts = [_acct("111111111111", "prod")]
        sections = [{"name": "Bad", "accounts": "111111111111"}]
        block = self._build(accounts, sections)
        assert block.element.option_groups is None  # type: ignore[union-attr]

    def test_flat_path_sort_is_case_insensitive(self):
        # Locks in the case-insensitive (name.lower()) flat-path ordering.
        accounts = [_acct("111111111111", "Zebra"), _acct("222222222222", "alpha")]
        block = RequestForAccessView.build_select_account_input_block(accounts, account_sections=None)
        assert [_opt_text(o) for o in block.element.options] == ["222222222222 - alpha", "111111111111 - Zebra"]  # type: ignore[union-attr]


class TestUpdateWithPermissionSets:
    """Tests for RequestForAccessView.update_with_permission_sets."""

    def _make_view_blocks(self) -> list:
        """Build a view and return its blocks after account selection (with placeholder)."""

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
        assert "Administrator (Admin)" in texts
        assert "Viewer (ReadOnly)" in texts

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


class TestRequestForAccessViewStructure:
    """Modal structure: reason deferred + ordered last, account select inert, load button present."""

    def _account(self, id_: str, name: str):
        return Account(id=id_, name=name)

    def _block_ids(self, view) -> list:  # noqa: ANN001
        from slack_helpers import get_block_id

        return [get_block_id(b) for b in view.blocks]

    def test_initial_build_has_no_reason_or_duration_block(self):
        view = RequestForAccessView.build()
        ids = self._block_ids(view)
        assert RequestForAccessView.REASON_BLOCK_ID not in ids
        assert RequestForAccessView.DURATION_BLOCK_ID not in ids
        assert RequestForAccessView.LOADING_BLOCK_ID in ids

    def test_build_sets_external_id(self):
        view = RequestForAccessView.build(external_id="req-access:abc.def")
        assert view.external_id == "req-access:abc.def"

    def test_update_with_accounts_orders_account_button_duration_reason(self):
        accounts = [self._account("111111111111", "prod"), self._account("222222222222", "dev")]
        view = RequestForAccessView.update_with_accounts(accounts)
        ids = self._block_ids(view)
        assert ids.index(RequestForAccessView.ACCOUNT_BLOCK_ID) < ids.index(RequestForAccessView.LOAD_PS_BUTTON_BLOCK_ID)
        assert ids.index(RequestForAccessView.LOAD_PS_BUTTON_BLOCK_ID) < ids.index(RequestForAccessView.DURATION_BLOCK_ID)
        assert ids.index(RequestForAccessView.DURATION_BLOCK_ID) < ids.index(RequestForAccessView.REASON_BLOCK_ID)
        assert RequestForAccessView.LOADING_BLOCK_ID not in ids

    def test_initial_build_has_no_submit_button(self):
        # No Request button until the form is loaded, so it cannot be submitted while accounts load.
        view = RequestForAccessView.build()
        assert view.submit is None

    def test_no_eligible_accounts_view_has_no_submit_button(self):
        # Terminal "no accounts" view has nothing to submit, so no Request button.
        view = RequestForAccessView.build_no_eligible_accounts_view()
        assert view.submit is None

    def test_update_with_accounts_has_submit_button(self):
        # Once the form (with inputs) is rendered, the Request button appears.
        view = RequestForAccessView.update_with_accounts([self._account("111111111111", "prod")])
        assert view.submit is not None

    def test_account_select_has_no_dispatch_action(self):
        accounts = [self._account("111111111111", "prod")]
        block = RequestForAccessView.build_select_account_input_block(accounts)
        assert getattr(block, "dispatch_action", False) in (False, None)

    def test_load_button_uses_load_action_id(self):
        block = RequestForAccessView.build_load_permission_sets_button_block()
        assert block.elements[0].action_id == RequestForAccessView.LOAD_PS_ACTION_ID  # type: ignore[union-attr]

    def test_update_with_permission_sets_inserts_after_button_and_keeps_reason(self):
        accounts = [self._account("111111111111", "prod")]
        view = RequestForAccessView.update_with_accounts(accounts)
        current_blocks = view.blocks
        updated = RequestForAccessView.update_with_permission_sets(
            view_blocks=current_blocks,
            permission_sets=[_ps("AdministratorAccess")],
        )
        ids = [b["block_id"] if isinstance(b, dict) else b.block_id for b in updated.blocks]
        assert ids.index(RequestForAccessView.LOAD_PS_BUTTON_BLOCK_ID) < ids.index(RequestForAccessView.PERMISSION_SET_BLOCK_ID)
        assert ids.index(RequestForAccessView.PERMISSION_SET_BLOCK_ID) < ids.index(RequestForAccessView.REASON_BLOCK_ID)
        assert updated.submit is not None


DOCS_URL = "https://runbooks.example.com/access#roles"


def _patch_docs_url(monkeypatch, url: str) -> None:  # noqa: ANN001
    """Override only `access_docs_url` on the real (frozen) config via model_copy, leaving the rest
    of the config intact so the duration block still builds."""
    monkeypatch.setattr(slack_helpers, "cfg", slack_helpers.cfg.model_copy(update={"access_docs_url": url}))


def _block_ids(view) -> list:  # noqa: ANN001
    return [slack_helpers.get_block_id(b) for b in view.blocks]


def _hint_text(view, block_id: str) -> str:  # noqa: ANN001
    block = next(b for b in view.blocks if slack_helpers.get_block_id(b) == block_id)
    return block.elements[0].text  # type: ignore[union-attr]


class TestAccountDocsHint:
    """Docs hint beside the permission-set dropdown in the account-access modal."""

    def _form_with_permission_sets(self):  # noqa: ANN202
        view = RequestForAccessView.update_with_accounts([_acct("111111111111", "prod")])
        return RequestForAccessView.update_with_permission_sets(view.blocks, [_ps("AdministratorAccess"), _ps("ReadOnly")])

    def test_hint_rendered_directly_below_dropdown_when_url_set(self, monkeypatch):  # noqa: ANN001
        _patch_docs_url(monkeypatch, DOCS_URL)
        view = self._form_with_permission_sets()
        ids = _block_ids(view)
        hint_id = RequestForAccessView.PERMISSION_SET_DOCS_HINT_BLOCK_ID
        assert ids.index(hint_id) == ids.index(RequestForAccessView.PERMISSION_SET_BLOCK_ID) + 1
        text = _hint_text(view, hint_id)
        assert DOCS_URL in text
        assert "See the access docs" in text

    def test_hint_absent_when_url_empty(self, monkeypatch):  # noqa: ANN001
        _patch_docs_url(monkeypatch, "")
        view = self._form_with_permission_sets()
        assert RequestForAccessView.PERMISSION_SET_DOCS_HINT_BLOCK_ID not in _block_ids(view)

    def test_hint_not_duplicated_after_account_reselection(self, monkeypatch):  # noqa: ANN001
        _patch_docs_url(monkeypatch, DOCS_URL)
        view = self._form_with_permission_sets()
        # Re-selecting an account: the loading state drops the hint, then it is rebuilt exactly once.
        view = RequestForAccessView.show_permission_set_loading(view.blocks)
        assert RequestForAccessView.PERMISSION_SET_DOCS_HINT_BLOCK_ID not in _block_ids(view)
        view = RequestForAccessView.update_with_permission_sets(view.blocks, [_ps("ReadOnly")])
        assert _block_ids(view).count(RequestForAccessView.PERMISSION_SET_DOCS_HINT_BLOCK_ID) == 1

    def test_order_is_dropdown_then_hint_then_approvers(self, monkeypatch):  # noqa: ANN001
        _patch_docs_url(monkeypatch, DOCS_URL)
        view = self._form_with_permission_sets()
        view = RequestForAccessView.update_with_approvers(view.blocks, "Requires approval from <@U1>")
        ids = _block_ids(view)
        assert (
            ids.index(RequestForAccessView.PERMISSION_SET_BLOCK_ID)
            < ids.index(RequestForAccessView.PERMISSION_SET_DOCS_HINT_BLOCK_ID)
            < ids.index(RequestForAccessView.APPROVERS_BLOCK_ID)
        )


def _sso_group(name: str, id_: str) -> SSOGroup:
    return SSOGroup(name=name, id=id_, description=None, identity_store_id="d-1")


class TestGroupDocsHint:
    """Docs hint beside the group dropdown in the group-access modal."""

    def test_hint_rendered_directly_below_dropdown_when_url_set(self, monkeypatch):  # noqa: ANN001
        _patch_docs_url(monkeypatch, DOCS_URL)
        view = RequestForGroupAccessView.update_with_groups([_sso_group("Engineering", "g-1")])
        ids = _block_ids(view)
        hint_id = RequestForGroupAccessView.GROUP_DOCS_HINT_BLOCK_ID
        assert ids.index(hint_id) == ids.index(RequestForGroupAccessView.GROUP_BLOCK_ID) + 1
        assert DOCS_URL in _hint_text(view, hint_id)

    def test_hint_absent_when_url_empty(self, monkeypatch):  # noqa: ANN001
        _patch_docs_url(monkeypatch, "")
        view = RequestForGroupAccessView.update_with_groups([_sso_group("Engineering", "g-1")])
        assert RequestForGroupAccessView.GROUP_DOCS_HINT_BLOCK_ID not in _block_ids(view)

    def test_order_is_dropdown_then_hint_then_approvers(self, monkeypatch):  # noqa: ANN001
        _patch_docs_url(monkeypatch, DOCS_URL)
        view = RequestForGroupAccessView.update_with_groups([_sso_group("Engineering", "g-1")])
        view = RequestForGroupAccessView.update_with_approvers(view.blocks, "Requires approval")
        ids = _block_ids(view)
        assert (
            ids.index(RequestForGroupAccessView.GROUP_BLOCK_ID)
            < ids.index(RequestForGroupAccessView.GROUP_DOCS_HINT_BLOCK_ID)
            < ids.index(RequestForGroupAccessView.APPROVERS_BLOCK_ID)
        )
