"""Tests for group module."""

from datetime import timedelta
from unittest.mock import MagicMock, patch
import sys

import pytest

import config  # noqa: F401 — must import before mock_group_imports patches boto3
import entities


@pytest.fixture(autouse=True)
def mock_group_imports():
    """Mock all the module-level side effects in group.py."""
    mock_session = MagicMock()
    mock_sso_client = MagicMock()
    mock_identity_store_client = MagicMock()
    mock_schedule_client = MagicMock()

    mock_session.client.side_effect = lambda service: {
        "sso-admin": mock_sso_client,
        "identitystore": mock_identity_store_client,
        "scheduler": mock_schedule_client,
    }.get(service, MagicMock())

    mock_cfg = MagicMock()
    mock_cfg.sso_instance_arn = "arn:aws:sso:::instance/ssoins-test"
    mock_cfg.slack_channel_id = "C12345"
    mock_cfg.group_statements = frozenset()
    mock_cfg.identity_store_id = "d-123456"
    mock_cfg.pending_status = "Pending"
    mock_cfg.granted_status = "Granted"
    mock_cfg.denied_status = "Denied"
    mock_cfg.approver_renotification_initial_wait_time = 15
    mock_cfg.send_dm_if_user_not_in_channel = False

    with patch.dict(sys.modules, {"boto3": MagicMock(_get_default_session=lambda: mock_session)}):
        with patch("config.get_config", return_value=mock_cfg):
            with patch("config.check_and_refresh_config", return_value=mock_cfg):
                with patch("sso.get_identity_store_id", return_value="d-123456"):
                    yield mock_cfg


@pytest.fixture()
def import_group(mock_group_imports):  # noqa: ARG001
    """Import group module with all side effects mocked."""
    sys.modules.pop("group", None)
    import group

    yield group

    sys.modules.pop("group", None)


class TestShowButtonsForApproverGroups:
    """Approve/Deny buttons must render whenever a group-access decision has
    approvers OR approver_groups.

    Regression: previously `show_buttons = bool(decision.approvers)` ignored
    approver_groups, leaving requests that only mentioned groups un-actionable.
    """

    def _body(self):
        # Minimal Slack view-submission payload shape (parse() is patched out anyway).
        return {"user": {"id": "U_REQUESTER"}, "view": {}}

    def _parsed_request(self):
        import slack_helpers

        return slack_helpers.RequestForGroupAccess(
            group_id="11111111-2222-3333-4444-555555555555",
            reason="Testing",
            requester_slack_id="U_REQUESTER",
            permission_duration=timedelta(hours=1),
        )

    def _decision(self, reason, approvers=frozenset(), approver_groups=frozenset()):
        import access_control

        return access_control.AccessRequestDecision(
            grant=False,
            reason=reason,
            based_on_statements=frozenset(),
            approvers=approvers,
            approver_groups=approver_groups,
        )

    def _setup_patches(self, group_module, decision):
        import access_control

        sso_group = entities.aws.SSOGroup(
            name="test-group",
            id="11111111-2222-3333-4444-555555555555",
            description=None,
            identity_store_id="d-123456",
        )

        return [
            patch.object(group_module.slack_helpers.RequestForGroupAccessView, "parse", return_value=self._parsed_request()),
            patch.object(
                group_module.slack_helpers,
                "get_user",
                return_value=entities.slack.User(id="U_REQUESTER", email="requester@test.com", real_name="Requester"),
            ),
            patch.object(
                group_module.slack_helpers,
                "get_user_by_email",
                return_value=entities.slack.User(id="U_APPROVER", email="approver@test.com", real_name="Approver"),
            ),
            patch.object(group_module.slack_helpers, "check_if_user_is_in_channel", return_value=True),
            patch.object(group_module.slack_helpers, "build_approval_request_message_blocks", return_value=[]),
            patch.object(group_module.slack_helpers, "build_approver_group_mentions", return_value="<!subteam^S_GROUP>"),
            patch.object(group_module.sso, "describe_group", return_value=sso_group),
            patch.object(group_module.access_control, "make_decision_on_access_request", return_value=decision),
            patch.object(
                group_module.access_control,
                "execute_decision_on_group_request",
                return_value=access_control.ExecuteDecisionResult(granted=False),
            ),
            patch.object(group_module.analytics, "capture"),
            patch.object(group_module.schedule, "schedule_discard_buttons_event"),
            patch.object(group_module.schedule, "schedule_approver_notification_event"),
        ]

    def _run(self, group_module):
        mock_client = MagicMock()
        mock_client.chat_postMessage.return_value = {"ts": "123.456", "message": {"blocks": []}}

        # Call the undecorated function to bypass @handle_errors' try/except swallow.
        handler = group_module.handle_request_for_group_access_submittion.__wrapped__
        handler(
            body=self._body(),
            ack=MagicMock(),
            client=mock_client,
            context=MagicMock(),
        )
        return mock_client

    def _show_buttons_kwarg(self, group_module):
        build = group_module.slack_helpers.build_approval_request_message_blocks
        assert build.called, "build_approval_request_message_blocks was not called"
        return build.call_args.kwargs["show_buttons"]

    def test_show_buttons_true_when_only_approver_groups(self, import_group):
        """Regression: approver_groups alone must still render buttons."""
        import access_control

        group = import_group
        decision = self._decision(
            reason=access_control.DecisionReason.RequiresApproval,
            approvers=frozenset(),
            approver_groups=frozenset(["S_GROUP"]),
        )
        patches = self._setup_patches(group, decision)
        for p in patches:
            p.start()
        try:
            self._run(group)
            assert self._show_buttons_kwarg(group) is True
            group.schedule.schedule_discard_buttons_event.assert_called_once()
            group.schedule.schedule_approver_notification_event.assert_called_once()
        finally:
            for p in patches:
                p.stop()

    def test_show_buttons_true_when_only_individual_approvers(self, import_group):
        import access_control

        group = import_group
        decision = self._decision(
            reason=access_control.DecisionReason.RequiresApproval,
            approvers=frozenset(["approver@test.com"]),
            approver_groups=frozenset(),
        )
        patches = self._setup_patches(group, decision)
        for p in patches:
            p.start()
        try:
            self._run(group)
            assert self._show_buttons_kwarg(group) is True
        finally:
            for p in patches:
                p.stop()

    def test_show_buttons_false_when_neither_set(self, import_group):
        import access_control

        group = import_group
        decision = self._decision(
            reason=access_control.DecisionReason.NoApprovers,
            approvers=frozenset(),
            approver_groups=frozenset(),
        )
        patches = self._setup_patches(group, decision)
        for p in patches:
            p.start()
        try:
            self._run(group)
            assert self._show_buttons_kwarg(group) is False
            group.schedule.schedule_discard_buttons_event.assert_not_called()
        finally:
            for p in patches:
                p.stop()


class TestDenyAuthorizationGroup:
    """Mirrors TestDenyAuthorization in test_main.py for the group-access flow."""

    REQUESTER_ID = "U_REQUESTER"
    APPROVER_ID = "U_APPROVER"
    RANDOM_ID = "U_RANDOM"
    GROUP_ID = "11111111-2222-3333-4444-555555555555"

    def _payload(self, clicker_slack_id: str):
        import slack_helpers

        return slack_helpers.ButtonGroupClickedPayload.model_construct(
            action=entities.ApproverAction.Deny,
            approver_slack_id=clicker_slack_id,
            thread_ts="123.456",
            channel_id="C12345",
            message={"blocks": []},
            request=slack_helpers.RequestForGroupAccess(
                group_id=self.GROUP_ID,
                reason="Testing",
                requester_slack_id=self.REQUESTER_ID,
                permission_duration=timedelta(hours=1),
            ),
        )

    def _user(self, user_id: str, email: str):
        return entities.slack.User(id=user_id, email=email, real_name=user_id)

    def _setup_patches(self, group_module, clicker_slack_id: str, clicker_email: str, decision_permit: bool):
        import access_control
        import slack_helpers

        user_by_id = {
            self.REQUESTER_ID: self._user(self.REQUESTER_ID, "requester@test.com"),
            self.APPROVER_ID: self._user(self.APPROVER_ID, "approver@test.com"),
            self.RANDOM_ID: self._user(self.RANDOM_ID, "random@test.com"),
        }
        user_by_id[clicker_slack_id] = self._user(clicker_slack_id, clicker_email)

        return [
            patch.object(
                slack_helpers.ButtonGroupClickedPayload,
                "model_validate",
                return_value=self._payload(clicker_slack_id),
            ),
            patch.object(
                group_module.slack_helpers,
                "get_user",
                side_effect=lambda _client, id: user_by_id[id],
            ),
            patch.object(group_module.slack_helpers, "check_if_user_is_in_channel", return_value=True),
            patch.object(group_module.slack_helpers, "remove_blocks", return_value=[]),
            patch.object(
                group_module.slack_helpers.HeaderSectionBlock,
                "set_status",
                return_value=[],
            ),
            patch.object(
                group_module.access_control,
                "make_decision_on_approve_request",
                return_value=access_control.ApproveRequestDecision(
                    grant=False,
                    permit=decision_permit,
                    based_on_statements=frozenset(),
                ),
            ),
        ]

    def _run(self, group_module):
        mock_client = MagicMock()
        handler = group_module.handle_group_button_click.__wrapped__
        handler(body={"foo": "bar"}, client=mock_client, context=MagicMock())
        group_module.cache_for_dublicate_requests.clear()
        return mock_client

    def test_requester_can_cancel_own_request(self, import_group):
        group = import_group
        patches = self._setup_patches(
            group,
            clicker_slack_id=self.REQUESTER_ID,
            clicker_email="requester@test.com",
            decision_permit=False,
        )
        for p in patches:
            p.start()
        try:
            mock_client = self._run(group)
            update_calls = mock_client.chat_update.call_args_list
            assert len(update_calls) == 1
            assert update_calls[0].kwargs["text"] == f"Request was cancelled by <@{self.REQUESTER_ID}>."
            post_texts = [c.kwargs.get("text", "") for c in mock_client.chat_postMessage.call_args_list]
            assert not any("You cannot" in t for t in post_texts)
            assert any("cancelled" in t for t in post_texts)
        finally:
            for p in patches:
                p.stop()

    def test_random_user_cannot_deny(self, import_group):
        group = import_group
        patches = self._setup_patches(
            group,
            clicker_slack_id=self.RANDOM_ID,
            clicker_email="random@test.com",
            decision_permit=False,
        )
        for p in patches:
            p.start()
        try:
            mock_client = self._run(group)
            assert mock_client.chat_update.call_count == 0
            post_texts = [c.kwargs.get("text", "") for c in mock_client.chat_postMessage.call_args_list]
            assert any("You cannot deny" in t for t in post_texts)
        finally:
            for p in patches:
                p.stop()

    def test_approver_can_still_deny(self, import_group):
        group = import_group
        patches = self._setup_patches(
            group,
            clicker_slack_id=self.APPROVER_ID,
            clicker_email="approver@test.com",
            decision_permit=True,
        )
        for p in patches:
            p.start()
        try:
            mock_client = self._run(group)
            update_calls = mock_client.chat_update.call_args_list
            assert len(update_calls) == 1
            assert update_calls[0].kwargs["text"] == f"Request was denied by <@{self.APPROVER_ID}>."
        finally:
            for p in patches:
                p.stop()
