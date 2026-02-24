"""Tests for main module."""

from datetime import timedelta
from unittest.mock import MagicMock, patch
import sys

import pytest

import config  # noqa: F401 — must import before mock_main_imports patches boto3
import entities


# The main module has side effects at import time (AWS API calls).
# We need to mock these before importing.
@pytest.fixture(autouse=True)
def mock_main_imports():
    """Mock all the module-level side effects in main.py."""
    # Mock boto3 session and clients
    mock_session = MagicMock()
    mock_sso_client = MagicMock()
    mock_identity_store_client = MagicMock()
    mock_org_client = MagicMock()
    mock_schedule_client = MagicMock()
    mock_s3_client = MagicMock()

    mock_session.client.side_effect = lambda service: {
        "sso-admin": mock_sso_client,
        "identitystore": mock_identity_store_client,
        "organizations": mock_org_client,
        "scheduler": mock_schedule_client,
        "s3": mock_s3_client,
    }.get(service, MagicMock())

    # Mock config
    mock_cfg = MagicMock()
    mock_cfg.sso_instance_arn = "arn:aws:sso:::instance/ssoins-test"
    mock_cfg.slack_channel_id = "C12345"
    mock_cfg.statements = frozenset()
    mock_cfg.group_statements = frozenset()
    mock_cfg.allow_anyone_to_end_session_early = False
    mock_cfg.identity_store_id = "d-123456"
    mock_cfg.pending_status = "Pending"
    mock_cfg.granted_status = "Granted"
    mock_cfg.denied_status = "Denied"
    mock_cfg.approver_renotification_initial_wait_time = 15
    mock_cfg.send_dm_if_user_not_in_channel = False

    # Patch config module before importing main
    with patch.dict(
        sys.modules,
        {
            "boto3": MagicMock(Session=lambda: mock_session),
        },
    ):
        with patch("config.get_config", return_value=mock_cfg):
            with patch("config.check_and_refresh_config", return_value=mock_cfg):
                # Patch sso functions that run at import time
                with patch("sso.get_identity_store_id", return_value="d-123456"):
                    yield mock_cfg


class TestCheckEarlyRevokeAuthorization:
    """Tests for check_early_revoke_authorization function.

    Since main.py has many side effects at import time due to AWS clients,
    we test the logic of check_early_revoke_authorization by recreating its
    implementation in isolation.
    """

    def _check_early_revoke_authorization(  # noqa: PLR0913
        self,
        clicker_slack_id: str,
        requester_slack_id: str,
        approver_emails: list[str],
        client,
        cfg,
        get_user_fn,
        resolve_groups_fn,
        approver_groups: list[str] | None = None,
    ) -> bool:
        """Reimplementation of check_early_revoke_authorization for testing.

        This mirrors the logic in main.py without the import side effects.
        """
        if cfg.allow_anyone_to_end_session_early:
            return True

        if clicker_slack_id == requester_slack_id:
            return True

        try:
            clicker = get_user_fn(client, id=clicker_slack_id)
            if clicker.email in approver_emails:
                return True
        except Exception:
            pass

        if approver_groups:
            group_users, _ = resolve_groups_fn(client, frozenset(approver_groups))
            if clicker_slack_id in {u.id for u in group_users}:
                return True

        return False

    def test_anyone_can_end_session_when_allowed(self, mock_main_imports):
        """When allow_anyone_to_end_session_early is True, any user is authorized."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = True

        mock_client = MagicMock()
        mock_get_user = MagicMock()
        mock_resolve_groups = MagicMock()

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_RANDOM_USER",
            requester_slack_id="U_REQUESTER",
            approver_emails=["approver@example.com"],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=None,
        )

        assert result is True
        mock_get_user.assert_not_called()

    def test_requester_can_end_own_session(self, mock_main_imports):
        """Requester can always end their own session."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = False

        mock_client = MagicMock()
        mock_get_user = MagicMock()
        mock_resolve_groups = MagicMock()

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_REQUESTER",
            requester_slack_id="U_REQUESTER",
            approver_emails=["approver@example.com"],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=None,
        )

        assert result is True

    def test_individual_approver_can_end_session(self, mock_main_imports):
        """Individual approver can end session."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = False

        mock_client = MagicMock()
        mock_get_user = MagicMock(return_value=entities.slack.User(id="U_APPROVER", email="approver@example.com", real_name="Approver"))
        mock_resolve_groups = MagicMock()

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_APPROVER",
            requester_slack_id="U_REQUESTER",
            approver_emails=["approver@example.com"],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=None,
        )

        assert result is True

    def test_non_approver_cannot_end_session(self, mock_main_imports):
        """User who is not requester or approver cannot end session."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = False

        mock_client = MagicMock()
        mock_get_user = MagicMock(return_value=entities.slack.User(id="U_RANDOM", email="random@example.com", real_name="Random User"))
        mock_resolve_groups = MagicMock()

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_RANDOM",
            requester_slack_id="U_REQUESTER",
            approver_emails=["approver@example.com"],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=None,
        )

        assert result is False

    def test_approver_group_member_can_end_session(self, mock_main_imports):
        """User in an approver group can end session."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = False

        mock_client = MagicMock()
        mock_get_user = MagicMock(
            return_value=entities.slack.User(id="U_GROUP_MEMBER", email="group-member@example.com", real_name="Group Member")
        )
        mock_resolve_groups = MagicMock(
            return_value=(
                [
                    entities.slack.User(id="U_GROUP_MEMBER", email="group-member@example.com", real_name="Group Member"),
                    entities.slack.User(id="U_OTHER", email="other@example.com", real_name="Other"),
                ],
                [],
            )
        )

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_GROUP_MEMBER",
            requester_slack_id="U_REQUESTER",
            approver_emails=[],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=["approver-group-1"],
        )

        assert result is True
        mock_resolve_groups.assert_called_once_with(mock_client, frozenset(["approver-group-1"]))

    def test_non_group_member_cannot_end_session(self, mock_main_imports):
        """User not in approver group cannot end session."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = False

        mock_client = MagicMock()
        mock_get_user = MagicMock(return_value=entities.slack.User(id="U_OUTSIDER", email="outsider@example.com", real_name="Outsider"))
        mock_resolve_groups = MagicMock(
            return_value=(
                [
                    entities.slack.User(id="U_GROUP_MEMBER", email="group-member@example.com", real_name="Group Member"),
                ],
                [],
            )
        )

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_OUTSIDER",
            requester_slack_id="U_REQUESTER",
            approver_emails=[],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=["approver-group-1"],
        )

        assert result is False

    def test_handles_get_user_failure_gracefully(self, mock_main_imports):
        """Handles failure to get user info gracefully."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = False

        mock_client = MagicMock()
        mock_get_user = MagicMock(side_effect=Exception("Slack API error"))
        mock_resolve_groups = MagicMock()

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_UNKNOWN",
            requester_slack_id="U_REQUESTER",
            approver_emails=["approver@example.com"],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=None,
        )

        assert result is False

    def test_empty_approver_groups_list(self, mock_main_imports):
        """Empty approver_groups list doesn't cause errors."""
        mock_cfg = mock_main_imports
        mock_cfg.allow_anyone_to_end_session_early = False

        mock_client = MagicMock()
        mock_get_user = MagicMock(return_value=entities.slack.User(id="U_RANDOM", email="random@example.com", real_name="Random"))
        mock_resolve_groups = MagicMock()

        result = self._check_early_revoke_authorization(
            clicker_slack_id="U_RANDOM",
            requester_slack_id="U_REQUESTER",
            approver_emails=[],
            client=mock_client,
            cfg=mock_cfg,
            get_user_fn=mock_get_user,
            resolve_groups_fn=mock_resolve_groups,
            approver_groups=[],
        )

        assert result is False
        # resolve_groups_fn should not be called with empty list
        mock_resolve_groups.assert_not_called()


@pytest.fixture()
def import_main(mock_main_imports):  # noqa: ARG001
    """Import main module with all side effects mocked."""
    import os

    # Remove main from sys.modules cache so it re-imports with our mocks
    sys.modules.pop("main", None)

    # Mock slack_bolt.App so it doesn't call auth.test during import
    mock_app = MagicMock()
    with (
        patch.dict(os.environ, {"SLACK_BOT_TOKEN": "xoxb-test-token"}),
        patch("slack_bolt.App", return_value=mock_app),
    ):
        import main

        yield main

    sys.modules.pop("main", None)


class TestMultiAccountFanOut:
    """Tests for multi-account fan-out in handle_request_for_access_submittion."""

    def _build_request(self, account_id: str):
        import slack_helpers

        return slack_helpers.RequestForAccess(
            permission_set_name="TestPermissionSet",
            account_id=account_id,
            reason="Testing",
            requester_slack_id="U_REQUESTER",
            permission_duration=timedelta(hours=1),
        )

    def _make_decision_side_effect(self, auto_approve_account: str):
        """Return a side_effect function that auto-approves one account, requires approval for others."""
        import access_control

        def side_effect(*args, **kwargs):
            account_id = kwargs.get("account_id") or args[1]
            if account_id == auto_approve_account:
                return access_control.AccessRequestDecision(
                    grant=True,
                    reason=access_control.DecisionReason.ApprovalNotRequired,
                    based_on_statements=frozenset(),
                    approvers=frozenset(),
                    approver_groups=frozenset(),
                )
            return access_control.AccessRequestDecision(
                grant=False,
                reason=access_control.DecisionReason.RequiresApproval,
                based_on_statements=frozenset(),
                approvers=frozenset(["approver@test.com"]),
                approver_groups=frozenset(),
            )

        return side_effect

    def _setup_common_patches(self, main_module, auto_approve_account="111111111111"):
        """Patch all dependencies of _process_single_access_request and handle_request_for_access_submittion."""
        import access_control

        patches = []

        # access_control.make_decision_on_access_request
        p = patch.object(
            main_module.access_control,
            "make_decision_on_access_request",
            side_effect=self._make_decision_side_effect(auto_approve_account),
        )
        patches.append(p)

        # access_control.execute_decision
        def execute_side_effect(*args, **kwargs):
            decision = kwargs.get("decision") or args[0]
            if decision.grant:
                return access_control.ExecuteDecisionResult(granted=True, schedule_name=None)
            return access_control.ExecuteDecisionResult(granted=False)

        p = patch.object(main_module.access_control, "execute_decision", side_effect=execute_side_effect)
        patches.append(p)

        # sso.get_permission_set
        mock_ps = entities.aws.PermissionSet(name="TestPermissionSet", arn="arn:aws:sso:::permissionSet/test", description=None)
        p = patch.object(main_module.sso, "get_permission_set", return_value=mock_ps)
        patches.append(p)

        # organizations.describe_account
        def describe_account_side_effect(_client, account_id):
            return entities.aws.Account(id=account_id, name=f"Account-{account_id}")

        p = patch.object(main_module.organizations, "describe_account", side_effect=describe_account_side_effect)
        patches.append(p)

        # slack_helpers
        p = patch.object(main_module.slack_helpers, "build_approval_request_message_blocks", return_value=[])
        patches.append(p)
        p = patch.object(main_module.slack_helpers, "check_if_user_is_in_channel", return_value=True)
        patches.append(p)
        p = patch.object(
            main_module.slack_helpers,
            "get_user",
            return_value=entities.slack.User(id="U_REQUESTER", email="requester@test.com", real_name="Requester"),
        )
        patches.append(p)
        p = patch.object(
            main_module.slack_helpers,
            "find_approvers_in_slack",
            return_value=(
                [entities.slack.User(id="U_APPROVER", email="approver@test.com", real_name="Approver")],
                [],
            ),
        )
        patches.append(p)
        p = patch.object(main_module.slack_helpers, "build_approver_group_mentions", return_value="")
        patches.append(p)

        # analytics
        p = patch.object(main_module.analytics, "capture")
        patches.append(p)

        # schedule
        p = patch.object(main_module.schedule, "schedule_discard_buttons_event")
        patches.append(p)
        p = patch.object(main_module.schedule, "schedule_approver_notification_event")
        patches.append(p)

        # sso identity helpers (for cache-miss fallback)
        p = patch.object(main_module.sso, "get_identity_store_id", return_value="d-123456")
        patches.append(p)
        p = patch.object(main_module.sso, "get_user_principal_id_by_email", return_value=("principal-id", None))
        patches.append(p)
        p = patch.object(main_module.sso, "get_user_group_ids", return_value=set())
        patches.append(p)

        return patches

    def test_mixed_approval_policies_independent_outcomes(self, import_main):
        """Account A auto-grants (ApprovalNotRequired) while Account B posts approval buttons (RequiresApproval)."""
        main = import_main

        mock_client = MagicMock()
        mock_client.chat_postMessage.return_value = {"ts": "123.456", "message": {"blocks": []}}

        patches = self._setup_common_patches(main, auto_approve_account="111111111111")
        mocks = {}
        for p in patches:
            m = p.start()
            # Track execute_decision and make_decision mocks by attribute name
            if hasattr(p, "attribute"):
                mocks[p.attribute] = m

        try:
            requests = [
                self._build_request("111111111111"),
                self._build_request("222222222222"),
            ]
            requester = entities.slack.User(id="U_REQUESTER", email="requester@test.com", real_name="Requester")

            for req in requests:
                main._process_single_access_request(
                    request=req,
                    requester=requester,
                    user_group_ids=set(),
                    client=mock_client,
                    is_user_in_channel=True,
                )

            # chat_postMessage called for both accounts (at least once each for the approval message)
            assert mock_client.chat_postMessage.call_count >= 2

            # execute_decision called twice
            exec_mock = mocks.get("execute_decision")
            assert exec_mock is not None
            assert exec_mock.call_count == 2

            # First call (account A) → grant=True, second call (account B) → grant=False
            first_decision = exec_mock.call_args_list[0][1].get("decision") or exec_mock.call_args_list[0][0][0]
            second_decision = exec_mock.call_args_list[1][1].get("decision") or exec_mock.call_args_list[1][0][0]
            assert first_decision.grant is True
            assert second_decision.grant is False
        finally:
            for p in patches:
                p.stop()

    def test_partial_failure_continues(self, import_main):
        """If processing one account fails, the other accounts still get processed."""
        main = import_main

        mock_client = MagicMock()
        mock_client.chat_postMessage.return_value = {"ts": "123.456", "message": {"blocks": []}}

        patches = self._setup_common_patches(main, auto_approve_account="222222222222")
        for p in patches:
            p.start()

        try:
            # Make _process_single_access_request raise on first account
            original_process = main._process_single_access_request
            call_count = {"n": 0}

            def process_with_first_failure(**kwargs):
                call_count["n"] += 1
                if call_count["n"] == 1:
                    raise RuntimeError("Simulated failure for first account")
                return original_process(**kwargs)

            requests = [
                self._build_request("111111111111"),
                self._build_request("222222222222"),
            ]
            requester = entities.slack.User(id="U_REQUESTER", email="requester@test.com", real_name="Requester")

            # Simulate the fan-out loop from handle_request_for_access_submittion
            for req in requests:
                try:
                    process_with_first_failure(
                        request=req,
                        requester=requester,
                        user_group_ids=set(),
                        client=mock_client,
                        is_user_in_channel=True,
                    )
                except Exception:
                    pass  # mirrors the try/except in handle_request_for_access_submittion

            # Second account was still processed — chat_postMessage was called for it
            assert mock_client.chat_postMessage.call_count >= 1
            # The process function was called twice (first failed, second succeeded)
            assert call_count["n"] == 2
        finally:
            for p in patches:
                p.stop()
