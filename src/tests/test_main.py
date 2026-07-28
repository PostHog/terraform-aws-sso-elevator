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
    mock_cfg.max_permissions_duration_time = 8
    mock_cfg.permission_duration_list_override = None
    mock_cfg.permission_set_display_names = None

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


class TestClassifyAutoApprovedPermissionSets:
    """Tests for classify_auto_approved_permission_sets."""

    def _ps(self, name: str, arn: str = "") -> entities.aws.PermissionSet:
        return entities.aws.PermissionSet(name=name, arn=arn or f"arn:sso:ps/{name}", description=None)

    def _decision(self, grant: bool):
        import access_control

        reason = access_control.DecisionReason.ApprovalNotRequired if grant else access_control.DecisionReason.RequiresApproval
        return access_control.AccessRequestDecision(
            grant=grant,
            reason=reason,
            based_on_statements=frozenset(),
            approvers=frozenset() if grant else frozenset(["approver@test.com"]),
            approver_groups=frozenset(),
        )

    def test_auto_approved_for_all_accounts(self, import_main):
        main = import_main
        ps = self._ps("ReadOnly")

        with patch.object(main.access_control, "make_decision_on_access_request", return_value=self._decision(grant=True)):
            result = main.classify_auto_approved_permission_sets(
                statements=frozenset(),
                permission_sets=[ps],
                account_ids=["111", "222"],
                requester_email="user@test.com",
                user_group_ids=set(),
                requester_slack_id="U123",
            )
        assert ps.arn in result

    def test_requires_approval_for_all_accounts(self, import_main):
        main = import_main
        ps = self._ps("Admin")

        with patch.object(main.access_control, "make_decision_on_access_request", return_value=self._decision(grant=False)):
            result = main.classify_auto_approved_permission_sets(
                statements=frozenset(),
                permission_sets=[ps],
                account_ids=["111", "222"],
                requester_email="user@test.com",
                user_group_ids=set(),
                requester_slack_id="U123",
            )
        assert ps.arn not in result

    def test_mixed_accounts_requires_approval(self, import_main):
        """PS auto-approved for account 111 but not 222 → not in auto_approved set."""
        main = import_main
        ps = self._ps("MixedRole")

        def side_effect(*_args, **kwargs):
            if kwargs.get("account_id") == "111":
                return self._decision(grant=True)
            return self._decision(grant=False)

        with patch.object(main.access_control, "make_decision_on_access_request", side_effect=side_effect):
            result = main.classify_auto_approved_permission_sets(
                statements=frozenset(),
                permission_sets=[ps],
                account_ids=["111", "222"],
                requester_email="user@test.com",
                user_group_ids=set(),
                requester_slack_id="U123",
            )
        assert ps.arn not in result

    def test_multiple_permission_sets_classified_independently(self, import_main):
        """Each PS is classified independently — one can be auto, another manual."""
        main = import_main
        ps_auto = self._ps("ReadOnly")
        ps_manual = self._ps("Admin")

        def side_effect(*_args, **kwargs):
            if kwargs.get("permission_set_name") == "ReadOnly":
                return self._decision(grant=True)
            return self._decision(grant=False)

        with patch.object(main.access_control, "make_decision_on_access_request", side_effect=side_effect):
            result = main.classify_auto_approved_permission_sets(
                statements=frozenset(),
                permission_sets=[ps_auto, ps_manual],
                account_ids=["111"],
                requester_email="user@test.com",
                user_group_ids=set(),
                requester_slack_id="U123",
            )
        assert ps_auto.arn in result
        assert ps_manual.arn not in result


class TestGetCachedUserInfo:
    """Tests for _get_cached_user_info re-fetching user info on cache miss."""

    def test_cache_hit_returns_cached_values(self, import_main):
        """When group_ids are cached, returns cached values without API calls."""
        main = import_main
        main.user_view_map.clear()

        view_key = "U_CACHED:request_for__account_access_submitted"
        main.user_view_map[f"{view_key}:group_ids"] = {"group-1"}
        main.user_view_map[f"{view_key}:user_email"] = "cached@test.com"

        mock_client = MagicMock()

        with (
            patch.object(main.sso, "get_identity_store_id") as mock_get_id,
            patch.object(main.sso, "get_user_principal_id_by_email") as mock_get_principal,
            patch.object(main.sso, "get_user_group_ids") as mock_get_groups,
        ):
            group_ids, email = main._get_cached_user_info(view_key, "U_CACHED", mock_client)

            mock_get_id.assert_not_called()
            mock_get_principal.assert_not_called()
            mock_get_groups.assert_not_called()

        assert group_ids == {"group-1"}
        assert email == "cached@test.com"

    def test_cache_miss_refetches_from_identity_center(self, import_main):
        """When group_ids are not cached, re-fetches from Identity Center."""
        main = import_main
        main.user_view_map.clear()

        view_key = "U_COLD:request_for__account_access_submitted"
        refetched_groups = {"group-dev", "group-admin"}

        mock_client = MagicMock()

        with (
            patch.object(main.sso, "get_identity_store_id", return_value="d-123456"),
            patch.object(
                main.slack_helpers,
                "get_user",
                return_value=entities.slack.User(id="U_COLD", email="cold@test.com", real_name="Cold User"),
            ),
            patch.object(main.sso, "get_user_principal_id_by_email", return_value=("principal-cold", None)),
            patch.object(main.sso, "get_user_group_ids", return_value=refetched_groups) as mock_get_groups,
        ):
            group_ids, email = main._get_cached_user_info(view_key, "U_COLD", mock_client)

            mock_get_groups.assert_called_once()

        assert group_ids == refetched_groups
        assert email == "cold@test.com"

    def test_cache_miss_repopulates_cache(self, import_main):
        """After re-fetching, user info is stored back in the cache."""
        main = import_main
        main.user_view_map.clear()

        view_key = "U_REPOP:request_for__account_access_submitted"
        mock_client = MagicMock()

        with (
            patch.object(main.sso, "get_identity_store_id", return_value="d-123456"),
            patch.object(
                main.slack_helpers,
                "get_user",
                return_value=entities.slack.User(id="U_REPOP", email="repop@test.com", real_name="Repop User"),
            ),
            patch.object(main.sso, "get_user_principal_id_by_email", return_value=("principal-repop", None)),
            patch.object(main.sso, "get_user_group_ids", return_value={"group-x"}),
        ):
            main._get_cached_user_info(view_key, "U_REPOP", mock_client)

        assert main.user_view_map[f"{view_key}:group_ids"] == {"group-x"}
        assert main.user_view_map[f"{view_key}:user_principal_id"] == "principal-repop"
        assert main.user_view_map[f"{view_key}:user_email"] == "repop@test.com"

    def test_second_call_after_refetch_uses_cache(self, import_main):
        """After a cache miss repopulates, the next call uses the cache."""
        main = import_main
        main.user_view_map.clear()

        view_key = "U_TWICE:request_for__account_access_submitted"
        mock_client = MagicMock()

        with (
            patch.object(main.sso, "get_identity_store_id", return_value="d-123456"),
            patch.object(
                main.slack_helpers,
                "get_user",
                return_value=entities.slack.User(id="U_TWICE", email="twice@test.com", real_name="Twice User"),
            ),
            patch.object(main.sso, "get_user_principal_id_by_email", return_value=("principal-twice", None)),
            patch.object(main.sso, "get_user_group_ids", return_value={"group-y"}) as mock_get_groups,
        ):
            # First call: cache miss, re-fetches
            main._get_cached_user_info(view_key, "U_TWICE", mock_client)
            assert mock_get_groups.call_count == 1

            # Second call: cache hit, no re-fetch
            group_ids, email = main._get_cached_user_info(view_key, "U_TWICE", mock_client)
            assert mock_get_groups.call_count == 1  # still 1, not 2

        assert group_ids == {"group-y"}
        assert email == "twice@test.com"


class TestShowButtonsForApproverGroups:
    """Approve/Deny buttons must render whenever a decision has approvers OR approver_groups.

    Regression: previously `show_buttons = bool(decision.approvers)` ignored approver_groups,
    leaving requests that only mentioned groups un-actionable in Slack.
    """

    def _build_request(self):
        import slack_helpers

        return slack_helpers.RequestForAccess(
            permission_set_name="TestPermissionSet",
            account_id="111111111111",
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

    def _setup_patches(self, main_module, decision):
        import access_control

        patches = [
            patch.object(main_module.access_control, "make_decision_on_access_request", return_value=decision),
            patch.object(
                main_module.access_control,
                "execute_decision",
                return_value=access_control.ExecuteDecisionResult(granted=False),
            ),
            patch.object(
                main_module.sso,
                "get_permission_set",
                return_value=entities.aws.PermissionSet(name="TestPermissionSet", arn="arn:sso:ps/test", description=None),
            ),
            patch.object(main_module.sso, "get_identity_store_id", return_value="d-123456"),
            patch.object(main_module.sso, "get_user_principal_id_by_email", return_value=("principal-id", None)),
            patch.object(
                main_module.organizations,
                "describe_account",
                side_effect=lambda _c, account_id: entities.aws.Account(id=account_id, name=f"Account-{account_id}"),
            ),
            patch.object(main_module.slack_helpers, "build_approval_request_message_blocks", return_value=[]),
            patch.object(main_module.slack_helpers, "check_if_user_is_in_channel", return_value=True),
            patch.object(
                main_module.slack_helpers,
                "get_user",
                return_value=entities.slack.User(id="U_REQUESTER", email="requester@test.com", real_name="Requester"),
            ),
            patch.object(main_module.slack_helpers, "find_approvers_in_slack", return_value=([], [])),
            patch.object(main_module.slack_helpers, "build_approver_group_mentions", return_value="<!subteam^S_GROUP>"),
            patch.object(main_module.analytics, "capture"),
            patch.object(main_module.schedule, "schedule_discard_buttons_event"),
            patch.object(main_module.schedule, "schedule_approver_notification_event"),
        ]
        return patches

    def _run(self, main_module):
        mock_client = MagicMock()
        mock_client.chat_postMessage.return_value = {"ts": "123.456", "message": {"blocks": []}}
        main_module._process_single_access_request(
            request=self._build_request(),
            requester=entities.slack.User(id="U_REQUESTER", email="requester@test.com", real_name="Requester"),
            user_group_ids=set(),
            client=mock_client,
            is_user_in_channel=True,
        )
        return mock_client

    def _show_buttons_kwarg(self, main_module):
        build = main_module.slack_helpers.build_approval_request_message_blocks
        assert build.called, "build_approval_request_message_blocks was not called"
        return build.call_args.kwargs["show_buttons"]

    def test_show_buttons_true_when_only_approver_groups(self, import_main):
        """Regression: approver_groups alone must still render buttons."""
        import access_control

        main = import_main
        decision = self._decision(
            reason=access_control.DecisionReason.RequiresApproval,
            approvers=frozenset(),
            approver_groups=frozenset(["S_GROUP"]),
        )
        patches = self._setup_patches(main, decision)
        for p in patches:
            p.start()
        try:
            self._run(main)
            assert self._show_buttons_kwarg(main) is True
            main.schedule.schedule_discard_buttons_event.assert_called_once()
            main.schedule.schedule_approver_notification_event.assert_called_once()
        finally:
            for p in patches:
                p.stop()

    def test_show_buttons_true_when_only_individual_approvers(self, import_main):
        import access_control

        main = import_main
        decision = self._decision(
            reason=access_control.DecisionReason.RequiresApproval,
            approvers=frozenset(["approver@test.com"]),
            approver_groups=frozenset(),
        )
        patches = self._setup_patches(main, decision)
        for p in patches:
            p.start()
        try:
            self._run(main)
            assert self._show_buttons_kwarg(main) is True
        finally:
            for p in patches:
                p.stop()

    def test_show_buttons_true_when_both_set(self, import_main):
        import access_control

        main = import_main
        decision = self._decision(
            reason=access_control.DecisionReason.RequiresApproval,
            approvers=frozenset(["approver@test.com"]),
            approver_groups=frozenset(["S_GROUP"]),
        )
        patches = self._setup_patches(main, decision)
        for p in patches:
            p.start()
        try:
            self._run(main)
            assert self._show_buttons_kwarg(main) is True
        finally:
            for p in patches:
                p.stop()

    def test_show_buttons_false_when_neither_set(self, import_main):
        import access_control

        main = import_main
        decision = self._decision(
            reason=access_control.DecisionReason.NoApprovers,
            approvers=frozenset(),
            approver_groups=frozenset(),
        )
        patches = self._setup_patches(main, decision)
        for p in patches:
            p.start()
        try:
            self._run(main)
            assert self._show_buttons_kwarg(main) is False
            main.schedule.schedule_discard_buttons_event.assert_not_called()
            main.schedule.schedule_approver_notification_event.assert_not_called()
        finally:
            for p in patches:
                p.stop()


class TestDenyAuthorization:
    """Deny must be authorized. Historically the Deny branch ran without any
    authorization check — any channel member could deny anyone's request.

    New rules:
      - Requester can Deny their own pending request (self-cancel).
      - Approvers (individual or via group) can Deny (existing behavior).
      - Anyone else is rejected.
    """

    REQUESTER_ID = "U_REQUESTER"
    APPROVER_ID = "U_APPROVER"
    RANDOM_ID = "U_RANDOM"

    def _payload(self, clicker_slack_id: str):
        import slack_helpers

        return slack_helpers.ButtonClickedPayload.model_construct(
            action=entities.ApproverAction.Deny,
            approver_slack_id=clicker_slack_id,
            thread_ts="123.456",
            channel_id="C12345",
            # A pending request still carries its "buttons" block — without it the handler
            # correctly treats the request as already handled.
            message={"blocks": [{"block_id": "buttons"}]},
            request=slack_helpers.RequestForAccess(
                permission_set_name="TestPermissionSet",
                account_id="111111111111",
                reason="Testing",
                requester_slack_id=self.REQUESTER_ID,
                permission_duration=timedelta(hours=1),
            ),
        )

    def _user(self, user_id: str, email: str):
        return entities.slack.User(id=user_id, email=email, real_name=user_id)

    def _setup_patches(self, main_module, clicker_slack_id: str, clicker_email: str, decision_permit: bool):
        import access_control
        import slack_helpers

        user_by_id = {
            self.REQUESTER_ID: self._user(self.REQUESTER_ID, "requester@test.com"),
            self.APPROVER_ID: self._user(self.APPROVER_ID, "approver@test.com"),
            self.RANDOM_ID: self._user(self.RANDOM_ID, "random@test.com"),
        }
        # Ensure the clicker-specific user exists in the lookup
        user_by_id[clicker_slack_id] = self._user(clicker_slack_id, clicker_email)

        return [
            patch.object(
                slack_helpers.ButtonClickedPayload,
                "model_validate",
                return_value=self._payload(clicker_slack_id),
            ),
            patch.object(
                main_module.slack_helpers,
                "get_user",
                side_effect=lambda _client, id: user_by_id[id],
            ),
            patch.object(main_module.slack_helpers, "check_if_user_is_in_channel", return_value=True),
            patch.object(main_module.slack_helpers, "remove_blocks", return_value=[]),
            patch.object(
                main_module.slack_helpers.HeaderSectionBlock,
                "set_status",
                return_value=[],
            ),
            patch.object(
                main_module.sso,
                "get_permission_set",
                return_value=entities.aws.PermissionSet(name="TestPermissionSet", arn="arn:sso:ps/test", description=None),
            ),
            patch.object(
                main_module.access_control,
                "make_decision_on_approve_request",
                return_value=access_control.ApproveRequestDecision(
                    grant=False,
                    permit=decision_permit,
                    based_on_statements=frozenset(),
                ),
            ),
            patch.object(main_module.analytics, "capture"),
        ]

    def _run(self, main_module):
        mock_client = MagicMock()
        # Call via __wrapped__ to bypass the @handle_errors decorator's exception swallowing
        handler = main_module.handle_button_click.__wrapped__
        handler(body={"foo": "bar"}, client=mock_client, context=MagicMock())
        main_module.cache_for_dublicate_requests.clear()
        return mock_client

    def test_requester_can_cancel_own_request(self, import_main):
        main = import_main
        patches = self._setup_patches(
            main,
            clicker_slack_id=self.REQUESTER_ID,
            clicker_email="requester@test.com",
            decision_permit=False,  # requester is NOT an approver, yet should still be allowed to cancel
        )
        for p in patches:
            p.start()
        try:
            mock_client = self._run(main)
            # chat_update called with cancellation text
            update_calls = mock_client.chat_update.call_args_list
            assert len(update_calls) == 1
            assert update_calls[0].kwargs["text"] == f"Request was cancelled by <@{self.REQUESTER_ID}>."
            # "not authorized" message must NOT be posted
            post_texts = [c.kwargs.get("text", "") for c in mock_client.chat_postMessage.call_args_list]
            assert not any("You cannot" in t for t in post_texts)
            # Final confirmation message posted
            assert any("cancelled" in t for t in post_texts)
            # Analytics uses cancelled event
            events = [c.kwargs["event"] for c in main.analytics.capture.call_args_list]
            assert "aws_access_cancelled" in events
        finally:
            for p in patches:
                p.stop()

    def test_random_user_cannot_deny(self, import_main):
        main = import_main
        patches = self._setup_patches(
            main,
            clicker_slack_id=self.RANDOM_ID,
            clicker_email="random@test.com",
            decision_permit=False,
        )
        for p in patches:
            p.start()
        try:
            mock_client = self._run(main)
            # No chat_update — the pending message must remain intact
            assert mock_client.chat_update.call_count == 0
            # "You cannot deny" message posted
            post_texts = [c.kwargs.get("text", "") for c in mock_client.chat_postMessage.call_args_list]
            assert any("You cannot deny" in t for t in post_texts)
        finally:
            for p in patches:
                p.stop()

    def test_approver_can_still_deny(self, import_main):
        main = import_main
        patches = self._setup_patches(
            main,
            clicker_slack_id=self.APPROVER_ID,
            clicker_email="approver@test.com",
            decision_permit=True,  # approver is authorized
        )
        for p in patches:
            p.start()
        try:
            mock_client = self._run(main)
            update_calls = mock_client.chat_update.call_args_list
            assert len(update_calls) == 1
            assert update_calls[0].kwargs["text"] == f"Request was denied by <@{self.APPROVER_ID}>."
            events = [c.kwargs["event"] for c in main.analytics.capture.call_args_list]
            assert "aws_access_denied" in events
        finally:
            for p in patches:
                p.stop()


class TestHandlePermissionSetSelection:
    """Tests for the new handle_permission_set_selection action handler."""

    PS_ARN = "arn:aws:sso:::permissionSet/ssoins-abc/ps-123"
    ACCOUNT_ID = "111111111111"
    USER_ID = "U_REQUESTER"

    def _ps(self):
        return entities.aws.PermissionSet(name="Admin", arn=self.PS_ARN, description=None)

    def _body(self, account_ids=None, permission_set_arn=None):
        import slack_helpers

        view_state = {}
        if permission_set_arn is not None:
            view_state[slack_helpers.RequestForAccessView.PERMISSION_SET_BLOCK_ID] = {
                slack_helpers.RequestForAccessView.PERMISSION_SET_ACTION_ID: {
                    "selected_option": {"value": permission_set_arn},
                }
            }
        if account_ids is not None:
            view_state[slack_helpers.RequestForAccessView.ACCOUNT_BLOCK_ID] = {
                slack_helpers.RequestForAccessView.ACCOUNT_ACTION_ID: {
                    "selected_options": [{"value": a} for a in account_ids],
                }
            }
        return {
            "user": {"id": self.USER_ID},
            "view": {
                "id": "V_TEST",
                "hash": "hash-1",
                "state": {"values": view_state},
                "blocks": [
                    {"type": "input", "block_id": "select_account"},
                    {"type": "input", "block_id": "select_permission_set"},
                ],
            },
        }

    def _mock_client_with_update(self):
        mock_client = MagicMock()
        update_response = MagicMock()
        update_response.data = {"view": {"hash": "hash-2", "blocks": [{"type": "input", "block_id": "select_permission_set"}]}}
        mock_client.views_update.return_value = update_response
        return mock_client

    def test_returns_none_when_no_permission_set_selected(self, import_main):
        main = import_main
        main.user_view_map.clear()
        mock_client = self._mock_client_with_update()

        result = main._handle_permission_set_selection_impl(self._body(account_ids=[self.ACCOUNT_ID]), mock_client)

        assert result is None
        mock_client.views_update.assert_not_called()

    def test_returns_none_when_no_accounts_selected(self, import_main):
        main = import_main
        main.user_view_map.clear()
        mock_client = self._mock_client_with_update()

        result = main._handle_permission_set_selection_impl(self._body(account_ids=[], permission_set_arn=self.PS_ARN), mock_client)

        assert result is None
        mock_client.views_update.assert_not_called()

    def test_returns_none_when_permission_set_arn_not_in_config(self, import_main):
        main = import_main
        main.user_view_map.clear()

        view_key = f"{self.USER_ID}:request_for__account_access_submitted"
        main.user_view_map[f"{view_key}:group_ids"] = set()
        main.user_view_map[f"{view_key}:user_email"] = "requester@test.com"

        mock_client = self._mock_client_with_update()

        with patch.object(main.sso, "get_permission_sets_from_config_with_cache", return_value=[]):
            result = main._handle_permission_set_selection_impl(
                self._body(account_ids=[self.ACCOUNT_ID], permission_set_arn="arn:nonexistent"), mock_client
            )

        assert result is None
        # Loading view was shown, but no second update
        assert mock_client.views_update.call_count == 1

    def test_happy_path_renders_approvers_text(self, import_main):
        import access_control

        main = import_main
        main.user_view_map.clear()
        view_key = f"{self.USER_ID}:request_for__account_access_submitted"
        main.user_view_map[f"{view_key}:group_ids"] = set()
        main.user_view_map[f"{view_key}:user_email"] = "requester@test.com"

        mock_client = self._mock_client_with_update()

        decision = access_control.AccessRequestDecision(
            grant=False,
            reason=access_control.DecisionReason.RequiresApproval,
            based_on_statements=frozenset(),
            approvers=frozenset(["alice@test.com"]),
            approver_groups=frozenset(),
        )

        with (
            patch.object(main.sso, "get_permission_sets_from_config_with_cache", return_value=[self._ps()]),
            patch.object(main.access_control, "make_decision_on_access_request", return_value=decision) as mock_decision,
            patch.object(
                main.slack_helpers,
                "get_user_by_email",
                return_value=entities.slack.User(id="U_ALICE", email="alice@test.com", real_name="Alice"),
            ),
        ):
            main._handle_permission_set_selection_impl(
                self._body(account_ids=[self.ACCOUNT_ID], permission_set_arn=self.PS_ARN), mock_client
            )

        assert mock_decision.call_count == 1
        call_kwargs = mock_decision.call_args.kwargs
        assert call_kwargs["account_id"] == self.ACCOUNT_ID
        assert call_kwargs["permission_set_arn"] == self.PS_ARN
        assert call_kwargs["permission_set_name"] == "Admin"
        assert call_kwargs["requester_email"] == "requester@test.com"

        # views_update called twice: loading then preview
        assert mock_client.views_update.call_count == 2
        final_view = mock_client.views_update.call_args_list[-1].kwargs["view"]
        rendered_text = self._extract_context_text(final_view, "approvers_preview")
        assert "<@U_ALICE>" in rendered_text

    def test_unions_approvers_across_multiple_accounts(self, import_main):
        import access_control

        main = import_main
        main.user_view_map.clear()
        view_key = f"{self.USER_ID}:request_for__account_access_submitted"
        main.user_view_map[f"{view_key}:group_ids"] = set()
        main.user_view_map[f"{view_key}:user_email"] = "requester@test.com"

        mock_client = self._mock_client_with_update()

        def decision_side_effect(*_args, **kwargs):
            account = kwargs["account_id"]
            approver = "alice@test.com" if account == "111" else "bob@test.com"
            return access_control.AccessRequestDecision(
                grant=False,
                reason=access_control.DecisionReason.RequiresApproval,
                based_on_statements=frozenset(),
                approvers=frozenset([approver]),
                approver_groups=frozenset(),
            )

        def get_user_side_effect(_client, email):
            uid = {"alice@test.com": "U_ALICE", "bob@test.com": "U_BOB"}[email]
            return entities.slack.User(id=uid, email=email, real_name=uid)

        with (
            patch.object(main.sso, "get_permission_sets_from_config_with_cache", return_value=[self._ps()]),
            patch.object(main.access_control, "make_decision_on_access_request", side_effect=decision_side_effect),
            patch.object(main.slack_helpers, "get_user_by_email", side_effect=get_user_side_effect),
        ):
            main._handle_permission_set_selection_impl(self._body(account_ids=["111", "222"], permission_set_arn=self.PS_ARN), mock_client)

        final_view = mock_client.views_update.call_args_list[-1].kwargs["view"]
        rendered_text = self._extract_context_text(final_view, "approvers_preview")
        assert "<@U_ALICE>" in rendered_text
        assert "<@U_BOB>" in rendered_text

    def _extract_context_text(self, view, block_id: str) -> str:
        for block in view.blocks:
            bid = getattr(block, "block_id", None) or (block.get("block_id") if isinstance(block, dict) else None)
            if bid == block_id:
                elements = getattr(block, "elements", None) or (block.get("elements") if isinstance(block, dict) else []) or []
                texts = []
                for el in elements:
                    text = getattr(el, "text", None) or (el.get("text") if isinstance(el, dict) else None)
                    if text:
                        texts.append(text)
                return " ".join(texts)
        return ""

    def test_handler_swallows_exceptions_so_user_can_still_submit(self, import_main):
        """If anything in the preview pipeline throws, the handler must log + return None
        instead of bubbling — otherwise the user gets stuck unable to submit the modal."""
        main = import_main
        main.user_view_map.clear()

        mock_client = self._mock_client_with_update()
        ack = MagicMock()

        # Force the impl to throw mid-flight.
        with patch.object(main, "_handle_permission_set_selection_impl", side_effect=RuntimeError("boom")):
            # Should NOT propagate.
            result = main.handle_permission_set_selection(
                ack, self._body(account_ids=[self.ACCOUNT_ID], permission_set_arn=self.PS_ARN), mock_client
            )

        assert result is None
        ack.assert_called_once()

    def test_loading_view_keeps_submit_button(self):
        """show_approvers_loading() must keep the submit button — preview is informational."""
        import slack_helpers

        loading_view = slack_helpers.RequestForAccessView.show_approvers_loading(
            [
                {"type": "input", "block_id": "select_account"},
                {"type": "input", "block_id": "select_permission_set"},
            ]
        )
        assert loading_view.submit is not None

    def test_preview_view_keeps_submit_button(self):
        """update_with_approvers() must keep the submit button."""
        import slack_helpers

        preview_view = slack_helpers.RequestForAccessView.update_with_approvers(
            [
                {"type": "input", "block_id": "select_account"},
                {"type": "input", "block_id": "select_permission_set"},
            ],
            text="*hello*",
        )
        assert preview_view.submit is not None


# ---------------------------------------------------------------------------
# Extend-grant publishes AccessChange event so eks-auth-updater can update the
# EKS aws-auth ConfigMap on extension. Regression for the bug where extending
# an EKS grant restored SSO access but left kubectl denied.
# ---------------------------------------------------------------------------


def _build_extend_button_body(payload_json: str, clicker_id: str = "U_REQ") -> dict:
    """Mimic the Slack button-click body that Bolt passes to the handler."""
    return {
        "user": {"id": clicker_id},
        "channel": {"id": "C_TEST"},
        "message": {"thread_ts": "1700000000.123456", "ts": "1700000000.123456"},
        "actions": [{"value": payload_json}],
        "trigger_id": "tg-1",
    }


def _build_account_extend_payload(requester_id: str = "U_REQ"):  # noqa: ANN202
    from datetime import datetime, timezone

    from slack_helpers import ExtendGrantButtonPayload

    return ExtendGrantButtonPayload(
        requester_slack_id=requester_id,
        expired_at=datetime.now(timezone.utc).isoformat(),  # within 1hr window
        extension_duration_in_minutes=60,
        extensions_count=0,
        account_id="111111111111",
        permission_set_name="eks-developer",
        permission_set_arn="arn:aws:sso:::permissionSet/ssoins-1234/ps-5678",
        instance_arn="arn:aws:sso:::instance/ssoins-1234",
        user_principal_id="uid-123",
        account_name="dev",
        approver={"id": requester_id, "email": "alice@example.com", "real_name": "Alice"},
        requester={"id": requester_id, "email": "alice@example.com", "real_name": "Alice"},
    )


def _build_group_extend_payload(requester_id: str = "U_REQ"):  # noqa: ANN202
    from datetime import datetime, timezone

    from slack_helpers import ExtendGrantButtonPayload

    return ExtendGrantButtonPayload(
        requester_slack_id=requester_id,
        expired_at=datetime.now(timezone.utc).isoformat(),
        extension_duration_in_minutes=60,
        extensions_count=0,
        group_id="g-1",
        group_name="developers",
        identity_store_id="d-x",
        user_principal_id="uid-123",
        approver={"id": requester_id, "email": "alice@example.com", "real_name": "Alice"},
        requester={"id": requester_id, "email": "alice@example.com", "real_name": "Alice"},
    )


class TestExtendGrantPublishesAccessEvent:
    """When the user extends an EKS-bound account grant, the handler MUST publish an
    AccessChange grant event so the cross-account eks-auth-updater Lambda restores
    the user's entry in the EKS aws-auth ConfigMap. Without this event, the SSO
    assignment is re-created but kubectl access stays denied.
    """

    def test_account_extend_publishes_grant_event(self, import_main):
        main_module = import_main
        payload = _build_account_extend_payload()
        body = _build_extend_button_body(payload.model_dump_json(), clicker_id="U_REQ")
        client = MagicMock()
        client.chat_postMessage.return_value = {"ts": "9999.0001"}

        with (
            patch.object(main_module.slack_helpers, "delete_extend_grant_button"),
            patch.object(main_module.slack_helpers, "get_message_from_timestamp", return_value=None),
            patch.object(main_module.schedule, "schedule_revoke_event", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
            patch.object(main_module.sso, "create_account_assignment_and_wait_for_result"),
            patch.object(main_module.event_publisher, "publish_access_event") as mock_publish,
            patch("s3.log_operation"),
        ):
            main_module.handle_extend_grant_button_click(body=body, client=client, context=MagicMock())

        mock_publish.assert_called_once()
        kwargs = mock_publish.call_args.kwargs
        assert kwargs["action"] == "grant"
        assert kwargs["account_id"] == "111111111111"
        assert kwargs["permission_set_name"] == "eks-developer"
        assert kwargs["permission_set_arn"] == "arn:aws:sso:::permissionSet/ssoins-1234/ps-5678"
        assert kwargs["user_principal_id"] == "uid-123"

    def test_account_extend_publishes_after_assignment_created(self, import_main):
        """The event must come AFTER CreateAccountAssignment succeeds — publishing first
        would tell eks-auth-updater to add a ConfigMap entry that doesn't yet correspond
        to a real SSO assignment."""
        main_module = import_main
        call_order: list[str] = []

        payload = _build_account_extend_payload()
        body = _build_extend_button_body(payload.model_dump_json(), clicker_id="U_REQ")
        client = MagicMock()
        client.chat_postMessage.return_value = {"ts": "9999.0001"}

        with (
            patch.object(main_module.slack_helpers, "delete_extend_grant_button"),
            patch.object(main_module.slack_helpers, "get_message_from_timestamp", return_value=None),
            patch.object(main_module.schedule, "schedule_revoke_event", return_value=({"ScheduleArn": "arn:s"}, "new-sched")),
            patch.object(
                main_module.sso,
                "create_account_assignment_and_wait_for_result",
                side_effect=lambda *a, **kw: call_order.append("create"),  # noqa: ARG005
            ),
            patch.object(
                main_module.event_publisher,
                "publish_access_event",
                side_effect=lambda *a, **kw: call_order.append("publish"),  # noqa: ARG005
            ),
            patch("s3.log_operation"),
        ):
            main_module.handle_extend_grant_button_click(body=body, client=client, context=MagicMock())

        assert call_order == ["create", "publish"]

    def test_account_extend_skips_publish_when_create_conflicts(self, import_main):
        """If CreateAccountAssignment hits ConflictException (another extend is racing
        ours), this invocation must NOT publish — the winning invocation owns the
        event, and double-publishing would re-trigger eks-auth-updater twice."""
        import botocore.exceptions

        main_module = import_main
        conflict = botocore.exceptions.ClientError(
            {"Error": {"Code": "ConflictException", "Message": "in progress"}},  # type: ignore[arg-type]
            "CreateAccountAssignment",
        )

        payload = _build_account_extend_payload()
        body = _build_extend_button_body(payload.model_dump_json(), clicker_id="U_REQ")
        client = MagicMock()

        with (
            patch.object(main_module.slack_helpers, "delete_extend_grant_button"),
            patch.object(main_module.sso, "create_account_assignment_and_wait_for_result", side_effect=conflict),
            patch.object(main_module.event_publisher, "publish_access_event") as mock_publish,
            patch.object(main_module.schedule, "schedule_revoke_event") as mock_schedule,
            patch("s3.log_operation") as mock_audit,
        ):
            main_module.handle_extend_grant_button_click(body=body, client=client, context=MagicMock())

        mock_publish.assert_not_called()
        mock_schedule.assert_not_called()
        mock_audit.assert_not_called()

    def test_account_extend_skipped_when_window_expired(self, import_main):
        """When the 1hr extension window has lapsed, no SSO call and no event."""
        from datetime import datetime, timedelta, timezone

        from slack_helpers import ExtendGrantButtonPayload

        main_module = import_main
        base = _build_account_extend_payload()
        payload = ExtendGrantButtonPayload.model_validate(
            {**base.model_dump(), "expired_at": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()}
        )
        body = _build_extend_button_body(payload.model_dump_json(), clicker_id="U_REQ")
        client = MagicMock()

        with (
            patch.object(main_module.sso, "create_account_assignment_and_wait_for_result") as mock_create,
            patch.object(main_module.event_publisher, "publish_access_event") as mock_publish,
        ):
            main_module.handle_extend_grant_button_click(body=body, client=client, context=MagicMock())

        mock_create.assert_not_called()
        mock_publish.assert_not_called()

    def test_account_extend_skipped_when_wrong_user_clicks(self, import_main):
        """Only the original requester can extend. Imposter click → no SSO call, no event."""
        main_module = import_main
        payload = _build_account_extend_payload(requester_id="U_REQ")
        body = _build_extend_button_body(payload.model_dump_json(), clicker_id="U_IMPOSTER")
        client = MagicMock()

        with (
            patch.object(main_module.sso, "create_account_assignment_and_wait_for_result") as mock_create,
            patch.object(main_module.event_publisher, "publish_access_event") as mock_publish,
        ):
            main_module.handle_extend_grant_button_click(body=body, client=client, context=MagicMock())

        mock_create.assert_not_called()
        mock_publish.assert_not_called()

    def test_group_extend_does_not_publish_event(self, import_main):
        """Group access has no downstream EventBridge consumer (eks-auth-updater filters
        on permission_set_name, not group membership). We don't publish for groups —
        the event schema is account-shaped and there's nothing to receive it."""
        main_module = import_main
        payload = _build_group_extend_payload()
        body = _build_extend_button_body(payload.model_dump_json(), clicker_id="U_REQ")
        client = MagicMock()
        client.chat_postMessage.return_value = {"ts": "9999.0001"}

        with (
            patch.object(main_module.slack_helpers, "delete_extend_grant_button"),
            patch.object(main_module.slack_helpers, "get_message_from_timestamp", return_value=None),
            patch.object(
                main_module.schedule,
                "schedule_group_revoke_event",
                return_value=({"ScheduleArn": "arn:s"}, "new-sched"),
            ),
            patch.object(main_module.sso, "add_user_to_a_group", return_value={"MembershipId": "m-1"}),
            patch.object(main_module.sso, "get_identity_store_id", return_value="d-x"),
            patch.object(main_module.event_publisher, "publish_access_event") as mock_publish,
            patch("s3.log_operation"),
        ):
            main_module.handle_extend_grant_button_click(body=body, client=client, context=MagicMock())

        mock_publish.assert_not_called()


class TestExternalIdCorrelation:
    """Open/populate are correlated by a deterministic external_id derived from trigger_id."""

    def test_external_id_is_deterministic_from_trigger_id(self, import_main):
        main = import_main
        body = {"trigger_id": "111.222.aaa", "user": {"id": "U1"}}
        assert main._external_id_for(body) == "req-access:111.222.aaa"
        assert main._external_id_for(dict(body)) == main._external_id_for(body)

    def test_external_id_truncated_to_255(self, import_main):
        main = import_main
        body = {"trigger_id": "t" * 300}
        assert len(main._external_id_for(body)) == 255

    def test_account_populate_updates_by_external_id_not_view_id(self, import_main):
        main = import_main
        import organizations
        import slack_helpers
        import sso
        import statement

        client = MagicMock()
        body = {"trigger_id": "111.222.aaa", "user": {"id": "U1"}}
        with (
            patch.object(sso, "get_identity_store_id", return_value="d-1"),
            patch.object(slack_helpers, "get_user", return_value=MagicMock(email="u@test.com")),
            patch.object(sso, "get_user_principal_id_by_email", return_value=("p-1", None)),
            patch.object(sso, "get_user_group_ids", return_value={"g-1"}),
            patch.object(statement, "get_accounts_for_user", return_value={"111111111111"}),
            patch.object(
                organizations,
                "get_accounts_from_config_with_cache",
                return_value=[entities.aws.Account(id="111111111111", name="prod")],
            ),
        ):
            main.load_select_options_for_account_access_request(client, body)

        assert client.views_update.called
        kwargs = client.views_update.call_args.kwargs
        assert kwargs.get("external_id") == "req-access:111.222.aaa"
        assert "view_id" not in kwargs


class TestHandleLoadPermissionSets:
    """The load-permission-sets button reads accounts from view state and updates the modal."""

    def _body(self, account_values):
        import slack_helpers

        return {
            "user": {"id": "U1"},
            "view": {
                "id": "V123",
                "hash": "h1",
                "blocks": slack_helpers.RequestForAccessView.update_with_accounts(
                    [entities.aws.Account(id="111111111111", name="prod")]
                ).to_dict()["blocks"],
                "state": {
                    "values": {
                        slack_helpers.RequestForAccessView.ACCOUNT_BLOCK_ID: {
                            slack_helpers.RequestForAccessView.ACCOUNT_ACTION_ID: {
                                "selected_options": [{"value": v} for v in account_values],
                            },
                        },
                    }
                },
            },
        }

    def test_no_accounts_selected_acks_without_loading(self, import_main):
        main = import_main
        client = MagicMock()
        ack = MagicMock()
        main.handle_load_permission_sets(ack, self._body([]), client)
        ack.assert_called_once()
        client.views_update.assert_not_called()

    def test_loads_permission_sets_for_selected_accounts(self, import_main):
        main = import_main
        import sso
        import statement

        client = MagicMock()

        def _echo_view(**kwargs):
            view = kwargs["view"]
            blocks = view.to_dict()["blocks"] if hasattr(view, "to_dict") else view["blocks"]
            return MagicMock(data={"view": {"blocks": blocks, "hash": "h2"}})

        client.views_update.side_effect = _echo_view
        ack = MagicMock()
        with (
            patch.object(statement, "get_permission_sets_for_accounts_and_user", return_value={"AdministratorAccess"}),
            patch.object(
                sso,
                "get_permission_sets_from_config_with_cache",
                return_value=[
                    entities.aws.PermissionSet(
                        name="AdministratorAccess", arn="arn:aws:sso:::permissionSet/ssoins-x/ps-1", description=None
                    )
                ],
            ),
            patch.object(main, "_get_cached_user_info", return_value=({"g-1"}, "u@test.com")),
            patch.object(main, "classify_auto_approved_permission_sets", return_value=set()),
        ):
            main.handle_load_permission_sets(ack, self._body(["111111111111"]), client)
        ack.assert_called_once()
        assert client.views_update.called


class TestWithRetries:
    """_with_retries retries transient AWS/Slack failures silently but not terminal ones."""

    def test_retries_transient_then_succeeds(self, import_main):
        main = import_main
        from botocore.exceptions import ClientError

        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise ClientError({"Error": {"Code": "ThrottlingException"}}, "ListAccounts")
            return "ok"

        with patch.object(main.time, "sleep", return_value=None):
            assert main._with_retries(flaky) == "ok"
        assert calls["n"] == 3

    def test_does_not_retry_non_transient(self, import_main):
        main = import_main
        from errors import SSOUserNotFound

        calls = {"n": 0}

        def boom():
            calls["n"] += 1
            raise SSOUserNotFound("nope")

        with pytest.raises(SSOUserNotFound):
            main._with_retries(boom)
        assert calls["n"] == 1

    def test_reraises_after_exhausting_attempts(self, import_main):
        main = import_main
        from botocore.exceptions import ClientError

        def always():
            raise ClientError({"Error": {"Code": "ThrottlingException"}}, "ListAccounts")

        with patch.object(main.time, "sleep", return_value=None):
            with pytest.raises(ClientError):
                main._with_retries(always, attempts=3)


class TestAcknowledgeRequestForAccess:
    """The account view ack rejects submissions with no permission set selected."""

    def _submission(self, *, with_permission_set: bool, with_duration: bool = True) -> dict:
        import slack_helpers

        v = slack_helpers.RequestForAccessView
        values = {
            v.ACCOUNT_BLOCK_ID: {v.ACCOUNT_ACTION_ID: {"selected_options": [{"value": "111111111111"}]}},
            v.REASON_BLOCK_ID: {v.REASON_ACTION_ID: {"value": "because reasons"}},
        }
        if with_duration:
            values[v.DURATION_BLOCK_ID] = {v.DURATION_ACTION_ID: {"selected_option": {"value": "01:00"}}}
        if with_permission_set:
            values[v.PERMISSION_SET_BLOCK_ID] = {
                v.PERMISSION_SET_ACTION_ID: {"selected_option": {"value": "arn:aws:sso:::permissionSet/ssoins-x/ps-1"}}
            }
        return {"user": {"id": "U1"}, "view": {"state": {"values": values}}}

    def test_rejects_when_no_permission_set(self, import_main):
        main = import_main
        import slack_helpers

        ack = MagicMock()
        main.acknowledge_request_for_access(ack, self._submission(with_permission_set=False))
        assert ack.call_args.kwargs.get("response_action") == "errors"
        assert slack_helpers.RequestForAccessView.ACCOUNT_BLOCK_ID in ack.call_args.kwargs.get("errors", {})

    def test_accepts_when_permission_set_present(self, import_main):
        main = import_main

        ack = MagicMock()
        main.acknowledge_request_for_access(ack, self._submission(with_permission_set=True))
        assert ack.call_args.kwargs.get("response_action") is None

    def test_rejects_when_no_duration(self, import_main):
        # Backstop: a submit that lands before the duration field is present (the original incident)
        # is rejected with the modal kept open, not crashed on.
        main = import_main
        import slack_helpers

        ack = MagicMock()
        main.acknowledge_request_for_access(ack, self._submission(with_permission_set=True, with_duration=False))
        assert ack.call_args.kwargs.get("response_action") == "errors"
        assert slack_helpers.RequestForAccessView.ACCOUNT_BLOCK_ID in ack.call_args.kwargs.get("errors", {})


class TestAlreadyHandledRequest:
    """A click on a request whose `buttons` block is already gone — another approver won the
    race, or the revoker expired it — must leave the message alone.

    Previously the handler appended a second `block_id="footer"` to blocks that already carried
    one, and Slack rejects duplicate block_ids with `invalid_blocks`. The clicker got a generic
    "Something went wrong handling this action" instead of being told what happened.
    """

    REQUESTER_ID = "U_REQUESTER"
    CLICKER_ID = "U_LATE_APPROVER"
    WINNER_ID = "U_WINNER"

    # Blocks as they look after another approver's update: buttons swapped for a footer.
    HANDLED_BLOCKS = [
        {"block_id": "header"},
        {"block_id": "content"},
        {"block_id": "footer", "text": {"type": "mrkdwn", "text": f"<@{WINNER_ID}> pressed approve button"}},
    ]

    def _payload(self, action):
        import slack_helpers

        return slack_helpers.ButtonClickedPayload.model_construct(
            action=action,
            approver_slack_id=self.CLICKER_ID,
            thread_ts="123.456",
            channel_id="C12345",
            message={"blocks": self.HANDLED_BLOCKS},
            request=slack_helpers.RequestForAccess(
                permission_set_name="TestPermissionSet",
                account_id="111111111111",
                reason="Testing",
                requester_slack_id=self.REQUESTER_ID,
                permission_duration=timedelta(hours=1),
            ),
        )

    def _user(self, user_id: str):
        return entities.slack.User(id=user_id, email=f"{user_id}@test.com", real_name=user_id)

    def _run(self, main_module, action):
        import access_control
        import slack_helpers

        mock_client = MagicMock()
        with (
            patch.object(slack_helpers.ButtonClickedPayload, "model_validate", return_value=self._payload(action)),
            patch.object(main_module.slack_helpers, "get_user", side_effect=lambda _client, id: self._user(id)),
            patch.object(main_module.slack_helpers, "check_if_user_is_in_channel", return_value=True),
            patch.object(
                main_module.sso,
                "get_permission_set",
                return_value=entities.aws.PermissionSet(name="TestPermissionSet", arn="arn:sso:ps/test", description=None),
            ),
            # The clicker IS a legitimate approver — the request being already handled is the
            # only reason to stop, so authorization must not be what makes this test pass.
            patch.object(
                main_module.access_control,
                "make_decision_on_approve_request",
                return_value=access_control.ApproveRequestDecision(
                    grant=True,
                    permit=True,
                    based_on_statements=frozenset(),
                ),
            ),
            patch.object(main_module.analytics, "capture"),
            patch.object(main_module.access_control, "execute_decision") as execute_decision,
        ):
            main_module.handle_button_click.__wrapped__(body={"foo": "bar"}, client=mock_client, context=MagicMock())
        main_module.cache_for_dublicate_requests.clear()
        return mock_client, execute_decision

    @pytest.mark.parametrize("action", [entities.ApproverAction.Approve, entities.ApproverAction.Deny])
    def test_does_not_update_message(self, import_main, action):
        mock_client, _ = self._run(import_main, action)
        assert mock_client.chat_update.call_count == 0

    @pytest.mark.parametrize("action", [entities.ApproverAction.Approve, entities.ApproverAction.Deny])
    def test_tells_clicker_it_was_already_handled(self, import_main, action):
        mock_client, _ = self._run(import_main, action)
        texts = [c.kwargs.get("text", "") for c in mock_client.chat_postMessage.call_args_list]
        assert any("already been handled" in t for t in texts)
        # The reply belongs in the request thread, not the channel root.
        assert all(c.kwargs.get("thread_ts") == "123.456" for c in mock_client.chat_postMessage.call_args_list)

    def test_names_the_approver_who_handled_it(self, import_main):
        mock_client, _ = self._run(import_main, entities.ApproverAction.Approve)
        texts = [c.kwargs.get("text", "") for c in mock_client.chat_postMessage.call_args_list]
        assert any(f"<@{self.WINNER_ID}> pressed approve button" in t for t in texts)

    def test_grants_nothing(self, import_main):
        # Approve only — the Deny branch never reaches execute_decision, so parametrizing it
        # would add a test that cannot fail.
        _, execute_decision = self._run(import_main, entities.ApproverAction.Approve)
        execute_decision.assert_not_called()
