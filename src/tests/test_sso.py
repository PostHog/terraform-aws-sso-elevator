from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

import sso
from entities.aws import Account, PermissionSet
from sso import get_user_group_ids

# ruff: noqa: ANN201, ANN001


class TestGetUserGroupIds:
    def test_returns_group_ids_for_user(self):
        """Should return all group IDs the user belongs to."""
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "GroupMemberships": [
                    {"GroupId": "group-1", "MembershipId": "membership-1"},
                    {"GroupId": "group-2", "MembershipId": "membership-2"},
                ]
            },
            {
                "GroupMemberships": [
                    {"GroupId": "group-3", "MembershipId": "membership-3"},
                ]
            },
        ]

        result = get_user_group_ids(
            identity_store_client=mock_client,
            identity_store_id="d-1234567890",
            user_principal_id="user-123",
        )

        assert result == {"group-1", "group-2", "group-3"}
        mock_client.get_paginator.assert_called_once_with("list_group_memberships_for_member")
        mock_paginator.paginate.assert_called_once_with(
            IdentityStoreId="d-1234567890",
            MemberId={"UserId": "user-123"},
        )

    def test_returns_empty_set_for_user_with_no_groups(self):
        """Should return empty set if user has no group memberships."""
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"GroupMemberships": []}]

        result = get_user_group_ids(
            identity_store_client=mock_client,
            identity_store_id="d-1234567890",
            user_principal_id="user-123",
        )

        assert result == set()

    def test_handles_missing_group_id_gracefully(self):
        """Should skip memberships without GroupId."""
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "GroupMemberships": [
                    {"GroupId": "group-1", "MembershipId": "membership-1"},
                    {"MembershipId": "membership-2"},  # Missing GroupId
                    {"GroupId": None, "MembershipId": "membership-3"},  # None GroupId
                ]
            }
        ]

        result = get_user_group_ids(
            identity_store_client=mock_client,
            identity_store_id="d-1234567890",
            user_principal_id="user-123",
        )

        assert result == {"group-1"}

    def test_raises_on_api_error(self):
        """Should raise exception on API error."""
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.side_effect = Exception("API Error")

        with pytest.raises(Exception, match="API Error"):
            get_user_group_ids(
                identity_store_client=mock_client,
                identity_store_id="d-1234567890",
                user_principal_id="user-123",
            )


SSO_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1111111111111111"
PS_ADMIN = PermissionSet(name="AdministratorAccess", arn="arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-1", description=None)
PS_READ = PermissionSet(name="ReadOnlyAccess", arn="arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-2", description=None)
PROD = Account(id="111111111111", name="prod")
DEV = Account(id="222222222222", name="dev")


def _cfg(**overrides):
    values = {
        "cache_enabled": True,
        "config_bucket_name": "test-config-bucket",
        "sso_instance_arn": SSO_INSTANCE_ARN,
        "accounts": frozenset({"*"}),
        "permission_sets": frozenset({"*"}),
    }
    values.update(overrides)
    return MagicMock(**values)


def _sso_client(permission_sets):
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{"PermissionSets": [ps.arn for ps in permission_sets]}]
    by_arn = {ps.arn: ps for ps in permission_sets}

    def describe(**kwargs):
        arn = kwargs["PermissionSetArn"]
        return {"PermissionSet": {"Name": by_arn[arn].name, "PermissionSetArn": arn}}

    client.describe_permission_set.side_effect = describe
    return client


def _org_client(accounts):
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{"Accounts": [{"Id": a.id, "Name": a.name} for a in accounts]}]
    return client


class TestListPermissionSetsWithCache:
    def test_cache_hit_makes_no_sso_admin_call(self):
        sso_client = _sso_client([PS_ADMIN])
        with patch("cache.get_cached_permission_sets", return_value=[PS_ADMIN, PS_READ]):
            result = sso.list_permission_sets_with_cache(sso_client, MagicMock(), SSO_INSTANCE_ARN, _cfg())

        assert result == [PS_ADMIN, PS_READ]
        sso_client.get_paginator.assert_not_called()
        sso_client.describe_permission_set.assert_not_called()

    def test_cache_miss_calls_api_and_writes_cache(self):
        sso_client = _sso_client([PS_ADMIN])
        with (
            patch("cache.get_cached_permission_sets", return_value=None),
            patch("cache.set_cached_permission_sets", return_value=True) as set_cached,
        ):
            result = sso.list_permission_sets_with_cache(sso_client, MagicMock(), SSO_INSTANCE_ARN, _cfg())

        assert result == [PS_ADMIN]
        assert set_cached.call_args.args[3] == [PS_ADMIN]


class TestGetPermissionSetsFromConfigWithCache:
    def test_filters_cached_permission_sets_by_name(self):
        with patch("cache.get_cached_permission_sets", return_value=[PS_ADMIN, PS_READ]):
            result = sso.get_permission_sets_from_config_with_cache(
                MagicMock(), MagicMock(), _cfg(permission_sets=frozenset({"ReadOnlyAccess"}))
            )

        assert result == [PS_READ]

    def test_filters_cached_permission_sets_by_arn(self):
        with patch("cache.get_cached_permission_sets", return_value=[PS_ADMIN, PS_READ]):
            result = sso.get_permission_sets_from_config_with_cache(
                MagicMock(), MagicMock(), _cfg(permission_sets=frozenset({PS_ADMIN.arn}))
            )

        assert result == [PS_ADMIN]

    def test_wildcard_returns_all_cached_permission_sets(self):
        with patch("cache.get_cached_permission_sets", return_value=[PS_ADMIN, PS_READ]):
            result = sso.get_permission_sets_from_config_with_cache(MagicMock(), MagicMock(), _cfg())

        assert result == [PS_ADMIN, PS_READ]


class TestRefreshAccountAndPermissionSetCaches:
    def test_disabled_cache_makes_no_calls(self):
        org_client = _org_client([PROD])
        sso_client = _sso_client([PS_ADMIN])
        with (
            patch("cache.get_cached_accounts") as get_accounts,
            patch("cache.get_cached_permission_sets") as get_permission_sets,
        ):
            sso.refresh_account_and_permission_set_caches(
                org_client=org_client, sso_client=sso_client, s3_client=MagicMock(), cfg=_cfg(cache_enabled=False)
            )

        org_client.get_paginator.assert_not_called()
        sso_client.get_paginator.assert_not_called()
        get_accounts.assert_not_called()
        get_permission_sets.assert_not_called()

    def test_writes_both_caches_when_changed(self):
        with (
            patch("cache.get_cached_accounts", return_value=[PROD]),
            patch("cache.get_cached_permission_sets", return_value=[PS_ADMIN]),
            patch("cache.set_cached_accounts", return_value=True) as set_accounts,
            patch("cache.set_cached_permission_sets", return_value=True) as set_permission_sets,
        ):
            sso.refresh_account_and_permission_set_caches(
                org_client=_org_client([PROD, DEV]), sso_client=_sso_client([PS_ADMIN, PS_READ]), s3_client=MagicMock(), cfg=_cfg()
            )

        assert set_accounts.call_args.args[2] == [PROD, DEV]
        assert set_permission_sets.call_args.args[3] == [PS_ADMIN, PS_READ]

    def test_account_failure_still_refreshes_permission_sets(self):
        org_client = MagicMock()
        org_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "TooManyRequestsException", "Message": "Rate exceeded"}}, "ListAccounts"
        )
        with (
            patch("cache.get_cached_permission_sets", return_value=[PS_ADMIN]),
            patch("cache.set_cached_accounts") as set_accounts,
            patch("cache.set_cached_permission_sets", return_value=True) as set_permission_sets,
        ):
            sso.refresh_account_and_permission_set_caches(
                org_client=org_client, sso_client=_sso_client([PS_ADMIN, PS_READ]), s3_client=MagicMock(), cfg=_cfg()
            )

        set_accounts.assert_not_called()
        assert set_permission_sets.call_args.args[3] == [PS_ADMIN, PS_READ]
