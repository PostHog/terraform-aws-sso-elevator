"""Tests for the cache-first account list in organizations.py."""

from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

import organizations
from entities.aws import Account

# ruff: noqa: ANN201, ANN001

PROD = Account(id="111111111111", name="prod")
DEV = Account(id="222222222222", name="dev")


def _cfg(accounts=frozenset({"*"})):
    return MagicMock(cache_enabled=True, config_bucket_name="test-config-bucket", accounts=accounts)


def _org_client(accounts):
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{"Accounts": [{"Id": a.id, "Name": a.name} for a in accounts]}]
    return client


class TestListAccountsWithCache:
    def test_cache_hit_makes_no_organizations_call(self):
        org_client = _org_client([PROD])
        with patch("cache.get_cached_accounts", return_value=[PROD, DEV]):
            result = organizations.list_accounts_with_cache(org_client, MagicMock(), _cfg())

        assert result == [PROD, DEV]
        org_client.get_paginator.assert_not_called()

    def test_cache_miss_calls_api_and_writes_cache(self):
        org_client = _org_client([PROD])
        with (
            patch("cache.get_cached_accounts", return_value=None),
            patch("cache.set_cached_accounts", return_value=True) as set_cached,
        ):
            result = organizations.list_accounts_with_cache(org_client, MagicMock(), _cfg())

        assert result == [PROD]
        org_client.get_paginator.assert_called_once_with("list_accounts")
        assert set_cached.call_args.args[2] == [PROD]


class TestGetAccountsFromConfigWithCache:
    def test_filters_cached_accounts_by_config(self):
        with patch("cache.get_cached_accounts", return_value=[PROD, DEV]):
            result = organizations.get_accounts_from_config_with_cache(MagicMock(), MagicMock(), _cfg(accounts=frozenset({"222222222222"})))

        assert result == [DEV]

    def test_wildcard_returns_all_cached_accounts(self):
        with patch("cache.get_cached_accounts", return_value=[PROD, DEV]):
            result = organizations.get_accounts_from_config_with_cache(MagicMock(), MagicMock(), _cfg())

        assert result == [PROD, DEV]


class TestRefreshAccountsCache:
    def test_writes_cache_when_accounts_changed(self):
        org_client = _org_client([PROD, DEV])
        with (
            patch("cache.get_cached_accounts", return_value=[PROD]),
            patch("cache.set_cached_accounts", return_value=True) as set_cached,
        ):
            organizations.refresh_accounts_cache(org_client, MagicMock(), _cfg())

        assert set_cached.call_args.args[2] == [PROD, DEV]

    def test_does_not_write_when_accounts_unchanged(self):
        org_client = _org_client([PROD])
        with (
            patch("cache.get_cached_accounts", return_value=[PROD]),
            patch("cache.set_cached_accounts", return_value=True) as set_cached,
        ):
            organizations.refresh_accounts_cache(org_client, MagicMock(), _cfg())

        set_cached.assert_not_called()

    def test_api_error_does_not_raise(self):
        org_client = MagicMock()
        org_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "TooManyRequestsException", "Message": "Rate exceeded"}}, "ListAccounts"
        )
        with patch("cache.set_cached_accounts") as set_cached:
            organizations.refresh_accounts_cache(org_client, MagicMock(), _cfg())

        set_cached.assert_not_called()
