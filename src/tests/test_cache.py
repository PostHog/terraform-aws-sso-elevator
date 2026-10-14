"""Unit tests for the cache module.

Tests cover all error handling scenarios including:
- S3 bucket doesn't exist
- Wrong bucket name
- Missing IAM permissions (simulated)
- Cache disabled (cache_enabled = false)
- Cache hit/miss scenarios
- Write failures
"""

import json
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError
from hypothesis import given, strategies as st

import cache as cache_module
from entities.aws import Account, PermissionSet

from . import strategies


@pytest.fixture
def cache_config_enabled():
    """Cache config with caching enabled."""
    return cache_module.CacheConfig(
        bucket_name="test-config-bucket",
        enabled=True,
    )


@pytest.fixture
def cache_config_disabled():
    """Cache config with caching disabled."""
    return cache_module.CacheConfig(
        bucket_name="test-config-bucket",
        enabled=False,
    )


@pytest.fixture
def mock_s3_client():
    """Mock S3 client."""
    client = Mock()
    client.exceptions = Mock()
    client.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
    client.exceptions.NoSuchBucket = type("NoSuchBucket", (Exception,), {})
    return client


@pytest.fixture
def sample_accounts():
    """Sample accounts for testing."""
    return [
        Account(id="111111111111", name="Test Account 1"),
        Account(id="222222222222", name="Test Account 2"),
    ]


@pytest.fixture
def sample_permission_sets():
    """Sample permission sets for testing."""
    return [
        PermissionSet(
            arn="arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-1111111111111111",
            name="AdministratorAccess",
            description="Administrator access permission set",
        ),
        PermissionSet(
            arn="arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-2222222222222222",
            name="ReadOnlyAccess",
            description="Read-only access permission set",
        ),
    ]


class TestCacheConfig:
    """Tests for CacheConfig."""

    def test_cache_config_enabled(self):
        """Test cache config when enabled."""
        config = cache_module.CacheConfig(
            bucket_name="test-config-bucket",
            enabled=True,
        )
        assert config.bucket_name == "test-config-bucket"
        assert config.enabled is True

    def test_cache_config_disabled(self):
        """Test cache config when disabled."""
        config = cache_module.CacheConfig(
            bucket_name="test-config-bucket",
            enabled=False,
        )
        assert config.bucket_name == "test-config-bucket"
        assert config.enabled is False


class TestGetCachedAccounts:
    """Tests for get_cached_accounts function."""

    def test_cache_disabled_returns_none(self, mock_s3_client, cache_config_disabled):
        """When cache is disabled, should return None without calling S3."""
        result = cache_module.get_cached_accounts(mock_s3_client, cache_config_disabled)

        assert result is None
        mock_s3_client.get_object.assert_not_called()

    def test_cache_miss_no_object(self, mock_s3_client, cache_config_enabled):
        """When object not found in cache, should return None."""
        mock_s3_client.get_object.side_effect = mock_s3_client.exceptions.NoSuchKey()

        result = cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled)

        assert result is None
        mock_s3_client.get_object.assert_called_once()

    def test_cache_hit_valid_data(self, mock_s3_client, cache_config_enabled, sample_accounts):
        """When cache has valid data, should return accounts."""
        accounts_data = [acc.dict() for acc in sample_accounts]
        body_mock = Mock()
        body_mock.read.return_value = json.dumps(accounts_data).encode("utf-8")

        mock_s3_client.get_object.return_value = {
            "Body": body_mock,
        }

        result = cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled)

        assert result is not None
        assert len(result) == 2
        assert result[0].id == "111111111111"
        assert result[1].id == "222222222222"

    def test_cache_hit_returns_data(self, mock_s3_client, cache_config_enabled, sample_accounts):
        """When cache has data, should return it (no TTL check)."""
        accounts_data = [acc.dict() for acc in sample_accounts]
        body_mock = Mock()
        body_mock.read.return_value = json.dumps(accounts_data).encode("utf-8")

        mock_s3_client.get_object.return_value = {
            "Body": body_mock,
        }

        result = cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled)

        assert result is not None
        assert len(result) == 2

    def test_bucket_doesnt_exist(self, mock_s3_client, cache_config_enabled):
        """When bucket doesn't exist, should return None gracefully."""
        mock_s3_client.get_object.side_effect = mock_s3_client.exceptions.NoSuchBucket()

        result = cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled)

        assert result is None

    def test_access_denied(self, mock_s3_client, cache_config_enabled):
        """When access is denied, should return None gracefully."""
        mock_s3_client.get_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetObject",
        )

        result = cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled)

        assert result is None

    def test_generic_exception(self, mock_s3_client, cache_config_enabled):
        """When generic exception occurs, should return None gracefully."""
        mock_s3_client.get_object.side_effect = Exception("Something went wrong")

        result = cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled)

        assert result is None


class TestSetCachedAccounts:
    """Tests for set_cached_accounts function."""

    def test_cache_disabled_no_write(self, mock_s3_client, cache_config_disabled, sample_accounts):
        """When cache is disabled, should not write to S3."""
        cache_module.set_cached_accounts(mock_s3_client, cache_config_disabled, sample_accounts)

        mock_s3_client.put_object.assert_not_called()

    def test_successful_write(self, mock_s3_client, cache_config_enabled, sample_accounts):
        """When cache is enabled, should write to S3."""
        cache_module.set_cached_accounts(mock_s3_client, cache_config_enabled, sample_accounts)

        mock_s3_client.put_object.assert_called_once()
        call_args = mock_s3_client.put_object.call_args
        assert call_args[1]["Bucket"] == "test-config-bucket"
        assert call_args[1]["Key"] == "accounts.json"
        assert call_args[1]["ContentType"] == "application/json"

    def test_bucket_doesnt_exist_during_write(self, mock_s3_client, cache_config_enabled, sample_accounts):
        """When bucket doesn't exist during write, should fail gracefully."""
        mock_s3_client.put_object.side_effect = mock_s3_client.exceptions.NoSuchBucket()

        # Should not raise exception
        cache_module.set_cached_accounts(mock_s3_client, cache_config_enabled, sample_accounts)

    def test_access_denied_during_write(self, mock_s3_client, cache_config_enabled, sample_accounts):
        """When access is denied during write, should fail gracefully."""
        mock_s3_client.put_object.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "PutObject",
        )

        # Should not raise exception
        cache_module.set_cached_accounts(mock_s3_client, cache_config_enabled, sample_accounts)

    def test_generic_exception_during_write(self, mock_s3_client, cache_config_enabled, sample_accounts):
        """When generic exception occurs during write, should fail gracefully."""
        mock_s3_client.put_object.side_effect = Exception("Something went wrong")

        # Should not raise exception
        cache_module.set_cached_accounts(mock_s3_client, cache_config_enabled, sample_accounts)


class TestGetCachedPermissionSets:
    """Tests for get_cached_permission_sets function."""

    def test_cache_disabled_returns_none(self, mock_s3_client, cache_config_disabled):
        """When cache is disabled, should return None without calling S3."""
        result = cache_module.get_cached_permission_sets(
            mock_s3_client,
            cache_config_disabled,
            "arn:aws:sso:::instance/ssoins-1111111111111111",
        )

        assert result is None
        mock_s3_client.get_object.assert_not_called()

    def test_cache_miss_no_object(self, mock_s3_client, cache_config_enabled):
        """When object not found in cache, should return None."""
        mock_s3_client.get_object.side_effect = mock_s3_client.exceptions.NoSuchKey()

        result = cache_module.get_cached_permission_sets(
            mock_s3_client,
            cache_config_enabled,
            "arn:aws:sso:::instance/ssoins-1111111111111111",
        )

        assert result is None

    def test_cache_hit_valid_data(self, mock_s3_client, cache_config_enabled, sample_permission_sets):
        """When cache has valid data, should return permission sets."""
        ps_data = [ps.dict() for ps in sample_permission_sets]
        body_mock = Mock()
        body_mock.read.return_value = json.dumps(ps_data).encode("utf-8")

        mock_s3_client.get_object.return_value = {
            "Body": body_mock,
        }

        result = cache_module.get_cached_permission_sets(
            mock_s3_client,
            cache_config_enabled,
            "arn:aws:sso:::instance/ssoins-1111111111111111",
        )

        assert result is not None
        assert len(result) == 2
        assert result[0].name == "AdministratorAccess"


class TestSetCachedPermissionSets:
    """Tests for set_cached_permission_sets function."""

    def test_cache_disabled_no_write(self, mock_s3_client, cache_config_disabled, sample_permission_sets):
        """When cache is disabled, should not write to S3."""
        cache_module.set_cached_permission_sets(
            mock_s3_client,
            cache_config_disabled,
            "arn:aws:sso:::instance/ssoins-1111111111111111",
            sample_permission_sets,
        )

        mock_s3_client.put_object.assert_not_called()

    def test_successful_write(self, mock_s3_client, cache_config_enabled, sample_permission_sets):
        """When cache is enabled, should write to S3."""
        cache_module.set_cached_permission_sets(
            mock_s3_client,
            cache_config_enabled,
            "arn:aws:sso:::instance/ssoins-1111111111111111",
            sample_permission_sets,
        )

        mock_s3_client.put_object.assert_called_once()
        call_args = mock_s3_client.put_object.call_args
        assert call_args[1]["Bucket"] == "test-config-bucket"
        assert "permission_sets/" in call_args[1]["Key"]


SSO_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-1111111111111111"

account_st = st.builds(Account, id=strategies.aws_account_id, name=st.text(min_size=1, max_size=20))


def _resource(cache_getter=None, api_getter=None, cache_setter=None):
    return cache_module.CachedResource(
        name="accounts",
        cache_getter=cache_getter or Mock(return_value=None),
        api_getter=api_getter or Mock(return_value=[]),
        cache_setter=cache_setter or Mock(return_value=True),
    )


class TestSetterReturnValues:
    """The setters report whether they wrote the object, so refresh_cache can log a failed write."""

    def test_set_cached_accounts_returns_true_on_write(self, mock_s3_client, cache_config_enabled, sample_accounts):
        assert cache_module.set_cached_accounts(mock_s3_client, cache_config_enabled, sample_accounts) is True

    def test_set_cached_accounts_returns_false_when_disabled(self, mock_s3_client, cache_config_disabled, sample_accounts):
        assert cache_module.set_cached_accounts(mock_s3_client, cache_config_disabled, sample_accounts) is False
        mock_s3_client.put_object.assert_not_called()

    def test_set_cached_accounts_returns_false_on_write_error(self, mock_s3_client, cache_config_enabled, sample_accounts):
        mock_s3_client.put_object.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "PutObject")
        assert cache_module.set_cached_accounts(mock_s3_client, cache_config_enabled, sample_accounts) is False

    def test_set_cached_permission_sets_returns_true_on_write(self, mock_s3_client, cache_config_enabled, sample_permission_sets):
        result = cache_module.set_cached_permission_sets(mock_s3_client, cache_config_enabled, SSO_INSTANCE_ARN, sample_permission_sets)
        assert result is True

    def test_set_cached_permission_sets_returns_false_when_disabled(self, mock_s3_client, cache_config_disabled, sample_permission_sets):
        result = cache_module.set_cached_permission_sets(mock_s3_client, cache_config_disabled, SSO_INSTANCE_ARN, sample_permission_sets)
        assert result is False
        mock_s3_client.put_object.assert_not_called()

    def test_set_cached_permission_sets_returns_false_on_write_error(self, mock_s3_client, cache_config_enabled, sample_permission_sets):
        mock_s3_client.put_object.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "PutObject")
        result = cache_module.set_cached_permission_sets(mock_s3_client, cache_config_enabled, SSO_INSTANCE_ARN, sample_permission_sets)
        assert result is False


class TestCorruptCacheObject:
    def test_invalid_json_is_a_miss(self, mock_s3_client, cache_config_enabled):
        mock_s3_client.get_object.return_value = {"Body": Mock(read=Mock(return_value=b"not json"))}
        assert cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled) is None

    def test_old_schema_is_a_miss(self, mock_s3_client, cache_config_enabled):
        body = json.dumps([{"account_id": "111111111111"}]).encode("utf-8")
        mock_s3_client.get_object.return_value = {"Body": Mock(read=Mock(return_value=body))}
        assert cache_module.get_cached_accounts(mock_s3_client, cache_config_enabled) is None


class TestGetCacheFirst:
    def test_cache_hit_returns_cache_without_api_call(self, sample_accounts):
        api_getter = Mock()
        cache_setter = Mock()
        resource = _resource(cache_getter=Mock(return_value=sample_accounts), api_getter=api_getter, cache_setter=cache_setter)

        assert cache_module.get_cache_first(resource) == sample_accounts
        api_getter.assert_not_called()
        cache_setter.assert_not_called()

    def test_empty_list_is_a_cache_hit(self):
        api_getter = Mock()
        resource = _resource(cache_getter=Mock(return_value=[]), api_getter=api_getter)

        assert cache_module.get_cache_first(resource) == []
        api_getter.assert_not_called()

    def test_cache_miss_calls_api_and_writes_cache(self, sample_accounts):
        cache_setter = Mock(return_value=True)
        resource = _resource(api_getter=Mock(return_value=sample_accounts), cache_setter=cache_setter)

        assert cache_module.get_cache_first(resource) == sample_accounts
        cache_setter.assert_called_once_with(sample_accounts)

    def test_disabled_cache_calls_api(self, mock_s3_client, cache_config_disabled, sample_accounts):
        api_getter = Mock(return_value=sample_accounts)
        resource = cache_module.CachedResource(
            name="accounts",
            cache_getter=lambda: cache_module.get_cached_accounts(mock_s3_client, cache_config_disabled),
            api_getter=api_getter,
            cache_setter=lambda accounts: cache_module.set_cached_accounts(mock_s3_client, cache_config_disabled, accounts),
        )

        assert cache_module.get_cache_first(resource) == sample_accounts
        api_getter.assert_called_once()
        mock_s3_client.get_object.assert_not_called()
        mock_s3_client.put_object.assert_not_called()

    def test_getter_error_counts_as_miss(self, sample_accounts):
        resource = _resource(cache_getter=Mock(side_effect=RuntimeError("s3 down")), api_getter=Mock(return_value=sample_accounts))

        assert cache_module.get_cache_first(resource) == sample_accounts

    def test_miss_and_api_error_raises(self):
        resource = _resource(api_getter=Mock(side_effect=ValueError("API error")))

        with pytest.raises(ValueError, match="API error"):
            cache_module.get_cache_first(resource)

    def test_setter_error_still_returns_api_data(self, sample_accounts):
        resource = _resource(api_getter=Mock(return_value=sample_accounts), cache_setter=Mock(side_effect=RuntimeError("put failed")))

        assert cache_module.get_cache_first(resource) == sample_accounts

    @given(cached=st.lists(account_st, max_size=5))
    def test_property_hit_never_calls_api(self, cached):
        api_getter = Mock()
        resource = _resource(cache_getter=Mock(return_value=cached), api_getter=api_getter)

        assert cache_module.get_cache_first(resource) == cached
        api_getter.assert_not_called()


class TestRefreshCache:
    def test_changed_data_is_written(self, sample_accounts):
        cache_setter = Mock(return_value=True)
        resource = _resource(
            cache_getter=Mock(return_value=sample_accounts[:1]), api_getter=Mock(return_value=sample_accounts), cache_setter=cache_setter
        )

        cache_module.refresh_cache(resource)

        cache_setter.assert_called_once_with(sample_accounts)

    def test_unchanged_data_is_not_written(self, sample_accounts):
        cache_setter = Mock(return_value=True)
        resource = _resource(
            cache_getter=Mock(return_value=list(sample_accounts)), api_getter=Mock(return_value=sample_accounts), cache_setter=cache_setter
        )

        cache_module.refresh_cache(resource)

        cache_setter.assert_not_called()

    def test_empty_cache_is_written(self, sample_accounts):
        cache_setter = Mock(return_value=True)
        resource = _resource(api_getter=Mock(return_value=sample_accounts), cache_setter=cache_setter)

        cache_module.refresh_cache(resource)

        cache_setter.assert_called_once_with(sample_accounts)

    def test_api_error_does_not_raise_or_write(self):
        cache_setter = Mock(return_value=True)
        resource = _resource(api_getter=Mock(side_effect=RuntimeError("throttled")), cache_setter=cache_setter)

        cache_module.refresh_cache(resource)

        cache_setter.assert_not_called()

    def test_setter_error_does_not_raise(self, sample_accounts):
        resource = _resource(api_getter=Mock(return_value=sample_accounts), cache_setter=Mock(side_effect=RuntimeError("put failed")))

        cache_module.refresh_cache(resource)

    def test_getter_error_counts_as_empty_cache(self, sample_accounts):
        cache_setter = Mock(return_value=True)
        resource = _resource(
            cache_getter=Mock(side_effect=RuntimeError("s3 down")), api_getter=Mock(return_value=sample_accounts), cache_setter=cache_setter
        )

        cache_module.refresh_cache(resource)

        cache_setter.assert_called_once_with(sample_accounts)

    def test_logs_updated(self, sample_accounts):
        resource = _resource(api_getter=Mock(return_value=sample_accounts))

        with patch.object(cache_module, "logger") as logger:
            cache_module.refresh_cache(resource)

        logger.info.assert_called_once_with("Cache refresh for accounts: updated")
        logger.warning.assert_not_called()

    def test_logs_unchanged(self, sample_accounts):
        resource = _resource(cache_getter=Mock(return_value=list(sample_accounts)), api_getter=Mock(return_value=sample_accounts))

        with patch.object(cache_module, "logger") as logger:
            cache_module.refresh_cache(resource)

        logger.info.assert_called_once_with("Cache refresh for accounts: unchanged")
        logger.warning.assert_not_called()

    def test_logs_failed_on_api_error(self):
        resource = _resource(api_getter=Mock(side_effect=RuntimeError("throttled")))

        with patch.object(cache_module, "logger") as logger:
            cache_module.refresh_cache(resource)

        logger.warning.assert_called_once()
        assert logger.warning.call_args.args[0] == "Cache refresh for accounts: failed"
        logger.info.assert_not_called()

    def test_logs_failed_when_setter_returns_false(self, sample_accounts):
        resource = _resource(api_getter=Mock(return_value=sample_accounts), cache_setter=Mock(return_value=False))

        with patch.object(cache_module, "logger") as logger:
            cache_module.refresh_cache(resource)

        logger.warning.assert_called_once()
        assert logger.warning.call_args.args[0] == "Cache refresh for accounts: failed"
        logger.info.assert_not_called()

    def test_logs_failed_when_setter_raises(self, sample_accounts):
        resource = _resource(api_getter=Mock(return_value=sample_accounts), cache_setter=Mock(side_effect=RuntimeError("put failed")))

        with patch.object(cache_module, "logger") as logger:
            cache_module.refresh_cache(resource)

        logger.warning.assert_called_once()
        assert logger.warning.call_args.args[0] == "Cache refresh for accounts: failed"

    @given(cached=st.none() | st.lists(account_st, max_size=5), api=st.lists(account_st, max_size=5))
    def test_property_successful_refresh_leaves_cache_equal_to_api(self, cached, api):
        store = {"value": cached}

        def setter(value):
            store["value"] = value
            return True

        resource = cache_module.CachedResource(
            name="accounts", cache_getter=lambda: store["value"], api_getter=lambda: api, cache_setter=setter
        )

        cache_module.refresh_cache(resource)

        assert store["value"] == api
