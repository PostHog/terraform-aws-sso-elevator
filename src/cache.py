"""S3 cache of AWS accounts and permission sets: cache-first reads and refreshes."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Generic, Optional, TypeVar

import config
from entities.aws import Account, PermissionSet

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client

logger = config.get_logger(service="cache")

T = TypeVar("T")

# Regex pattern for validating AWS ARN format
ARN_PATTERN = re.compile(r"^arn:aws(?:-[a-z0-9]+){0,5}:sso:::\w+/[\w-]+$")

# Maximum ARN length to prevent excessively long input
MAX_ARN_LENGTH = 1024

# Maximum size for serialized data to prevent excessively large payloads (in bytes)
MAX_DATA_SIZE = 5 * 1024 * 1024  # 5MB limit for S3 objects

# Pattern for validating S3 bucket names
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


@dataclass
class CacheConfig:
    """Configuration for the cache."""

    bucket_name: str
    enabled: bool

    @staticmethod
    def from_config(cfg: config.Config) -> "CacheConfig":
        """Create a CacheConfig from the application config."""
        return CacheConfig(
            bucket_name=cfg.config_bucket_name,
            enabled=cfg.cache_enabled,
        )


class CacheKey:
    """Constants for cache keys."""

    ACCOUNTS = "accounts.json"
    PERMISSION_SETS_PREFIX = "permission_sets/"


def _validate_arn(arn: str) -> str:
    """Validate and sanitize SSO instance ARN.

    Args:
        arn: SSO instance ARN to validate

    Returns:
        Validated ARN string

    Raises:
        ValueError: If the ARN format is invalid
    """
    if not isinstance(arn, str):
        raise ValueError(f"ARN must be a string, got {type(arn)}")

    if not ARN_PATTERN.match(arn):
        raise ValueError(f"Invalid SSO instance ARN format: {arn}")

    if len(arn) > MAX_ARN_LENGTH:
        raise ValueError("ARN exceeds maximum length")

    return arn


def _validate_bucket_name(bucket_name: str) -> str:
    """Validate S3 bucket name to prevent injection attacks.

    Args:
        bucket_name: Bucket name to validate

    Returns:
        Validated bucket name

    Raises:
        ValueError: If the bucket name format is invalid
    """
    if not isinstance(bucket_name, str):
        raise ValueError(f"Bucket name must be a string, got {type(bucket_name)}")

    if not BUCKET_NAME_PATTERN.match(bucket_name):
        raise ValueError(f"Invalid S3 bucket name format: {bucket_name}")

    return bucket_name


def _sanitize_json_data(data: list[dict[str, Any]]) -> str:
    """Sanitize and validate data before storing in S3.

    Args:
        data: List of dictionaries to serialize

    Returns:
        JSON string of the sanitized data

    Raises:
        ValueError: If the data is invalid or too large
    """
    if not isinstance(data, list):
        raise ValueError(f"Data must be a list, got {type(data)}")

    try:
        serialized = json.dumps(data)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Data contains non-serializable content: {e}") from e

    data_size = len(serialized.encode("utf-8"))
    if data_size > MAX_DATA_SIZE:
        raise ValueError(f"Data size ({data_size} bytes) exceeds maximum allowed size ({MAX_DATA_SIZE} bytes)")

    return serialized


def get_cached_accounts(
    s3_client: S3Client,
    cache_config: CacheConfig,
) -> Optional[list[Account]]:
    """Get cached accounts from S3.

    Args:
        s3_client: S3 client
        cache_config: Cache configuration

    Returns:
        List of cached accounts or None if cache miss
    """
    if not cache_config.enabled:
        logger.debug("Cache is disabled, skipping cache lookup")
        return None

    try:
        validated_bucket_name = _validate_bucket_name(cache_config.bucket_name)

        response = s3_client.get_object(
            Bucket=validated_bucket_name,
            Key=CacheKey.ACCOUNTS,
        )

        accounts_data = json.loads(response["Body"].read().decode("utf-8"))
        accounts = [Account.model_validate(acc) for acc in accounts_data]

        logger.info(f"Retrieved {len(accounts)} accounts from cache")
        return accounts

    except s3_client.exceptions.NoSuchKey:
        logger.info("Cache miss for accounts - no cached data found")
        return None
    except Exception as e:
        logger.warning(f"Failed to get cached accounts: {e}", extra={"error": str(e)})
        return None


def set_cached_accounts(
    s3_client: S3Client,
    cache_config: CacheConfig,
    accounts: list[Account],
) -> bool:
    """Store accounts in S3 cache.

    Args:
        s3_client: S3 client
        cache_config: Cache configuration
        accounts: List of accounts to cache

    Returns:
        True if the accounts were written, False if the cache is disabled or the write failed
    """
    if not cache_config.enabled:
        logger.debug("Cache is disabled, skipping cache write")
        return False

    try:
        validated_bucket_name = _validate_bucket_name(cache_config.bucket_name)

        accounts_data = [account.dict() for account in accounts]
        sanitized_data = _sanitize_json_data(accounts_data)

        s3_client.put_object(
            Bucket=validated_bucket_name,
            Key=CacheKey.ACCOUNTS,
            Body=sanitized_data.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )

        logger.info(f"Cached {len(accounts)} accounts")
        return True

    except ValueError as e:
        logger.warning(f"Validation failed when caching accounts: {e}", extra={"error": str(e)})
    except Exception as e:
        logger.warning(f"Failed to cache accounts: {e}", extra={"error": str(e)})
    return False


def get_cached_permission_sets(
    s3_client: S3Client,
    cache_config: CacheConfig,
    sso_instance_arn: str,
) -> Optional[list[PermissionSet]]:
    """Get cached permission sets from S3.

    Args:
        s3_client: S3 client
        cache_config: Cache configuration
        sso_instance_arn: SSO instance ARN (used as part of cache key)

    Returns:
        List of cached permission sets or None if cache miss
    """
    if not cache_config.enabled:
        logger.debug("Cache is disabled, skipping cache lookup")
        return None

    try:
        validated_bucket_name = _validate_bucket_name(cache_config.bucket_name)
        validated_arn = _validate_arn(sso_instance_arn)

        arn_hash = validated_arn.replace(":", "_").replace("/", "_")
        key = f"{CacheKey.PERMISSION_SETS_PREFIX}{arn_hash}.json"

        response = s3_client.get_object(
            Bucket=validated_bucket_name,
            Key=key,
        )

        permission_sets_data = json.loads(response["Body"].read().decode("utf-8"))
        permission_sets = [PermissionSet.model_validate(ps) for ps in permission_sets_data]

        logger.info(f"Retrieved {len(permission_sets)} permission sets from cache")
        return permission_sets

    except s3_client.exceptions.NoSuchKey:
        logger.info("Cache miss for permission sets - no cached data found")
        return None
    except Exception as e:
        logger.warning(f"Failed to get cached permission sets: {e}", extra={"error": str(e)})
        return None


def set_cached_permission_sets(
    s3_client: S3Client,
    cache_config: CacheConfig,
    sso_instance_arn: str,
    permission_sets: list[PermissionSet],
) -> bool:
    """Store permission sets in S3 cache.

    Args:
        s3_client: S3 client
        cache_config: Cache configuration
        sso_instance_arn: SSO instance ARN (used as part of cache key)
        permission_sets: List of permission sets to cache

    Returns:
        True if the permission sets were written, False if the cache is disabled or the write failed
    """
    if not cache_config.enabled:
        logger.debug("Cache is disabled, skipping cache write")
        return False

    try:
        validated_bucket_name = _validate_bucket_name(cache_config.bucket_name)
        validated_arn = _validate_arn(sso_instance_arn)

        permission_sets_data = [ps.dict() for ps in permission_sets]
        sanitized_data = _sanitize_json_data(permission_sets_data)

        arn_hash = validated_arn.replace(":", "_").replace("/", "_")
        key = f"{CacheKey.PERMISSION_SETS_PREFIX}{arn_hash}.json"

        s3_client.put_object(
            Bucket=validated_bucket_name,
            Key=key,
            Body=sanitized_data.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )

        logger.info(f"Cached {len(permission_sets)} permission sets")
        return True

    except ValueError as e:
        logger.warning(f"Validation failed when caching permission sets: {e}", extra={"error": str(e)})
    except Exception as e:
        logger.warning(f"Failed to cache permission sets: {e}", extra={"error": str(e)})
    return False


def _compute_data_hash(data: object) -> str:
    """Compute SHA256 hash of data for comparison.

    Args:
        data: Data to hash (list of Account or PermissionSet objects)

    Returns:
        Hex string of SHA256 hash
    """
    try:
        # Convert to JSON string with sorted keys for consistent hashing
        json_str = json.dumps([item.dict() if hasattr(item, "dict") else item for item in data], sort_keys=True)  # pyright: ignore[reportGeneralTypeIssues]
        return hashlib.sha256(json_str.encode("utf-8")).hexdigest()
    except Exception as e:
        logger.warning(f"Failed to compute hash: {e}")
        # Return a random value to force cache update on error
        return ""


def _compare_data(api_data: T, cached_data: T) -> bool:
    """Compare API data with cached data using hash comparison.

    Args:
        api_data: Data from API
        cached_data: Data from cache

    Returns:
        True if data matches, False otherwise
    """
    try:
        api_hash = _compute_data_hash(api_data)
        cache_hash = _compute_data_hash(cached_data)
        return api_hash == cache_hash and api_hash != ""
    except Exception:
        # If comparison fails, assume data is different
        return False


@dataclass(frozen=True)
class CachedResource(Generic[T]):
    """An AWS resource list kept in the S3 cache: how to read the cache, call the API, and write the cache."""

    name: str
    cache_getter: Callable[[], Optional[T]]
    api_getter: Callable[[], T]
    cache_setter: Callable[[T], bool]


def _read_cache(resource: CachedResource[T]) -> Optional[T]:
    try:
        return resource.cache_getter()
    except Exception as e:
        logger.warning(f"Cache read failed for {resource.name}: {e}")
        return None


def get_cache_first(resource: CachedResource[T]) -> T:
    """Return the cached data if there is any. Otherwise call the API and write the result to the cache.

    An empty cached list is a hit. refresh_cache keeps the cache current.

    Raises:
        Exception: If the cache has no data and the API call fails
    """
    cached_data = _read_cache(resource)
    if cached_data is not None:
        return cached_data

    api_data = resource.api_getter()
    try:
        resource.cache_setter(api_data)
    except Exception as e:
        logger.warning(f"Failed to cache {resource.name}: {e}")
    return api_data


def refresh_cache(resource: CachedResource[T]) -> None:
    """Call the API and write the result to the cache if it differs from the cached data. Never raises."""
    try:
        api_data = resource.api_getter()
    except Exception as e:
        logger.warning(f"Cache refresh for {resource.name}: failed", extra={"error": str(e)})
        return

    cached_data = _read_cache(resource)
    if cached_data is not None and _compare_data(api_data, cached_data):
        logger.info(f"Cache refresh for {resource.name}: unchanged")
        return

    try:
        written = resource.cache_setter(api_data)
    except Exception as e:
        logger.warning(f"Cache refresh for {resource.name}: failed", extra={"error": str(e)})
        return

    if written:
        logger.info(f"Cache refresh for {resource.name}: updated")
    else:
        logger.warning(f"Cache refresh for {resource.name}: failed", extra={"error": "cache write did not complete"})
