from mypy_boto3_organizations import OrganizationsClient, type_defs
from mypy_boto3_s3 import S3Client

import cache as cache_module
import config
from entities.aws import Account

logger = config.get_logger(service="organizations")


def parse_account(td: type_defs.AccountTypeDef) -> Account:
    return Account.model_validate({"id": td.get("Id"), "name": td.get("Name")})


def list_accounts(client: OrganizationsClient) -> list[Account]:
    accounts = []
    paginator = client.get_paginator("list_accounts")
    for page in paginator.paginate():
        accounts.extend(page["Accounts"])
    return [parse_account(account) for account in accounts]


def _accounts_cache(
    org_client: OrganizationsClient,
    s3_client: S3Client,
    cfg: config.Config,
) -> cache_module.CachedResource[list[Account]]:
    cache_config = cache_module.CacheConfig.from_config(cfg)
    return cache_module.CachedResource(
        name="accounts",
        cache_getter=lambda: cache_module.get_cached_accounts(s3_client, cache_config),
        api_getter=lambda: list_accounts(org_client),
        cache_setter=lambda accounts: cache_module.set_cached_accounts(s3_client, cache_config, accounts),
    )


def list_accounts_with_cache(
    org_client: OrganizationsClient,
    s3_client: S3Client,
    cfg: config.Config,
) -> list[Account]:
    """List all accounts, from the S3 cache if it has data.

    On a cache miss, this calls the Organizations API and writes the result to the cache.
    refresh_accounts_cache keeps the cache current.

    Args:
        org_client: Organizations client
        s3_client: S3 client for cache
        cfg: Application configuration

    Returns:
        List of all accounts
    """
    return cache_module.get_cache_first(_accounts_cache(org_client, s3_client, cfg))


def refresh_accounts_cache(
    org_client: OrganizationsClient,
    s3_client: S3Client,
    cfg: config.Config,
) -> None:
    """Fetch all accounts from the Organizations API and update the S3 cache if they changed. Never raises."""
    cache_module.refresh_cache(_accounts_cache(org_client, s3_client, cfg))


def describe_account(client: OrganizationsClient, account_id: str) -> Account:
    account = client.describe_account(AccountId=account_id)["Account"]
    return parse_account(account)


def get_accounts_from_config(client: OrganizationsClient, cfg: config.Config) -> list[Account]:
    if "*" in cfg.accounts:
        accounts = list_accounts(client)
    else:
        accounts = [ac for ac in list_accounts(client) if ac.id in cfg.accounts]
    return accounts


def get_accounts_from_config_with_cache(
    org_client: OrganizationsClient,
    s3_client: S3Client,
    cfg: config.Config,
) -> list[Account]:
    """Get the accounts named in the config, from the S3 cache if it has data.

    Args:
        org_client: Organizations client
        s3_client: S3 client for cache
        cfg: Application configuration

    Returns:
        List of accounts based on config
    """
    all_accounts = list_accounts_with_cache(org_client, s3_client, cfg)

    if "*" in cfg.accounts:
        return all_accounts
    else:
        return [ac for ac in all_accounts if ac.id in cfg.accounts]
