# AWS Accounts and Permission Sets Caching Implementation

## Overview

SSO Elevator caches AWS accounts and permission sets in S3. The request modal reads from the cache first, so it does not wait for the Organizations API (which returns at most 20 accounts per page). The cache also keeps the modal working during an AWS API outage.

## Caching Strategy

### Cache-first reads

1. **Cache hit**: return the cached data. Do not call the API. An empty cached list is a hit.
2. **Cache miss** (no object, unreadable object, or cache disabled): call the API, write the result to the cache, and return it.
3. **Cache miss and API failure**: raise the error.

### Refreshes

A refresh calls the API and writes the result to the cache only if it differs from the cached data. A refresh never raises. Two triggers run it:

1. **The request modal.** After the modal shows the account list, the same Lambda invocation refreshes the accounts and permission-sets caches. The user does not wait for it. A user who does not see a new account closes and reopens the modal.
2. **A schedule.** An EventBridge rule sends `{"action": "refresh_cache"}` to the revoker Lambda. The default is `rate(15 minutes)` (`schedule_expression_for_cache_refresh`). The rule exists only when `cache_enabled` is true.

### Trade-off

A new or removed account or permission set can show stale data until the next refresh: up to 15 minutes by default, or until a user reopens the modal.

## Implementation Details

### Infrastructure Changes

1. **S3 Bucket** (`s3.tf`):
   - Uses the same `fivexl/account-baseline/aws//modules/s3_baseline` module as the audit bucket
   - Bucket name: Configurable via `config_bucket_name` variable (default: `sso-elevator-config`)
   - Cache structure:
     - `accounts.json` - stores all accounts
     - `permission_sets/<arn_hash>.json` - stores permission sets per SSO instance
   - No TTL metadata - cache is kept indefinitely
   - **Security Features**:
     - Server-side encryption enabled (AES256 by default, KMS optional via `config_bucket_kms_key_arn`)
     - Public access blocked (via s3_baseline module)
     - Versioning enabled
     - Lifecycle policy to clean up old versions after 7 days
   - **Note**: The bucket is always created (not conditional) as it's intended for future config storage even when caching is disabled

2. **Variables** (`vars.tf`):
   - `config_bucket_name`: Name of the S3 bucket (default: `sso-elevator-config`)
   - `cache_enabled`: Enable/disable caching (default: `true`)
   - `config_bucket_kms_key_arn`: Optional ARN of a customer-managed KMS key for encryption (default: null)
   - Variables are passed to Lambda functions as environment variables

3. **IAM Permissions**:
   - S3 permissions added to the requester Lambda function:
     - `s3:GetObject`
     - `s3:PutObject`
     - `s3:ListBucket`
   - Note: The revoker Lambda has `s3:GetObject` and `s3:ListBucket` on the config bucket. When `cache_enabled` is true, it also has `s3:PutObject` on `accounts.json` and `permission_sets/*` for the scheduled refresh.

4. **Outputs** (`outputs.tf`):
   - `config_s3_bucket_name`: The name of the config S3 bucket
   - `config_s3_bucket_arn`: The ARN of the config S3 bucket

### Application Changes

1. **Cache Module** (`src/cache.py`):
   - `CacheConfig`: Configuration class for cache settings (no TTL field)
   - `get_cached_accounts()` / `set_cached_accounts()`: Read and write the accounts object. The setter returns `True` when it wrote the object.
   - `get_cached_permission_sets()` / `set_cached_permission_sets()`: Read and write the permission-sets object. The setter returns `True` when it wrote the object.
   - `CachedResource`: Bundles a resource name, cache getter, API getter and cache setter.
   - `get_cache_first()`: Cache-first read.
   - `refresh_cache()`: API read, then a cache write if the data changed. Never raises.

2. **Organizations Module** (`src/organizations.py`):
   - `list_accounts_with_cache()` / `get_accounts_from_config_with_cache()`: Cache-first account lists
   - `refresh_accounts_cache()`: Refreshes the accounts cache

3. **SSO Module** (`src/sso.py`):
   - `list_permission_sets_with_cache()` / `get_permission_sets_from_config_with_cache()`: Cache-first permission-set lists
   - `refresh_permission_sets_cache()`: Refreshes the permission-sets cache
   - `refresh_account_and_permission_set_caches()`: Refreshes both. Returns at once when `cache_enabled` is false.

4. **Updated Config** (`src/config.py`):
   - `config_bucket_name`: S3 bucket name (default: `sso-elevator-config`)
   - `cache_enabled`: Boolean flag to enable/disable caching (default: `True`)
   - Removed `cache_ttl_minutes` field

5. **Lambda Handlers**:
   - `src/main.py`: Reads accounts and permission sets cache-first. The account-modal populate step refreshes both caches after `views_update`.
   - `src/revoker.py`: Refreshes both caches on the `refresh_cache` scheduled event. Its inconsistency checks and revocations do NOT read the cache. They always fetch fresh data from AWS APIs for accuracy.

## Cache Behavior

### Cache Key Structure

The cache uses S3 object keys:

1. **Accounts Cache**:
   - Key: `accounts.json`
   - Stores all accounts in a single JSON file

2. **Permission Sets Cache**:
   - Key: `permission_sets/<arn_hash>.json`
   - Stores all permission sets for a specific SSO instance
   - ARN is hashed (colons and slashes replaced with underscores) for safe file naming

### Cache Lifecycle

1. **First request after deploy**: Cache miss → API → write cache → return API data. The refresh after the modal fills calls the API again.
2. **Later requests**: Cache hit → return cached data. No API call before the modal fills.
3. **Data changed in AWS**: The next refresh (modal or schedule) writes the new data. The next modal open shows it.
4. **API unavailable**: Reads return cached data. Refreshes log `Cache refresh for <name>: failed` and keep the old cache.
5. **Cache unavailable**: Reads fall back to the API on every request. Refreshes log `failed`.

### Error Handling

**The cache is designed to be fail-safe:**

- All cache operations are wrapped in try-except blocks
- **Cache failures NEVER prevent the application from functioning**
- Warnings are logged when cache operations fail
- S3 unavailability automatically triggers fallback to direct AWS API calls
- Application works normally if:
  - S3 bucket doesn't exist
  - Bucket name is misconfigured
  - IAM permissions are missing
  - S3 service is down
  
**Behavior on errors:**
- **Cache read errors**: Treated as a cache miss. The read calls the API.
- **Cache write errors**: Log a warning. The read returns the API data. A refresh logs `failed`.
- **API errors on a cache hit**: None. The read does not call the API.
- **API errors during a refresh**: Log `failed` and keep the old cache.
- **Cache miss and API error**: Raise an exception (the application cannot function).

## Configuration

### Default Configuration

Caching is **enabled by default**:

```hcl
module "aws_sso_elevator" {
  source = "path/to/module"
  
  # Other configuration...
  
  # These are the defaults (no need to specify):
  # cache_enabled          = true
  # config_bucket_name     = "sso-elevator-config"
  # config_bucket_kms_key_arn = null  # Uses AES256 encryption
}
```

### Disabling Cache

To disable caching (S3 bucket will still be created for future config storage):

```hcl
module "aws_sso_elevator" {
  source = "path/to/module"
  
  # Other configuration...
  
  cache_enabled = false  # Disable caching (bucket still created for future use)
}
```

### Custom Bucket Name

To use a custom S3 bucket name:

```hcl
module "aws_sso_elevator" {
  source = "path/to/module"
  
  # Other configuration...
  
  config_bucket_name = "my-custom-sso-elevator-config"
}
```

### Custom KMS Key for Encryption

To use a customer-managed KMS key instead of AES256:

```hcl
module "aws_sso_elevator" {
  source = "path/to/module"
  
  # Other configuration...
  
  config_bucket_kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}
```

## Monitoring

### CloudWatch Logs

Cache operations are logged with the following patterns:

- `"Retrieved X accounts from cache"`: Cache hit
- `"Cache miss for accounts"`: No cached accounts found
- `"Cache refresh for accounts: updated"` / `"... permission_sets: updated"`: The refresh wrote new data (INFO)
- `"Cache refresh for accounts: unchanged"`: The refresh found no change (INFO)
- `"Cache refresh for accounts: failed"`: The API call or the cache write failed (WARNING)
- `"Failed to get cached accounts"`: Error reading from cache
- `"Failed to cache accounts"`: Error writing to cache

The scheduled refresh logs to the revoker log group. Each run logs one `Cache refresh for` line per resource.

### S3 Metrics

Monitor these CloudWatch metrics for the cache bucket:

- `NumberOfObjects`: Number of cached items
- `BucketSizeBytes`: Total cache size
- `AllRequests`: Cache read/write activity

## Security Considerations

1. **Data Sensitivity**: Cache contains account IDs, names, and permission set information
2. **Encryption**: 
   - Server-side encryption is **enabled by default** using AES256
   - Optional customer-managed KMS key support via `cache_kms_key_arn` variable
   - Encryption at rest is always active
3. **Access Control**: IAM permissions limit cache access to Lambda functions only
4. **Public Access**: All public access is blocked by default
5. **Versioning**: Enabled to protect against accidental overwrites
6. **No Expiration**: Cache is kept indefinitely and updated automatically when data changes

## Performance Impact

- **Cache hit**: about 0.1s (S3 GetObject). The modal does not wait for the API.
- **Cache miss**: API latency. For about 600 accounts, the Organizations API takes about 5s (31 pages of 20).
- **Refresh**: API latency, after the modal fills or on the schedule. No user waits for it.
- **Cost**: S3 charges apply (~$0.005 per 1,000 GET requests, ~$0.005 per 1,000 PUT requests). The schedule adds 96 runs per day at the default rate.

## Backward Compatibility

- Existing deployments will need to update their Terraform configuration
- The variable `cache_ttl_minutes` has been removed and replaced with `cache_enabled`
- Cache behavior has changed from TTL-based to automatic update-based
- No data migration is needed as the cache will refresh automatically

## Migration from TTL-Based Cache

If you're migrating from the TTL-based cache:

1. Update your Terraform configuration to remove `cache_ttl_minutes` and use `cache_enabled` instead
2. Apply the Terraform changes
3. The cache will continue to work with the new strategy
4. No manual intervention needed

## Testing Recommendations

### Integration Testing

1. **Cache hit**: Open the request modal → Verify that the account list shows in about 1s.
2. **Modal refresh**: Create an account → Open the modal (old list) → Reopen it → Verify that the new account shows.
3. **Scheduled refresh**: Check the revoker logs every 15 minutes for one `Cache refresh for` line per resource.
4. **API outage**: Temporarily block API access → Verify that the modal still shows cached data.
5. **Cache disabled**: Set `cache_enabled = false` → Verify normal operation (no S3 calls) and no refresh rule.

## Troubleshooting

### "Failed to get cached accounts" warnings

**Important:** These warnings do not break functionality. The application will continue to work using API data.

Common causes:
- S3 bucket doesn't exist (check Terraform deployment)
- Wrong bucket name (verify `config_bucket_name` matches between Terraform and Lambda environment variables)
- Lambda IAM permissions missing S3 read access

**How to diagnose:**
1. Check CloudWatch Logs for the full error message
2. Verify the bucket exists: `aws s3 ls s3://sso-elevator-config-<random-suffix>`
3. Confirm bucket name environment variable: Check Lambda configuration `CONFIG_BUCKET_NAME`
4. Verify IAM permissions include `s3:GetObject`, `s3:ListBucket`

### "Failed to cache accounts" warnings

**Important:** These warnings do not break functionality. The application will continue to work with API data.

Common causes:
- S3 bucket doesn't exist
- Wrong bucket name configuration
- Lambda IAM permissions missing S3 write access

**How to diagnose:**
1. Check CloudWatch Logs for detailed error messages
2. Verify IAM permissions include `s3:PutObject`

### Cache not updating

If the cache does not update when AWS data changes:
1. Search the revoker logs for `Cache refresh for`. No lines at all means the schedule is not running: check the `<revoker>-cache-refresh` EventBridge rule.
2. A `failed` line means the API call or the write failed. Check the `error` field.
3. Verify that the revoker role has `s3:PutObject` on `accounts.json` and `permission_sets/*` in the config bucket.
