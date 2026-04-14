# Claude Code Instructions

## Before Committing

Always run these commands before committing changes:

```bash
# Run type checking
cd src && uv run pyright .

# Run tests
cd src && uv run pytest -q

# Run all pre-commit hooks (linting, formatting, terraform docs, etc.)
uv run --directory src --extra dev pre-commit run --all-files
```

## Running Tests

```bash
cd src && uv run pytest -q
```

## Architecture Overview

Terraform module that deploys AWS Lambda functions for just-in-time AWS SSO access management via Slack. Two access models exist: **account access** (temporary permission set assignment on AWS accounts) and **group access** (temporary SSO group membership).

### Terraform Layer

- `vars.tf` — Module inputs. Two separate config variables: `config` (account access statements) and `group_config` (group access statements), both `type = any`.
- `s3.tf` — Serializes both to a single S3 object as `{"statements": var.config, "group_statements": var.group_config}`.
- `locals.tf` — Validation logic (group/attribute-sync overlap checks, extracting group names from `group_config`).
- `slack_handler_lambda.tf` / `perm_revoker_lambda.tf` — Lambda function definitions. Both read config from the same S3 object.

### Python Layer (`src/`)

**Config & Models:**
- `config.py` — Loads config from S3 (`load_approval_config_from_s3`), parses into `Statement`/`GroupStatement` via `parse_statement`/`parse_group_statement`. `Config` is a Pydantic `BaseSettings` singleton with `frozenset` fields for statements, accounts, groups, permission_sets.
- `statement.py` — `BaseStatement` (has `permission_set`, `required_group_membership`, etc.) → `Statement` (account access). `GroupStatement` is separate (does not inherit `BaseStatement`, lacks `permission_set` and `required_group_membership`). Eligibility filtering (`get_eligible_statements_for_user`) currently only applies to `Statement`, not `GroupStatement`.
- `events.py` — `RevokeEvent`/`GroupRevokeEvent` and their `Scheduled*` wrappers. Tagged union via `action` field literal types.
- `entities/` — Pydantic models for AWS resources (`Account`, `PermissionSet`, `SSOGroup`) and Slack users.

**Request Flow (Slack → Decision → Execution):**
- `main.py` — Slack bolt app. Handles account access shortcuts, modal interactions, button clicks. Registers handlers via `app.shortcut()`, `app.view()`, `app.action()`. The `handle_button_click` function falls through to `group.handle_group_button_click` on parse failure.
- `group.py` — Parallel handlers for group access shortcuts, submission, and button clicks.
- `slack_helpers.py` — View builders (`RequestForAccessView`, `RequestForGroupAccessView`), payload parsers (`ButtonClickedPayload`, `ButtonGroupClickedPayload`), message block builders. Modal uses dynamic view updates: accounts load first, then permission sets update on account selection via `dispatch_action=True`.
- `access_control.py` — Decision logic (`make_decision_on_access_request`, `make_decision_on_approve_request`) is already unified for both Statement and GroupStatement. Execution is split: `execute_decision` (account) vs `execute_decision_on_group_request` (group).

**Revocation & Scheduling:**
- `schedule.py` — `schedule_revoke_event`/`schedule_group_revoke_event` create EventBridge schedules that fire the revoker Lambda.
- `revoker.py` — Handles scheduled revocations, early revocations, inconsistency checks, extend-grant button posting. Parallel functions for account and group flows.

**SSO Operations:**
- `sso.py` — AWS SSO/Identity Store API calls. Account operations (create/delete assignment) and group operations (add/remove membership) are fundamentally different APIs. User lookup (`get_user_principal_id_by_email`) is shared.

**Attribute Sync (separate feature):**
- `attribute_syncer.py`, `attribute_mapper.py`, `sync_state.py`, `sync_config.py`, `sync_notifications.py` — Automatic user-to-group sync based on Identity Store attributes. Runs on its own Lambda/schedule.

### Key Design Patterns

- **Config uses two separate Terraform variables** (`config` and `group_config`) that map directly to `statements` and `group_statements` in the S3 JSON. Python reads these as separate lists.
- **Pydantic models use `frozen=True`** (`ConfigDict(frozen=True)` in `entities/model.py`). Extra fields are silently ignored (default Pydantic v2 behavior, no `extra="forbid"`).
- **`parse_group_statement` manually extracts keys** from the raw dict (doesn't pass the whole dict to Pydantic), so extra keys like `ResourceType` in the S3 JSON are harmlessly ignored.
- **Decision logic is unified** in `access_control.py` — same `make_decision_on_access_request` handles both `FrozenSet[Statement]` and `FrozenSet[GroupStatement]`.
- **Execution logic is deliberately split** — account and group execution have different SSO API calls, audit fields, and scheduling.
- **Tests use Hypothesis** (`src/tests/strategies.py`) for property-based testing of statement parsing alongside standard pytest.
