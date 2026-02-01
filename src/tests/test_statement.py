from statement import (
    Statement,
    get_accounts_for_user,
    get_eligible_statements_for_user,
    get_permission_sets_for_account,
    get_permission_sets_for_account_and_user,
    is_statement_eligible_for_user,
)

# ruff: noqa: ANN201, ANN001


class TestIsStatementEligibleForUser:
    def test_empty_required_group_membership_is_eligible_for_all(self):
        """Empty required_group_membership means available to all users."""
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": [],
            }
        )
        assert is_statement_eligible_for_user(statement, set()) is True
        assert is_statement_eligible_for_user(statement, {"group-1", "group-2"}) is True

    def test_user_in_required_group_is_eligible(self):
        """User who is in at least one required group is eligible."""
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["group-a", "group-b"],
            }
        )
        # User in group-a
        assert is_statement_eligible_for_user(statement, {"group-a"}) is True
        # User in group-b
        assert is_statement_eligible_for_user(statement, {"group-b"}) is True
        # User in both
        assert is_statement_eligible_for_user(statement, {"group-a", "group-b"}) is True
        # User in one required and one other
        assert is_statement_eligible_for_user(statement, {"group-a", "other-group"}) is True

    def test_user_not_in_required_group_is_not_eligible(self):
        """User who is not in any required group is not eligible."""
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["group-a", "group-b"],
            }
        )
        assert is_statement_eligible_for_user(statement, set()) is False
        assert is_statement_eligible_for_user(statement, {"other-group"}) is False
        assert is_statement_eligible_for_user(statement, {"group-c", "group-d"}) is False


class TestGetEligibleStatementsForUser:
    def test_returns_only_eligible_statements(self):
        """Should filter out statements user is not eligible for."""
        statement_open = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["ReadOnlyAccess"],
                "required_group_membership": [],
            }
        )
        statement_restricted = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["admin-group"],
            }
        )
        statements = frozenset([statement_open, statement_restricted])

        # User not in admin group - only sees open statement
        result = get_eligible_statements_for_user(statements, set())
        assert result == frozenset([statement_open])

        # User in admin group - sees both
        result = get_eligible_statements_for_user(statements, {"admin-group"})
        assert result == frozenset([statement_open, statement_restricted])

    def test_empty_statements_returns_empty(self):
        """Empty statements should return empty."""
        result = get_eligible_statements_for_user(frozenset(), {"any-group"})
        assert result == frozenset()


class TestGetAccountsForUser:
    def test_returns_accounts_from_eligible_statements(self):
        """Should return accounts only from eligible statements."""
        statement_open = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["ReadOnlyAccess"],
                "required_group_membership": [],
            }
        )
        statement_restricted = Statement.model_validate(
            {
                "resource": ["222222222222"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["admin-group"],
            }
        )
        statements = frozenset([statement_open, statement_restricted])

        # User not in admin group
        result = get_accounts_for_user(statements, set())
        assert result == {"111111111111"}

        # User in admin group
        result = get_accounts_for_user(statements, {"admin-group"})
        assert result == {"111111111111", "222222222222"}

    def test_wildcard_account_returns_wildcard(self):
        """If eligible statement has wildcard, return wildcard."""
        statement = Statement.model_validate(
            {
                "resource": ["*"],
                "permission_set": ["ReadOnlyAccess"],
                "required_group_membership": [],
            }
        )
        result = get_accounts_for_user(frozenset([statement]), set())
        assert result == {"*"}

    def test_no_eligible_statements_returns_empty(self):
        """If no eligible statements, return empty set."""
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["admin-group"],
            }
        )
        result = get_accounts_for_user(frozenset([statement]), set())
        assert result == set()


class TestGetPermissionSetsForAccountAndUser:
    def test_filters_by_both_account_and_user_eligibility(self):
        """Should filter by both account match and user group eligibility."""
        statement_open = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["ReadOnlyAccess"],
                "required_group_membership": [],
            }
        )
        statement_restricted = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["admin-group"],
            }
        )
        statement_other_account = Statement.model_validate(
            {
                "resource": ["222222222222"],
                "permission_set": ["PowerUserAccess"],
                "required_group_membership": [],
            }
        )
        statements = frozenset([statement_open, statement_restricted, statement_other_account])

        # User not in admin group, account 111111111111
        result = get_permission_sets_for_account_and_user(statements, "111111111111", set())
        assert result == {"ReadOnlyAccess"}

        # User in admin group, account 111111111111
        result = get_permission_sets_for_account_and_user(statements, "111111111111", {"admin-group"})
        assert result == {"ReadOnlyAccess", "AdministratorAccess"}

        # User not in admin group, account 222222222222
        result = get_permission_sets_for_account_and_user(statements, "222222222222", set())
        assert result == {"PowerUserAccess"}

    def test_wildcard_permission_set_returns_wildcard(self):
        """If eligible statement has wildcard permission set, return wildcard."""
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["*"],
                "required_group_membership": [],
            }
        )
        result = get_permission_sets_for_account_and_user(frozenset([statement]), "111111111111", set())
        assert result == {"*"}


class TestCacheMissScenario:
    """Tests for behavior when user_group_ids defaults to empty set (cache miss)."""

    def test_empty_user_group_ids_only_returns_unrestricted_permission_sets(self):
        """When user_group_ids is empty (cache miss), only unrestricted statements should match.

        This simulates the scenario where Lambda container is recycled between
        load_select_options_for_account_access_request (which caches groups) and
        handle_account_selection (which uses cache), defaulting to empty set.
        """
        statement_restricted = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["admin-group"],
            }
        )
        statement_unrestricted = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["ReadOnlyAccess"],
                "required_group_membership": [],
            }
        )
        statements = frozenset([statement_restricted, statement_unrestricted])

        # Empty set (cache miss) should only return unrestricted permission set
        result = get_permission_sets_for_account_and_user(statements, "111111111111", set())
        assert result == {"ReadOnlyAccess"}

    def test_empty_user_group_ids_returns_empty_when_all_restricted(self):
        """When all statements require group membership, empty user_group_ids returns empty."""
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["AdministratorAccess"],
                "required_group_membership": ["admin-group"],
            }
        )
        result = get_permission_sets_for_account_and_user(frozenset([statement]), "111111111111", set())
        assert result == set()


class TestGetPermissionSetsForAccount:
    """Tests for existing get_permission_sets_for_account function."""

    def test_returns_permission_sets_for_matching_account(self):
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["ReadOnlyAccess", "ViewOnlyAccess"],
            }
        )
        result = get_permission_sets_for_account(frozenset([statement]), "111111111111")
        assert result == {"ReadOnlyAccess", "ViewOnlyAccess"}

    def test_returns_empty_for_non_matching_account(self):
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["ReadOnlyAccess"],
            }
        )
        result = get_permission_sets_for_account(frozenset([statement]), "222222222222")
        assert result == set()

    def test_wildcard_resource_matches_any_account(self):
        statement = Statement.model_validate(
            {
                "resource": ["*"],
                "permission_set": ["ReadOnlyAccess"],
            }
        )
        result = get_permission_sets_for_account(frozenset([statement]), "any-account")
        assert result == {"ReadOnlyAccess"}

    def test_wildcard_permission_set_returns_wildcard(self):
        statement = Statement.model_validate(
            {
                "resource": ["111111111111"],
                "permission_set": ["*"],
            }
        )
        result = get_permission_sets_for_account(frozenset([statement]), "111111111111")
        assert result == {"*"}
