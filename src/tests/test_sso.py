from unittest.mock import MagicMock

import pytest

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
