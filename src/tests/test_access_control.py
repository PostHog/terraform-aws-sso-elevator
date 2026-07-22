import datetime
from unittest.mock import MagicMock, patch

import botocore.exceptions
import pytest

import access_control
import entities
from access_control import (
    AccessRequestDecision,
    ApproveRequestDecision,
    DecisionReason,
    execute_decision,
    make_decision_on_access_request,
    make_decision_on_approve_request,
)
from statement import Statement

# ruff: noqa: ANN201, ANN001


@pytest.fixture
def execute_decision_info():
    return {
        "permission_set_name": "1233321",
        "account_id": "1233321",
        "permission_duration": datetime.timedelta(days=1),
        "approver": entities.slack.User(email="email@email", id="123", real_name="123"),
        "requester": entities.slack.User(email="email@email", id="123", real_name="123"),
        "reason": "",
    }


@pytest.fixture(
    params=[
        {
            "description": """If we have two statements, and one of them explicitly denies (with self_approval = False)
            while the other allows (with self_approval = True), then we should deny self_approval.""",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": [
                                    "CTO@test.com",
                                ],
                                "allow_self_approval": True,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": [
                                    "Approver2@test.com",
                                    "CTO@test.com",
                                ],
                                "allow_self_approval": False,
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "CTO@test.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.RequiresApproval,
                approvers=frozenset(["Approver2@test.com"]),
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": [
                                    "CTO@test.com",
                                ],
                                "allow_self_approval": True,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["Approver2@test.com", "CTO@test.com"],
                                "allow_self_approval": False,
                            }
                        ),
                    ]
                ),
            ),
        },
        {
            "description": "Test where allow_self_approval is set to None",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": None,
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "CTO@test.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoApprovers,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": None,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "Test where allow_self_approval has mixed values of None and False",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": None,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": False,
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "CTO@test.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoApprovers,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": False,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": None,
                            }
                        ),
                    ]
                ),
            ),
        },
        {
            "description": "Test where allow_self_approval has mixed values of None and True",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": None,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": True,
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "CTO@test.com",
            },
            "out": AccessRequestDecision(
                grant=True,
                reason=DecisionReason.SelfApproval,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["CTO@test.com"],
                                "allow_self_approval": True,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "Test where approval_is_not_required is set to None",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": [
                                    "Approver2@test.com",
                                    "CTO@test.com",
                                ],
                                "approval_is_not_required": None,
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "Approver2@test.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.RequiresApproval,
                approvers=frozenset(["CTO@test.com"]),
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": [
                                    "Approver2@test.com",
                                    "CTO@test.com",
                                ],
                                "approval_is_not_required": None,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "Test where approval_is_not_required has mixed values of None and False",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approval_is_not_required": None,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approval_is_not_required": False,
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "anybody@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoApprovers,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approval_is_not_required": False,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approval_is_not_required": None,
                            }
                        ),
                    ]
                ),
            ),
        },
        {
            "description": "Test where approval_is_not_required has mixed values of None and True",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approval_is_not_required": None,
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approval_is_not_required": True,
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "anybody@example.com",
            },
            "out": AccessRequestDecision(
                grant=True,
                reason=DecisionReason.ApprovalNotRequired,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approval_is_not_required": True,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "test allow_self_approval and approval_is_not_required None values",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["anybody@example.com"],
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "anybody@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoApprovers,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["anybody@example.com"],
                                "approval_is_not_required": None,
                                "allow_self_approval": None,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "Grant access if approval is not required",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approval_is_not_required": True,
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "anybody@example.com",
            },
            "out": AccessRequestDecision(
                grant=True,
                reason=DecisionReason.ApprovalNotRequired,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approval_is_not_required": True,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "Request requires approval if requester is not an approver",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["one@example.com"],
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "second@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.RequiresApproval,
                approvers=frozenset(["one@example.com"]),
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["one@example.com"],
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "requester is not an approver and self approval is allowed - RequiresApproval",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["one@example.com"],
                                "allow_self_approval": True,
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "second@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.RequiresApproval,
                approvers=frozenset(["one@example.com"]),
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["one@example.com"],
                                "allow_self_approval": True,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "requester is an approver, but self approval is not allowed, and there is other approver - RequiresApproval",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": [
                                    "approver@example.com",
                                    "approver2@example.com",
                                ],
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "approver@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.RequiresApproval,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": [
                                    "approver@example.com",
                                    "approver2@example.com",
                                ],
                            }
                        )
                    ]
                ),
                approvers=frozenset({"approver2@example.com"}),
            ),
        },
        {
            "description": "self approval is allowed and requester is approver -SelfApproval",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["approver@example.com"],
                                "allow_self_approval": True,
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "approver@example.com",
            },
            "out": AccessRequestDecision(
                grant=True,
                reason=DecisionReason.SelfApproval,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "approvers": ["approver@example.com"],
                                "allow_self_approval": True,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "no approvers - NoApprovers",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "example@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoApprovers,
                based_on_statements=frozenset(
                    frozenset(
                        [
                            Statement.model_validate(
                                {
                                    "resource_type": "Account",
                                    "resource": ["*"],
                                    "permission_set": ["*"],
                                }
                            )
                        ]
                    )
                ),
            ),
        },
        {
            "description": "requester is an approver, but self approval is not allowed - NoApprovers",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "approver@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoApprovers,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "no approvers but self approval is allowed - NoApprovers",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["*"],
                                "permission_set": ["*"],
                                "allow_self_approval": True,
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "example@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoApprovers,
                based_on_statements=frozenset(
                    frozenset(
                        [
                            Statement.model_validate(
                                {
                                    "resource_type": "Account",
                                    "resource": ["*"],
                                    "permission_set": ["*"],
                                    "allow_self_approval": True,
                                }
                            )
                        ]
                    )
                ),
            ),
        },
        {
            "description": "statement is not affected by the access request - NoStatements",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["ReadOnlyAccess"],
                                "approvers": ["approver@example.com"],
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "requester@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.NoStatements,
                based_on_statements=frozenset([]),
            ),
        },
        {
            "description": "multiple statements affecting the access request, some require approval and some don't",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approval_is_not_required": True,
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "approver@example.com",
            },
            "out": AccessRequestDecision(
                grant=True,
                reason=DecisionReason.ApprovalNotRequired,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approval_is_not_required": True,
                            }
                        ),
                    ]
                ),
            ),
        },
        {
            "description": "multiple statements affecting the access request, with different sets of approvers.",
            "in": {
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver1@example.com"],
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver2@example.com"],
                            }
                        ),
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "requester@example.com",
            },
            "out": AccessRequestDecision(
                grant=False,
                reason=DecisionReason.RequiresApproval,
                approvers=frozenset(["approver1@example.com", "approver2@example.com"]),
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver1@example.com"],
                            }
                        ),
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver2@example.com"],
                            }
                        ),
                    ]
                ),
            ),
        },
    ],
    ids=lambda t: t["description"],
)
def test_cases_for_access_request_decision(request):
    return request.param


@pytest.fixture(
    params=[
        {
            "description": "approver is approver",
            "in": {
                "action": entities.ApproverAction.Approve,
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "requester@example.com",
                "approver_email": "approver@example.com",
            },
            "out": ApproveRequestDecision(
                grant=True,
                permit=True,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "approver is approver but self approval is not allowed",
            "in": {
                "action": entities.ApproverAction.Approve,
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                                "allow_self_approval": False,
                            }
                        )
                    ]
                ),
                "account_id": "111111111111",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "approver@example.com",
                "approver_email": "approver@example.com",
            },
            "out": ApproveRequestDecision(
                grant=False,
                permit=False,
                based_on_statements=frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                                "allow_self_approval": False,
                            }
                        )
                    ]
                ),
            ),
        },
        {
            "description": "approver is not an approver",
            "in": {
                "action": entities.ApproverAction.Approve,
                "statements": frozenset(
                    [
                        Statement.model_validate(
                            {
                                "resource_type": "Account",
                                "resource": ["111111111111"],
                                "permission_set": ["AdministratorAccess"],
                                "approvers": ["approver@example.com"],
                            }
                        )
                    ]
                ),
                "account_id": "222222222222",
                "permission_set_name": "AdministratorAccess",
                "requester_email": "requester@example.com",
                "approver_email": "notapprover@example.com",
            },
            "out": ApproveRequestDecision(
                grant=False,
                permit=False,
                based_on_statements=frozenset(),
            ),
        },
    ],
    ids=lambda t: t["description"],
)
def test_cases_for_approve_request_decision(request):
    return request.param


def test_make_decision_on_access_request(test_cases_for_access_request_decision):
    actual = make_decision_on_access_request(**test_cases_for_access_request_decision["in"])
    expected = test_cases_for_access_request_decision["out"]

    # Compare grant and reason attributes directly
    assert actual.grant == expected.grant
    assert actual.reason == expected.reason

    # Compare based_on_statements attributes as sets to ignore order
    assert set(actual.based_on_statements) == set(expected.based_on_statements)

    # Compare approvers attributes directly (assuming it is not a set/frozenset)
    assert actual.approvers == expected.approvers


def test_make_decision_on_approve_request(test_cases_for_approve_request_decision):
    assert (
        make_decision_on_approve_request(**test_cases_for_approve_request_decision["in"]) == test_cases_for_approve_request_decision["out"]
    )


def test_execute_access_request_decision(
    test_cases_for_access_request_decision,
    execute_decision_info,
):
    if test_cases_for_access_request_decision["out"].grant is not True:
        result = execute_decision(decision=test_cases_for_access_request_decision["out"], **execute_decision_info)
        assert result.granted is False


def test_execute_approve_request_decision(
    test_cases_for_approve_request_decision,
    execute_decision_info,
):
    if test_cases_for_approve_request_decision["out"].grant is not True:
        result = execute_decision(decision=test_cases_for_approve_request_decision["out"], **execute_decision_info)
        assert result.granted is False


def test_make_and_excute_access_request_decision(
    test_cases_for_access_request_decision,
    execute_decision_info,
):
    decision = make_decision_on_access_request(**test_cases_for_access_request_decision["in"])
    if decision.grant is not True:
        result = execute_decision(decision=decision, **execute_decision_info)
        assert result.granted is False


def test_make_and_excute_approve_request_decision(
    test_cases_for_approve_request_decision,
    execute_decision_info,
):
    decision = make_decision_on_approve_request(**test_cases_for_approve_request_decision["in"])
    if decision.grant is not True:
        result = execute_decision(decision=decision, **execute_decision_info)
        assert result.granted is False


# Tests for group-based access filtering
class TestGroupBasedAccessFiltering:
    """Tests for required_group_membership filtering in access decisions."""

    def test_user_eligible_for_statement_gets_normal_decision(self):
        """User in required group should get normal decision flow."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["approver@example.com"],
                        "required_group_membership": ["admin-group"],
                    }
                )
            ]
        )
        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            user_group_ids={"admin-group"},
        )
        assert decision.reason == DecisionReason.RequiresApproval
        assert decision.approvers == frozenset(["approver@example.com"])

    def test_user_not_eligible_for_any_statement_gets_no_statements(self):
        """User not in any required group should get NoStatements."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["approver@example.com"],
                        "required_group_membership": ["admin-group"],
                    }
                )
            ]
        )
        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            user_group_ids={"other-group"},
        )
        assert decision.reason == DecisionReason.NoStatements
        assert decision.grant is False

    def test_empty_required_group_membership_is_backwards_compatible(self):
        """Statement with empty required_group_membership should work for all users."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["approver@example.com"],
                        "required_group_membership": [],
                    }
                )
            ]
        )
        # Works with no groups
        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            user_group_ids=set(),
        )
        assert decision.reason == DecisionReason.RequiresApproval

        # Works with any groups
        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            user_group_ids={"random-group"},
        )
        assert decision.reason == DecisionReason.RequiresApproval

    def test_none_user_group_ids_skips_filtering(self):
        """When user_group_ids is None, no filtering should be applied."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["approver@example.com"],
                        "required_group_membership": ["admin-group"],
                    }
                )
            ]
        )
        # Without user_group_ids, statement is included (backwards compatible)
        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            user_group_ids=None,
        )
        assert decision.reason == DecisionReason.RequiresApproval

    def test_multiple_statements_only_eligible_ones_considered(self):
        """When multiple statements exist, only eligible ones should be considered."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["admin-approver@example.com"],
                        "required_group_membership": ["admin-group"],
                    }
                ),
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["regular-approver@example.com"],
                        "required_group_membership": [],  # Available to all
                    }
                ),
            ]
        )

        # User not in admin group should only see regular-approver
        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            user_group_ids={"other-group"},
        )
        assert decision.reason == DecisionReason.RequiresApproval
        assert decision.approvers == frozenset(["regular-approver@example.com"])

        # User in admin group should see both approvers
        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            user_group_ids={"admin-group"},
        )
        assert decision.reason == DecisionReason.RequiresApproval
        assert decision.approvers == frozenset(["admin-approver@example.com", "regular-approver@example.com"])


class TestApproverGroupsSelfApproval:
    """Tests for self-approval via approver group membership."""

    def test_user_in_approver_group_can_self_approve(self):
        """User in approver group can self-approve when allow_self_approval is True."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": [],  # No individual approvers
                        "approver_groups": frozenset(["approver-group-1"]),
                        "allow_self_approval": True,
                    }
                )
            ]
        )

        # Resolver returns requester's Slack ID as member of the approver group
        def mock_resolver(group_ids):
            if "approver-group-1" in group_ids:
                return {"U_REQUESTER"}
            return set()

        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            requester_slack_id="U_REQUESTER",
            approver_group_resolver=mock_resolver,
        )

        assert decision.grant is True
        assert decision.reason == DecisionReason.SelfApproval

    def test_user_in_approver_group_blocked_when_self_approval_denied(self):
        """User in approver group is blocked when allow_self_approval is False."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["other-approver@example.com"],
                        "approver_groups": frozenset(["approver-group-1"]),
                        "allow_self_approval": False,
                    }
                )
            ]
        )

        def mock_resolver(group_ids):
            if "approver-group-1" in group_ids:
                return {"U_REQUESTER"}
            return set()

        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            requester_slack_id="U_REQUESTER",
            approver_group_resolver=mock_resolver,
        )

        assert decision.grant is False
        assert decision.reason == DecisionReason.RequiresApproval
        # Requester should not be in the approvers list
        assert "requester@example.com" not in decision.approvers

    def test_user_not_in_approver_group_cannot_self_approve(self):
        """User not in any approver group cannot self-approve."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["actual-approver@example.com"],
                        "approver_groups": frozenset(["approver-group-1"]),
                        "allow_self_approval": True,
                    }
                )
            ]
        )

        # Resolver returns different user ID
        def mock_resolver(group_ids):
            if "approver-group-1" in group_ids:
                return {"U_OTHER_USER"}
            return set()

        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            requester_slack_id="U_REQUESTER",
            approver_group_resolver=mock_resolver,
        )

        assert decision.grant is False
        assert decision.reason == DecisionReason.RequiresApproval

    def test_explicit_deny_self_approval_blocks_group_member(self):
        """Explicit deny in one statement blocks self-approval even if another allows it."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["*"],
                        "permission_set": ["*"],
                        "approvers": [],
                        "approver_groups": frozenset(["approver-group-1"]),
                        "allow_self_approval": True,
                    }
                ),
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["other-approver@example.com"],
                        "approver_groups": frozenset(["approver-group-1"]),
                        "allow_self_approval": False,
                    }
                ),
            ]
        )

        def mock_resolver(group_ids):
            if "approver-group-1" in group_ids:
                return {"U_REQUESTER"}
            return set()

        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
            requester_slack_id="U_REQUESTER",
            approver_group_resolver=mock_resolver,
        )

        assert decision.grant is False
        assert decision.reason == DecisionReason.RequiresApproval

    def test_approver_groups_in_decision_output(self):
        """Approver groups should be included in decision output."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": ["individual@example.com"],
                        "approver_groups": frozenset(["group-1", "group-2"]),
                    }
                )
            ]
        )

        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
        )

        assert decision.grant is False
        assert decision.reason == DecisionReason.RequiresApproval
        assert decision.approver_groups == frozenset(["group-1", "group-2"])

    def test_only_approver_groups_no_individual_approvers(self):
        """Statement with only approver groups (no individual approvers) works."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": [],
                        "approver_groups": frozenset(["approver-group"]),
                    }
                )
            ]
        )

        decision = make_decision_on_access_request(
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            requester_email="requester@example.com",
        )

        assert decision.grant is False
        assert decision.reason == DecisionReason.RequiresApproval
        assert decision.approvers == frozenset()
        assert decision.approver_groups == frozenset(["approver-group"])


class TestApproveRequestWithGroups:
    """Tests for make_decision_on_approve_request with approver groups."""

    def test_group_member_can_approve(self):
        """User in approver group can approve requests."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": [],
                        "approver_groups": frozenset(["approver-group"]),
                    }
                )
            ]
        )

        def mock_resolver(group_ids):
            if "approver-group" in group_ids:
                return {"U_APPROVER"}
            return set()

        decision = make_decision_on_approve_request(
            action=entities.ApproverAction.Approve,
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            approver_email="approver@example.com",
            requester_email="requester@example.com",
            approver_slack_id="U_APPROVER",
            approver_group_resolver=mock_resolver,
        )

        assert decision.grant is True
        assert decision.permit is True

    def test_non_group_member_cannot_approve(self):
        """User not in approver group cannot approve."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": [],
                        "approver_groups": frozenset(["approver-group"]),
                    }
                )
            ]
        )

        def mock_resolver(group_ids):
            if "approver-group" in group_ids:
                return {"U_OTHER_USER"}  # Not the approver
            return set()

        decision = make_decision_on_approve_request(
            action=entities.ApproverAction.Approve,
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            approver_email="not-in-group@example.com",
            requester_email="requester@example.com",
            approver_slack_id="U_APPROVER",
            approver_group_resolver=mock_resolver,
        )

        assert decision.grant is False
        assert decision.permit is False

    def test_per_statement_group_resolution(self):
        """Approver groups are resolved per-statement to prevent cross-statement bypass."""
        statements = frozenset(
            [
                Statement.model_validate(
                    {
                        "resource_type": "Account",
                        "resource": ["111111111111"],
                        "permission_set": ["AdministratorAccess"],
                        "approvers": [],
                        "approver_groups": frozenset(["group-for-admin-access"]),
                    }
                ),
            ]
        )

        # Track which groups are resolved
        resolved_groups = []

        def mock_resolver(group_ids):
            resolved_groups.append(set(group_ids))
            if "group-for-admin-access" in group_ids:
                return {"U_APPROVER"}
            return set()

        decision = make_decision_on_approve_request(
            action=entities.ApproverAction.Approve,
            statements=statements,
            account_id="111111111111",
            permission_set_name="AdministratorAccess",
            approver_email="approver@example.com",
            requester_email="requester@example.com",
            approver_slack_id="U_APPROVER",
            approver_group_resolver=mock_resolver,
        )

        assert decision.permit is True
        # Resolver should have been called with only the statement's group
        assert {"group-for-admin-access"} in [set(g) for g in resolved_groups]


class TestRollbackOnScheduleFailure:
    """When schedule creation fails after the SSO grant succeeded, access_control must
    best-effort revoke the grant and alert the channel so an admin is aware."""

    def _granted_decision(self):
        return AccessRequestDecision(
            grant=True,
            reason=DecisionReason.ApprovalNotRequired,
            based_on_statements=frozenset(
                [
                    Statement.model_validate(
                        {
                            "resource_type": "Account",
                            "resource": ["*"],
                            "permission_set": ["*"],
                            "approvers": ["CTO@test.com"],
                            "allow_self_approval": True,
                        }
                    )
                ]
            ),
        )

    def test_account_grant_rolls_back_and_alerts_on_schedule_failure(self):
        from unittest.mock import MagicMock, patch

        import access_control

        real_user_account_assignment = access_control.sso.UserAccountAssignment
        decision = self._granted_decision()
        info = {
            "permission_set_name": "AdminAccess",
            "account_id": "111111111111",
            "permission_duration": datetime.timedelta(hours=1),
            "approver": entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
            "requester": entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            "reason": "testing",
        }

        permission_set = MagicMock(arn="arn:aws:sso:::permissionSet/ssoins-x/ps-y", name="AdminAccess")
        boom = RuntimeError("schedule creation exploded")

        with (
            patch.object(access_control, "sso") as mock_sso,
            patch.object(access_control, "schedule") as mock_schedule,
            patch.object(access_control, "organizations") as mock_orgs,
            patch.object(access_control, "s3"),
            patch.object(access_control, "event_publisher"),
            patch.object(access_control, "slack_client") as mock_slack,
        ):
            mock_sso.get_identity_store_id.return_value = "d-123"
            mock_sso.get_permission_set.return_value = permission_set
            mock_sso.get_user_principal_id_by_email.return_value = ("user-principal-id", False)
            mock_sso.create_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
            mock_sso.UserAccountAssignment = real_user_account_assignment
            mock_orgs.describe_account.return_value = MagicMock(name="prod")
            mock_schedule.schedule_revoke_event.side_effect = boom

            with pytest.raises(RuntimeError, match="schedule creation exploded"):
                access_control.execute_decision(decision=decision, **info)

            mock_sso.delete_account_assignment_and_wait_for_result.assert_called_once()
            mock_slack.chat_postMessage.assert_called_once()
            posted = mock_slack.chat_postMessage.call_args
            assert "failed to schedule auto-revoke" in posted.kwargs["text"]
            assert "rolled back" in posted.kwargs["text"]
            assert "<@U_REQ>" in posted.kwargs["text"]

    def test_account_cleanup_message_names_console_path_and_ids(self):
        """When rollback fails, the alert names the exact Identity Center console path + IDs."""
        from unittest.mock import MagicMock, patch

        import access_control

        real_user_account_assignment = access_control.sso.UserAccountAssignment
        decision = self._granted_decision()
        info = {
            "permission_set_name": "AdminAccess",
            "account_id": "111111111111",
            "permission_duration": datetime.timedelta(hours=1),
            "approver": entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
            "requester": entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            "reason": "testing",
        }
        permission_set = MagicMock(arn="arn:aws:sso:::permissionSet/ssoins-x/ps-y", name="AdminAccess")

        with (
            patch.object(access_control, "sso") as mock_sso,
            patch.object(access_control, "schedule") as mock_schedule,
            patch.object(access_control, "organizations") as mock_orgs,
            patch.object(access_control, "s3"),
            patch.object(access_control, "event_publisher"),
            patch.object(access_control, "slack_client") as mock_slack,
        ):
            mock_sso.get_identity_store_id.return_value = "d-123"
            mock_sso.get_permission_set.return_value = permission_set
            mock_sso.get_user_principal_id_by_email.return_value = ("user-abc-123", False)
            mock_sso.create_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
            mock_sso.UserAccountAssignment = real_user_account_assignment
            mock_orgs.describe_account.return_value = MagicMock(name="prod")
            mock_schedule.schedule_revoke_event.side_effect = RuntimeError("boom")
            mock_sso.delete_account_assignment_and_wait_for_result.side_effect = RuntimeError("rollback failed")

            with pytest.raises(RuntimeError):
                access_control.execute_decision(decision=decision, **info)

            text = mock_slack.chat_postMessage.call_args.kwargs["text"]
            assert "AWS IAM Identity Center" in text
            assert "AWS accounts" in text
            assert "111111111111" in text
            assert "user-abc-123" in text
            assert "AdminAccess" in text
            assert "remove assignment" in text

    def test_account_alert_prepends_configured_slack_group_ping(self):
        """If cfg.cleanup_alert_slack_group is set, the alert is prefixed with that handle."""
        from unittest.mock import MagicMock, patch

        import access_control

        real_user_account_assignment = access_control.sso.UserAccountAssignment
        decision = self._granted_decision()
        info = {
            "permission_set_name": "AdminAccess",
            "account_id": "111111111111",
            "permission_duration": datetime.timedelta(hours=1),
            "approver": entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
            "requester": entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            "reason": "testing",
        }
        permission_set = MagicMock(arn="arn:aws:sso:::permissionSet/ssoins-x/ps-y", name="AdminAccess")

        # cfg is a frozen pydantic BaseSettings, so we swap it with a copy containing the override.
        cfg_with_ping = access_control.cfg.model_copy(update={"cleanup_alert_slack_group": "S12345"})
        with (
            patch.object(access_control, "cfg", cfg_with_ping),
            patch.object(access_control, "sso") as mock_sso,
            patch.object(access_control, "schedule") as mock_schedule,
            patch.object(access_control, "organizations") as mock_orgs,
            patch.object(access_control, "s3"),
            patch.object(access_control, "event_publisher"),
            patch.object(access_control, "slack_client") as mock_slack,
        ):
            mock_sso.get_identity_store_id.return_value = "d-123"
            mock_sso.get_permission_set.return_value = permission_set
            mock_sso.get_user_principal_id_by_email.return_value = ("user-abc-123", False)
            mock_sso.create_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
            mock_sso.UserAccountAssignment = real_user_account_assignment
            mock_orgs.describe_account.return_value = MagicMock(name="prod")
            mock_schedule.schedule_revoke_event.side_effect = RuntimeError("boom")

            with pytest.raises(RuntimeError):
                access_control.execute_decision(decision=decision, **info)

            text = mock_slack.chat_postMessage.call_args.kwargs["text"]
            assert text.startswith("<!subteam^S12345> ")

    def test_account_alert_notes_manual_cleanup_when_rollback_also_fails(self):
        from unittest.mock import MagicMock, patch

        import access_control

        real_user_account_assignment = access_control.sso.UserAccountAssignment
        decision = self._granted_decision()
        info = {
            "permission_set_name": "AdminAccess",
            "account_id": "111111111111",
            "permission_duration": datetime.timedelta(hours=1),
            "approver": entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
            "requester": entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            "reason": "testing",
        }
        permission_set = MagicMock(arn="arn:aws:sso:::permissionSet/ssoins-x/ps-y", name="AdminAccess")

        with (
            patch.object(access_control, "sso") as mock_sso,
            patch.object(access_control, "schedule") as mock_schedule,
            patch.object(access_control, "organizations") as mock_orgs,
            patch.object(access_control, "s3"),
            patch.object(access_control, "event_publisher"),
            patch.object(access_control, "slack_client") as mock_slack,
        ):
            mock_sso.get_identity_store_id.return_value = "d-123"
            mock_sso.get_permission_set.return_value = permission_set
            mock_sso.get_user_principal_id_by_email.return_value = ("user-principal-id", False)
            mock_sso.create_account_assignment_and_wait_for_result.return_value = MagicMock(request_id="req-1")
            mock_sso.UserAccountAssignment = real_user_account_assignment
            mock_orgs.describe_account.return_value = MagicMock(name="prod")
            mock_schedule.schedule_revoke_event.side_effect = RuntimeError("boom")
            mock_sso.delete_account_assignment_and_wait_for_result.side_effect = RuntimeError("rollback failed")

            with pytest.raises(RuntimeError, match="boom"):
                access_control.execute_decision(decision=decision, **info)

            posted = mock_slack.chat_postMessage.call_args
            assert "MANUAL CLEANUP REQUIRED" in posted.kwargs["text"]


class TestGroupRollbackOnScheduleFailure:
    def test_group_grant_rolls_back_and_alerts_on_schedule_failure(self):
        from unittest.mock import patch

        import access_control

        real_group_assignment = access_control.sso.GroupAssignment
        decision = AccessRequestDecision(
            grant=True,
            reason=DecisionReason.ApprovalNotRequired,
            based_on_statements=frozenset(),
        )
        group = entities.aws.SSOGroup(id="g-1", name="Admins", description=None, identity_store_id="d-123")
        info = {
            "group": group,
            "permission_duration": datetime.timedelta(hours=1),
            "approver": entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
            "requester": entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            "reason": "testing",
            "identity_store_id": "d-123",
        }

        with (
            patch.object(access_control, "sso") as mock_sso,
            patch.object(access_control, "schedule") as mock_schedule,
            patch.object(access_control, "s3"),
            patch.object(access_control, "slack_client") as mock_slack,
        ):
            mock_sso.get_user_principal_id_by_email.return_value = ("user-principal-id", False)
            mock_sso.is_user_in_group.return_value = None
            mock_sso.add_user_to_a_group.return_value = {"MembershipId": "m-1"}
            mock_sso.GroupAssignment = real_group_assignment
            mock_schedule.schedule_group_revoke_event.side_effect = RuntimeError("boom")

            with pytest.raises(RuntimeError, match="boom"):
                access_control.execute_decision_on_group_request(decision=decision, **info)

            mock_sso.remove_user_from_group.assert_called_once_with("d-123", "m-1", access_control.identitystore_client)
            mock_slack.chat_postMessage.assert_called_once()
            posted = mock_slack.chat_postMessage.call_args
            assert "failed to schedule auto-revoke" in posted.kwargs["text"]
            assert "Admins" in posted.kwargs["text"]
            assert "rolled back" in posted.kwargs["text"]

    def test_group_cleanup_message_names_console_path_and_ids_on_rollback_failure(self):
        from unittest.mock import patch

        import access_control

        real_group_assignment = access_control.sso.GroupAssignment
        decision = AccessRequestDecision(
            grant=True,
            reason=DecisionReason.ApprovalNotRequired,
            based_on_statements=frozenset(),
        )
        group = entities.aws.SSOGroup(id="g-1", name="Admins", description=None, identity_store_id="d-123")
        info = {
            "group": group,
            "permission_duration": datetime.timedelta(hours=1),
            "approver": entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
            "requester": entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            "reason": "testing",
            "identity_store_id": "d-123",
        }

        with (
            patch.object(access_control, "sso") as mock_sso,
            patch.object(access_control, "schedule") as mock_schedule,
            patch.object(access_control, "s3"),
            patch.object(access_control, "slack_client") as mock_slack,
        ):
            mock_sso.get_user_principal_id_by_email.return_value = ("user-abc-123", False)
            mock_sso.is_user_in_group.return_value = None
            mock_sso.add_user_to_a_group.return_value = {"MembershipId": "m-1"}
            mock_sso.GroupAssignment = real_group_assignment
            mock_schedule.schedule_group_revoke_event.side_effect = RuntimeError("boom")
            mock_sso.remove_user_from_group.side_effect = RuntimeError("rollback failed")

            with pytest.raises(RuntimeError):
                access_control.execute_decision_on_group_request(decision=decision, **info)

            text = mock_slack.chat_postMessage.call_args.kwargs["text"]
            assert "MANUAL CLEANUP REQUIRED" in text
            assert "AWS IAM Identity Center" in text
            assert "Groups" in text
            assert "Admins" in text
            assert "user-abc-123" in text
            assert "remove principal" in text


# ruff: noqa: ARG002


def _conflict_exception() -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": "ConflictException", "Message": "There is a conflicting operation in process."}},  # type: ignore[arg-type]
        "CreateAccountAssignment",
    )


class TestConcurrentOperationHandling:
    """When two approvers click Approve simultaneously, AWS SSO accepts one and rejects
    the other with ConflictException. The loser should silently skip its follow-up so
    only the winner's success message reaches Slack — no scary 'unexpected error'."""

    def test_account_grant_returns_concurrent_flag_on_conflict_exception(self, execute_decision_info):
        decision = ApproveRequestDecision(grant=True, permit=True, based_on_statements=frozenset())
        with (
            patch("access_control.sso.get_permission_set", return_value=MagicMock(arn="arn:ps")),
            patch("access_control.sso.get_user_principal_id_by_email", return_value=("u-1", False)),
            patch("access_control.sso.get_identity_store_id", return_value="d-1"),
            patch(
                "access_control.sso.create_account_assignment_and_wait_for_result",
                side_effect=_conflict_exception(),
            ),
            patch("access_control.schedule.schedule_revoke_event") as mock_schedule,
            patch("access_control.s3.log_operation") as mock_audit,
            patch("access_control.event_publisher.publish_access_event") as mock_event,
        ):
            result = execute_decision(decision=decision, **execute_decision_info)

        assert result.granted is False
        assert result.concurrent_operation is True
        # Side effects MUST be skipped — the winning invocation owns them.
        mock_schedule.assert_not_called()
        mock_audit.assert_not_called()
        mock_event.assert_not_called()

    def test_account_grant_propagates_non_conflict_client_errors(self, execute_decision_info):
        decision = ApproveRequestDecision(grant=True, permit=True, based_on_statements=frozenset())
        other_error = botocore.exceptions.ClientError(
            {"Error": {"Code": "ValidationException", "Message": "bad"}},  # type: ignore[arg-type]
            "CreateAccountAssignment",
        )
        with (
            patch("access_control.sso.get_permission_set", return_value=MagicMock(arn="arn:ps")),
            patch("access_control.sso.get_user_principal_id_by_email", return_value=("u-1", False)),
            patch("access_control.sso.get_identity_store_id", return_value="d-1"),
            patch("access_control.sso.create_account_assignment_and_wait_for_result", side_effect=other_error),
            pytest.raises(botocore.exceptions.ClientError),
        ):
            execute_decision(decision=decision, **execute_decision_info)

    def test_group_grant_returns_concurrent_flag_on_conflict_exception(self):
        decision = AccessRequestDecision(
            grant=True,
            reason=DecisionReason.ApprovalNotRequired,
            based_on_statements=frozenset(),
        )
        group = entities.aws.SSOGroup(id="g-1", name="Admins", description=None, identity_store_id="d-123")
        info = {
            "group": group,
            "permission_duration": datetime.timedelta(hours=1),
            "approver": entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
            "requester": entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            "reason": "",
            "identity_store_id": "d-123",
            "thread_ts": "t1",
        }
        with (
            patch("access_control.sso.get_user_principal_id_by_email", return_value=("u-1", False)),
            patch("access_control.sso.is_user_in_group", return_value=None),
            patch("access_control.sso.add_user_to_a_group", side_effect=_conflict_exception()),
            patch("access_control.schedule.schedule_group_revoke_event") as mock_schedule,
            patch("access_control.s3.log_operation") as mock_audit,
        ):
            result = access_control.execute_decision_on_group_request(decision=decision, **info)

        assert result.granted is False
        assert result.concurrent_operation is True
        mock_schedule.assert_not_called()
        mock_audit.assert_not_called()


def test_rollback_alert_posts_to_error_channel():
    """The rollback-failure alert is an operator alert and must go to the dedicated error channel,
    not the busy request channel. Uses a distinct error channel so the assertion isn't vacuous."""
    from unittest.mock import PropertyMock

    import config

    with (
        patch.object(access_control, "sso"),
        patch.object(access_control, "slack_client") as mock_slack,
        patch.object(config.Config, "error_channel_id", new_callable=PropertyMock, return_value="C_ERR"),
    ):
        access_control._rollback_account_grant_on_schedule_failure(
            error=RuntimeError("boom"),
            account_assignment=MagicMock(),
            permission_set_name="AdminAccess",
            account_id="111111111111",
            requester=entities.slack.User(email="r@r", id="U_REQ", real_name="Requester"),
            approver=entities.slack.User(email="a@a", id="U_APP", real_name="Approver"),
        )

    assert mock_slack.chat_postMessage.call_args.kwargs["channel"] == "C_ERR"
