from enum import Enum

from .model import BaseModel


class ApproverAction(Enum):
    Approve = "approve"
    Deny = "deny"
    EarlyRevoke = "early_revoke"
    ExtendGrant = "extend_grant"


class User(BaseModel):
    id: str
    email: str
    real_name: str
