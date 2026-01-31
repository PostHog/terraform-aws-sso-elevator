from enum import Enum

from .model import BaseModel


class ApproverAction(Enum):
    Approve = "approve"
    Discard = "discard"
    EarlyRevoke = "early_revoke"


class User(BaseModel):
    id: str
    email: str
    real_name: str
