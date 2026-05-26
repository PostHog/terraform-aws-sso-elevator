import functools
import inspect

import botocore.exceptions
from aws_lambda_powertools import Logger
from slack_bolt import BoltContext
from slack_sdk import WebClient

import analytics
import config


class ConfigurationError(Exception): ...


class AccountAssignmentError(ConfigurationError):
    def __init__(self, message: str, failure_reason: str | None = None) -> None:
        super().__init__(message)
        self.failure_reason = failure_reason


class NotFound(ConfigurationError): ...


class SSOUserNotFound(ConfigurationError): ...


logger = config.get_logger(service="errors")
cfg = config.get_config()


def is_conflict_exception(e: BaseException) -> bool:
    """True if `e` is an AWS SSO/Identity Store ConflictException — i.e., another operation on
    the same target is in progress. Treat these as benign across the codebase: the other
    operation will either succeed or surface its own failure."""
    return isinstance(e, botocore.exceptions.ClientError) and e.response.get("Error", {}).get("Code") == "ConflictException"


def is_resource_not_found_exception(e: BaseException) -> bool:
    """True if `e` is an AWS SSO/Identity Store ResourceNotFoundException — i.e., the target
    object already doesn't exist."""
    return isinstance(e, botocore.exceptions.ClientError) and e.response.get("Error", {}).get("Code") == "ResourceNotFoundException"


def error_handler(client: WebClient, e: Exception, logger: Logger, context: BoltContext, cfg: config.Config) -> None:
    logger.exception("An error occurred:", exc_info=e)
    user_id = context.get("user_id", "UNKNOWN_USER")

    analytics.capture(
        event="aws_sso_elevator_error",
        distinct_id=user_id,
        properties={
            "error_type": type(e).__name__,
            "error_message": str(e),
        },
    )

    if isinstance(e, SSOUserNotFound):
        text = (
            f"<@{user_id}> Your request for AWS permissions failed because your user was not found in AWS SSO. "
            "This often happens if you haven't yet been added to AWS, or if your AWS SSO email differs from your Slack email. "
            "Please check the SSO Elevator logs for more details."
        )
    else:
        # The tagged user is whoever triggered the action (requester on submission, approver on
        # button click), so the message stays role-neutral instead of assuming "your request".
        text = f"<@{user_id}> Something went wrong handling this action. Check the SSO Elevator logs for details."
    client.chat_postMessage(text=text, channel=cfg.slack_channel_id)


def handle_errors(fn):  # noqa: ANN001, ANN201
    # Default slack error handler (app.error) does not handle all exceptions. Or at least I did not find how to do it.
    # So I created this error handler.
    sig = inspect.signature(fn)
    params = list(sig.parameters.keys())

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            # Extract client and context from args or kwargs (Slack Bolt passes positional args)
            if "client" in kwargs:
                client = kwargs["client"]
            else:
                client_idx = params.index("client")
                client = args[client_idx]

            if "context" in kwargs:
                context = kwargs["context"]
            else:
                context_idx = params.index("context")
                context = args[context_idx]

            error_handler(client=client, e=e, logger=logger, context=context, cfg=cfg)

    return wrapper
