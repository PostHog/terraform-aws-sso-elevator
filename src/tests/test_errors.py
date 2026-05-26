"""Tests for errors.py — the shared conflict/not-found classifiers and the role-neutral
error handler text."""

# ruff: noqa: ARG002

from unittest.mock import MagicMock

import botocore.exceptions

import errors


def _client_error(code: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError(
        {"Error": {"Code": code, "Message": "boom"}},  # type: ignore[arg-type]
        "SomeOperation",
    )


class TestExceptionClassifiers:
    def test_is_conflict_exception_true_for_conflict_client_error(self):
        assert errors.is_conflict_exception(_client_error("ConflictException")) is True

    def test_is_conflict_exception_false_for_other_client_error(self):
        assert errors.is_conflict_exception(_client_error("ValidationException")) is False
        assert errors.is_conflict_exception(_client_error("ResourceNotFoundException")) is False

    def test_is_conflict_exception_false_for_non_client_error(self):
        assert errors.is_conflict_exception(ValueError("nope")) is False
        assert errors.is_conflict_exception(RuntimeError("nope")) is False

    def test_is_resource_not_found_true_for_not_found_client_error(self):
        assert errors.is_resource_not_found_exception(_client_error("ResourceNotFoundException")) is True

    def test_is_resource_not_found_false_for_other_client_error(self):
        assert errors.is_resource_not_found_exception(_client_error("ConflictException")) is False

    def test_is_resource_not_found_false_for_non_client_error(self):
        assert errors.is_resource_not_found_exception(ValueError("nope")) is False


class TestErrorHandlerText:
    """The handler tags whoever triggered the action (requester on submission, approver on
    button click). The message must NOT claim 'your request' since the tagged user may not
    have made a request — they may have just clicked Approve."""

    def test_generic_error_message_is_role_neutral(self):
        client = MagicMock()
        context = MagicMock()
        context.get.side_effect = lambda key, default=None: "U_APPROVER" if key == "user_id" else default
        cfg = MagicMock()
        cfg.slack_channel_id = "C1"
        logger = MagicMock()

        errors.error_handler(client=client, e=RuntimeError("boom"), logger=logger, context=context, cfg=cfg)

        client.chat_postMessage.assert_called_once()
        text = client.chat_postMessage.call_args.kwargs["text"]
        assert "<@U_APPROVER>" in text
        # Must NOT use the old phrasing that incorrectly attributes a request to the tagged user.
        assert "Your request for AWS permissions" not in text
        assert "your request" not in text.lower()

    def test_sso_user_not_found_keeps_dedicated_requester_message(self):
        """SSOUserNotFound is requester-specific (the requester's email wasn't in SSO),
        so the more detailed 'your request failed because your user was not found' message
        is still appropriate."""
        client = MagicMock()
        context = MagicMock()
        context.get.side_effect = lambda key, default=None: "U_REQUESTER" if key == "user_id" else default
        cfg = MagicMock()
        cfg.slack_channel_id = "C1"
        logger = MagicMock()

        errors.error_handler(client=client, e=errors.SSOUserNotFound("no user"), logger=logger, context=context, cfg=cfg)

        text = client.chat_postMessage.call_args.kwargs["text"]
        assert "<@U_REQUESTER>" in text
        assert "not found in AWS SSO" in text
