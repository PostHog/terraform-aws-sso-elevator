import time
from datetime import timedelta
from typing import Callable, TypeVar

import boto3
import botocore.exceptions
import jmespath as jp
from slack_bolt import Ack, App, BoltContext
from slack_bolt.adapter.aws_lambda import SlackRequestHandler
import slack_sdk.errors
from slack_sdk import WebClient
from slack_sdk.web.slack_response import SlackResponse

import access_control
import analytics
import cli_handler
import config
import entities
import event_publisher
import group
import organizations
import revoker
import schedule
import slack_helpers
import sso
import statement
import errors
from errors import AccountAssignmentError, SSOUserNotFound, handle_errors

logger = config.get_logger(service="main")

session = boto3.Session()
schedule_client = session.client("scheduler")
org_client = session.client("organizations")
sso_client = session.client("sso-admin")
identity_store_client = session.client("identitystore")
s3_client = session.client("s3")

cfg = config.get_config()
app = App(
    process_before_response=True,
    # Logger removed to avoid pickle errors with lazy listeners in Lambda
    # Slack Bolt will use its own default logger instead
)


def lambda_handler(event: str, context):  # noqa: ANN001, ANN201
    global cfg  # noqa: PLW0603
    cfg = config.check_and_refresh_config(s3_client)
    # Non-Slack ingress: the secrets CLI posts signed access requests to a dedicated route.
    # These carry no Slack signature, so they must be dispatched before the Slack Bolt handler
    # (which would reject them for a missing/invalid signature).
    if isinstance(event, dict) and event.get("routeKey") == cli_handler.ROUTE_KEY:
        return cli_handler.handle(event, context)
    slack_handler = SlackRequestHandler(app=app)
    return slack_handler.handle(event, context)


user_view_map = {}
# To update the view, it is necessary to know the view_id. It is returned when the view is opened.
# But shortcut 'request_for_access' handled by two functions. The first one opens the view and the second one updates it.
# So we need to store the view_id somewhere. We use user_id + callback_id as the key since:
# - It's available in both handler functions
# - It persists across Lambda invocations within the same container
# - It's unique per user per request type
# - A user can only have one active modal of each type at a time
#
# NOTE: This in-memory map still has limitations in AWS Lambda:
# - Lambda containers can be recycled between invocations, causing the map to be empty
# - For production use with high traffic, consider using DynamoDB or ElastiCache
# - The account-access flow no longer relies on it for the view_id (see _external_id_for);
#   the group-access flow and the per-user info cache still use it.


def _external_id_for(body: dict) -> str:
    """Deterministic view correlator shared by the open and populate invocations.

    Both invocations receive the same shortcut body with the same trigger_id, so the open
    handler can set this external_id on the view and the populate handler can target it via
    views.update(external_id=...) without any shared state surviving across Lambda containers.
    """
    return f"req-access:{body['trigger_id']}"[:255]


# Transient errors worth retrying silently while populating the modal. Terminal errors (e.g.
# SSOUserNotFound) are intentionally excluded so they surface immediately instead of looping.
_RETRYABLE_ERRORS = (
    botocore.exceptions.ClientError,
    botocore.exceptions.BotoCoreError,
    slack_sdk.errors.SlackApiError,
    ConnectionError,
    TimeoutError,
)


_RetryResult = TypeVar("_RetryResult")


def _with_retries(fn: Callable[[], _RetryResult], *, attempts: int = 5, base_delay: float = 0.5, max_delay: float = 4.0) -> _RetryResult:
    """Run fn, retrying transient failures with exponential backoff. No user-facing output."""
    for i in range(attempts):
        try:
            return fn()
        except _RETRYABLE_ERRORS as e:
            if i == attempts - 1:
                raise
            delay = min(max_delay, base_delay * (2**i))
            logger.warning(f"Retryable failure (attempt {i + 1}/{attempts}): {e}; retrying in {delay}s")
            time.sleep(delay)
    raise AssertionError("unreachable: _with_retries exhausted without returning or raising")


def build_initial_form_handler(
    view_class: slack_helpers.RequestForAccessView | slack_helpers.RequestForGroupAccessView,
) -> Callable[[WebClient, dict, Ack], SlackResponse]:
    def show_initial_form_for_request(
        client: WebClient,
        body: dict,
        ack: Ack,
    ) -> SlackResponse:
        ack()
        if view_class == slack_helpers.RequestForGroupAccessView and not cfg.group_statements:
            return client.chat_postMessage(
                channel=cfg.slack_channel_id,
                text="Group statements are not configured, please check the configuration. Or use another /command.",
            )
        if view_class == slack_helpers.RequestForAccessView and not cfg.statements:
            return client.chat_postMessage(
                channel=cfg.slack_channel_id,
                text="Statements are not configured, please check the configuration. Or use another /command.",
            )

        # Try getting SSO user to check if user exist
        try:
            sso.get_user_principal_id_by_email(
                identity_store_client=identity_store_client,
                identity_store_id=sso.get_identity_store_id(cfg, sso_client),
                email=slack_helpers.get_user(client, id=body.get("user", {}).get("id")).email,
                cfg=cfg,
            )

        except SSOUserNotFound:
            client.chat_postMessage(
                channel=cfg.slack_channel_id,
                text=f"<@{body.get('user', {}).get('id') or 'UNKNOWN_USER'}>,"
                "Your request for AWS permissions failed because your user was not found in AWS SSO. "
                "This often happens if you haven't yet been added to AWS, or if your AWS SSO email differs from your Slack email. "
                "Please check the SSO Elevator logs for more details.",
            )
            raise

        logger.info(f"Showing initial form for {view_class.__name__}")
        logger.debug("Request body", extra={"body": body})
        trigger_id = body["trigger_id"]
        user_id = body.get("user", {}).get("id")
        callback_id = view_class.CALLBACK_ID

        response = client.views_open(trigger_id=trigger_id, view=view_class.build(external_id=_external_id_for(body)))

        # Store view_id using user_id + callback_id as key for persistence across Lambda invocations.
        # The account-access flow now correlates via external_id instead, but the group-access flow
        # still reads this on its populate step.
        view_key = f"{user_id}:{callback_id}"
        user_view_map[view_key] = response.data["view"]["id"]  # type: ignore # noqa: PGH003
        logger.debug(f"Stored view_id for key: {view_key}")

        return response

    return show_initial_form_for_request


def load_select_options_for_group_access_request(client: WebClient, body: dict) -> SlackResponse:
    logger.info("Loading select options for view (groups)")
    logger.debug("Request body", extra={"body": body})
    identity_store_id = sso.get_identity_store_id(cfg, sso_client)
    groups = sso.get_groups_from_config(identity_store_id, identity_store_client, cfg)

    user_id = body.get("user", {}).get("id")
    callback_id = slack_helpers.RequestForGroupAccessView.CALLBACK_ID
    view_key = f"{user_id}:{callback_id}"

    view_id = user_view_map.get(view_key)
    if not view_id:
        logger.warning(
            f"View ID not found for key: {view_key}. "
            "This happens when Lambda container is recycled between shortcut invocations. "
            "Opening a new view as fallback."
        )
        # Fallback: open a new view with the data already loaded
        trigger_id = body["trigger_id"]
        view = slack_helpers.RequestForGroupAccessView.update_with_groups(groups=groups)
        return client.views_open(trigger_id=trigger_id, view=view)

    logger.debug(f"Updating view with view_id from key: {view_key}")
    view = slack_helpers.RequestForGroupAccessView.update_with_groups(groups=groups)
    return client.views_update(view_id=view_id, view=view)


def load_select_options_for_account_access_request(client: WebClient, body: dict) -> SlackResponse:
    logger.info("Loading select options for view (accounts only)")
    logger.debug("Request body", extra={"body": body})

    user_id = body.get("user", {}).get("id")
    callback_id = slack_helpers.RequestForAccessView.CALLBACK_ID
    view_key = f"{user_id}:{callback_id}"

    # Get user's SSO info and group memberships for filtering
    identity_store_id = sso.get_identity_store_id(cfg, sso_client)
    user_email = slack_helpers.get_user(client, id=user_id).email
    user_principal_id, _ = sso.get_user_principal_id_by_email(
        identity_store_client=identity_store_client,
        identity_store_id=identity_store_id,
        email=user_email,
        cfg=cfg,
    )
    user_group_ids = sso.get_user_group_ids(
        identity_store_client=identity_store_client,
        identity_store_id=identity_store_id,
        user_principal_id=user_principal_id,
    )

    # Cache user info for use in handle_account_selection and handle_request_for_access_submittion
    user_view_map[f"{view_key}:group_ids"] = user_group_ids
    user_view_map[f"{view_key}:user_principal_id"] = user_principal_id
    user_view_map[f"{view_key}:user_email"] = user_email

    # Filter accounts based on user's eligible statements
    eligible_account_ids = statement.get_accounts_for_user(cfg.statements, user_group_ids)

    # Correlate this populate invocation back to the modal opened in the first invocation by a
    # deterministic external_id (derived from the shared trigger_id) rather than an in-memory
    # view_id, which is lost when this invocation lands on a different warm container.
    external_id = _external_id_for(body)

    # If no eligible accounts, show empty view
    if not eligible_account_ids:
        logger.info("User has no eligible accounts", extra={"user_id": user_id})
        return _with_retries(
            lambda: client.views_update(
                external_id=external_id,
                view=slack_helpers.RequestForAccessView.build_no_eligible_accounts_view(),
            )
        )

    # Get all accounts and filter to eligible ones. Retried silently: a transient failure here is
    # the common cause of the modal getting stuck on "Loading..." with nothing submitted yet.
    all_accounts = _with_retries(
        lambda: organizations.get_accounts_from_config_with_cache(org_client=org_client, s3_client=s3_client, cfg=cfg)
    )
    if "*" in eligible_account_ids:
        accounts = all_accounts
    else:
        accounts = [a for a in all_accounts if a.id in eligible_account_ids]

    logger.debug(f"Updating view with external_id: {external_id}")
    return _with_retries(
        lambda: client.views_update(
            external_id=external_id,
            view=slack_helpers.RequestForAccessView.update_with_accounts(accounts=accounts, account_sections=cfg.account_sections),
        )
    )


app.shortcut("request_for_access")(
    build_initial_form_handler(view_class=slack_helpers.RequestForAccessView),  # type: ignore # noqa: PGH003
    load_select_options_for_account_access_request,
)

app.shortcut("request_for_group_membership")(
    build_initial_form_handler(view_class=slack_helpers.RequestForGroupAccessView),  # type: ignore # noqa: PGH003
    load_select_options_for_group_access_request,
)

cache_for_dublicate_requests = {}


@handle_errors
def handle_button_click(body: dict, client: WebClient, context: BoltContext) -> SlackResponse:  # noqa: ARG001, PLR0911, PLR0915
    logger.info("Handling button click")
    try:
        payload = slack_helpers.ButtonClickedPayload.model_validate(body)
    except Exception as e:
        logger.exception(e)
        return group.handle_group_button_click(body, client, context)

    logger.info("Button click payload", extra={"payload": payload})
    # Approver might be from different Slack workspace, if so, get_user will fail.
    try:
        approver = slack_helpers.get_user(client, id=payload.approver_slack_id)
    except Exception as e:
        logger.warning(f"Failed to get approver user info: {e}")
        return client.chat_postMessage(
            channel=payload.channel_id,
            text=f"""Unable to process this approval - approver information could not be retrieved.
            This may happen if the approver <@{payload.approver_slack_id}> is from a different Slack workspace.
            Please check the module configuration.""",
            thread_ts=payload.thread_ts,
        )
    requester = slack_helpers.get_user(client, id=payload.request.requester_slack_id)
    is_user_in_channel = slack_helpers.check_if_user_is_in_channel(client, cfg.slack_channel_id, requester.id)

    if (
        cache_for_dublicate_requests.get("requester_slack_id") == payload.request.requester_slack_id
        and cache_for_dublicate_requests.get("account_id") == payload.request.account_id
        and cache_for_dublicate_requests.get("permission_set_name") == payload.request.permission_set_name
    ):
        return client.chat_postMessage(
            channel=payload.channel_id,
            text=f"<@{approver.id}> request is already in progress, please wait for the result.",
            thread_ts=payload.thread_ts,
        )
    cache_for_dublicate_requests["requester_slack_id"] = payload.request.requester_slack_id
    cache_for_dublicate_requests["account_id"] = payload.request.account_id
    cache_for_dublicate_requests["permission_set_name"] = payload.request.permission_set_name

    # Look up permission set to get ARN for matching and name for display
    permission_set = sso.get_permission_set(sso_client, cfg.sso_instance_arn, payload.request.permission_set_name)

    # Create a resolver function that resolves approver groups per-statement
    # This prevents cross-statement authorization bypass where someone in GroupY
    # could approve requests for Statement A just because Statement A has some groups
    resolver_cache: dict[frozenset[str], set[str]] = {}

    def approver_group_resolver(group_ids: frozenset[str]) -> set[str]:
        if not group_ids:
            return set()
        if group_ids in resolver_cache:
            return resolver_cache[group_ids]
        group_users, _ = slack_helpers.resolve_approver_groups(client, group_ids)
        result = {u.id for u in group_users}
        resolver_cache[group_ids] = result
        return result

    is_self_cancel = payload.approver_slack_id == payload.request.requester_slack_id and payload.action == entities.ApproverAction.Deny

    decision = access_control.make_decision_on_approve_request(
        action=payload.action,
        statements=cfg.statements,
        account_id=payload.request.account_id,
        permission_set_name=payload.request.permission_set_name,
        approver_email=approver.email,
        requester_email=requester.email,
        permission_set_arn=permission_set.arn,
        approver_slack_id=approver.id,
        approver_group_resolver=approver_group_resolver,
    )
    logger.info("Decision on request was made", extra={"decision": decision.dict()})

    if not decision.permit and not is_self_cancel:
        cache_for_dublicate_requests.clear()
        verb = "deny" if payload.action == entities.ApproverAction.Deny else "approve"
        return client.chat_postMessage(
            channel=payload.channel_id,
            text=f"<@{approver.id}> You cannot {verb} this request.",
            thread_ts=payload.thread_ts,
        )

    if payload.action == entities.ApproverAction.Deny:
        blocks = slack_helpers.HeaderSectionBlock.set_status(
            blocks=payload.message["blocks"],
            status_text=cfg.denied_status,
        )

        blocks = slack_helpers.remove_blocks(blocks, block_ids=["buttons"])
        if is_self_cancel:
            footer_text = f"<@{requester.id}> cancelled the request"
            text = f"Request was cancelled by <@{requester.id}>."
            dm_text = None
            analytics_event = "aws_access_cancelled"
        else:
            footer_text = f"<@{approver.id}> pressed {payload.action.value} button"
            text = f"Request was denied by <@{approver.id}>."
            dm_text = f"Your request was denied by <@{approver.id}>."
            analytics_event = "aws_access_denied"
        blocks.append(slack_helpers.footer_info_block(footer_text).to_dict())

        client.chat_update(
            channel=payload.channel_id,
            ts=payload.thread_ts,
            blocks=blocks,
            text=text,
        )

        analytics.capture(
            event=analytics_event,
            distinct_id=requester.email,
            properties={
                "account_id": payload.request.account_id,
                "permission_set": permission_set.name,
                "approver_email": approver.email,
                "requester_email": requester.email,
            },
        )

        cache_for_dublicate_requests.clear()
        if dm_text is not None and cfg.send_dm_if_user_not_in_channel and not is_user_in_channel:
            logger.info(f"User {requester.id} is not in the channel. Sending DM with message: {dm_text}")
            client.chat_postMessage(channel=requester.id, text=dm_text)
        return client.chat_postMessage(
            channel=payload.channel_id,
            text=text,
            thread_ts=payload.thread_ts,
        )

    text = f"Permissions granted by <@{approver.id}>."
    dm_text = f"Your request was approved by <@{approver.id}>. Permissions granted."
    blocks = slack_helpers.HeaderSectionBlock.set_status(
        blocks=payload.message["blocks"],
        status_text=cfg.granted_status,
    )

    blocks = slack_helpers.remove_blocks(blocks, block_ids=["buttons"])
    blocks.append(slack_helpers.button_click_info_block(payload.action, approver.id).to_dict())
    is_user_in_channel = slack_helpers.check_if_user_is_in_channel(client, cfg.slack_channel_id, requester.id)
    client.chat_update(
        channel=payload.channel_id,
        ts=payload.thread_ts,
        blocks=blocks,
        text=text,
    )

    result = access_control.execute_decision(
        decision=decision,
        permission_set_name=payload.request.permission_set_name,
        account_id=payload.request.account_id,
        permission_duration=payload.request.permission_duration,
        approver=approver,
        requester=requester,
        reason=payload.request.reason,
        thread_ts=payload.thread_ts,
    )

    if result.concurrent_operation:
        # Another approver (or a Slack retry) is already processing this approval.
        # Skip side effects — the winning invocation will post the success message
        # and grant the access.
        logger.info("Skipping follow-up — concurrent approval already in progress")
        cache_for_dublicate_requests.clear()
        return None  # type: ignore[return-value]

    if result.granted:
        analytics.capture(
            event="aws_access_approved",
            distinct_id=requester.email,
            properties={
                "account_id": payload.request.account_id,
                "permission_set": permission_set.name,
                "approver_email": approver.email,
                "requester_email": requester.email,
                "duration_hours": payload.request.permission_duration.total_seconds() / 3600,
                "self_approved": approver.email == requester.email,
            },
        )

    cache_for_dublicate_requests.clear()
    if cfg.send_dm_if_user_not_in_channel and not is_user_in_channel:
        logger.info(f"User {requester.id} is not in the channel. Sending DM with message: {dm_text}")
        client.chat_postMessage(channel=requester.id, text=dm_text)

    # Post the "End session early" button after permissions are granted
    if result.granted and result.schedule_name:
        first_statement = list(decision.based_on_statements)[0] if decision.based_on_statements else None
        approver_emails = list(first_statement.approvers) if first_statement else []
        approver_groups = list(first_statement.approver_groups) if first_statement else []
        assert result.user_principal_id is not None
        early_revoke_payload = slack_helpers.EarlyRevokeButtonPayload(
            schedule_name=result.schedule_name,
            requester_slack_id=requester.id,
            account_id=result.account_id,
            permission_set_name=result.permission_set_name,
            permission_set_arn=result.permission_set_arn,
            instance_arn=result.instance_arn,
            user_principal_id=result.user_principal_id,
            approver_emails=approver_emails,
            approver_groups=approver_groups,
        )
        client.chat_postMessage(
            channel=payload.channel_id,
            thread_ts=payload.thread_ts,
            blocks=[slack_helpers.build_early_revoke_button(early_revoke_payload).to_dict()],
            text="End session early",
        )

    return client.chat_postMessage(
        channel=payload.channel_id,
        text=text,
        thread_ts=payload.thread_ts,
    )


def acknowledge_request(ack: Ack):  # noqa: ANN201
    ack()


app.action(entities.ApproverAction.Approve.value)(
    ack=acknowledge_request,
    lazy=[handle_button_click],
)

app.action(entities.ApproverAction.Deny.value)(
    ack=acknowledge_request,
    lazy=[handle_button_click],
)


def _process_single_access_request(  # noqa: PLR0915, PLR0912
    request: slack_helpers.RequestForAccess,
    requester: entities.slack.User,
    user_group_ids: set[str],
    client: WebClient,
    is_user_in_channel: bool,
) -> access_control.AccessRequestDecision:
    """Process a single account access request (post approval message, make decision, etc.).

    Returns the access decision so non-Slack callers (e.g. the CLI handler) can report the
    outcome to the requester. The Slack submission handler ignores the return value.
    """
    # Look up permission set to get ARN for matching against ARN-based config
    permission_set = sso.get_permission_set(sso_client, cfg.sso_instance_arn, request.permission_set_name)

    # Create a resolver function for self-approval via group membership
    resolver_cache: dict[frozenset[str], set[str]] = {}

    def approver_group_resolver(group_ids: frozenset[str]) -> set[str]:
        if not group_ids:
            return set()
        if group_ids in resolver_cache:
            return resolver_cache[group_ids]
        group_users, _ = slack_helpers.resolve_approver_groups(client, group_ids)
        result = {u.id for u in group_users}
        resolver_cache[group_ids] = result
        return result

    decision = access_control.make_decision_on_access_request(
        cfg.statements,
        account_id=request.account_id,
        permission_set_name=request.permission_set_name,
        requester_email=requester.email,
        user_group_ids=user_group_ids,
        permission_set_arn=permission_set.arn,
        requester_slack_id=request.requester_slack_id,
        approver_group_resolver=approver_group_resolver,
    )
    logger.info("Decision on request was made", extra={"decision": decision.dict()})

    analytics.capture(
        event="aws_access_requested",
        distinct_id=requester.email,
        properties={
            "account_id": request.account_id,
            "permission_set": permission_set.name,
            "requester_email": requester.email,
            "decision_reason": decision.reason.value,
            "granted": decision.grant,
            "duration_hours": request.permission_duration.total_seconds() / 3600,
        },
    )

    try:
        account = organizations.describe_account(org_client, request.account_id)
    except Exception:
        logger.warning("Failed to describe account, using account ID as fallback", extra={"account_id": request.account_id})
        account = entities.aws.Account(id=request.account_id, name=request.account_id)

    show_buttons = bool(decision.approvers) or bool(decision.approver_groups)
    slack_response = client.chat_postMessage(
        blocks=slack_helpers.build_approval_request_message_blocks(
            sso_client=sso_client,
            identity_store_client=identity_store_client,
            slack_client=client,
            requester_slack_id=request.requester_slack_id,
            account=account,
            role_name=permission_set.name,
            reason=request.reason,
            permission_duration=request.permission_duration,
            show_buttons=show_buttons,
            status_text=cfg.pending_status,
        ),
        channel=cfg.slack_channel_id,
        text=f"Request for access to {account.name} account from {requester.real_name}",
    )

    if show_buttons:
        ts = slack_response["ts"]
        if ts is not None:
            schedule.schedule_discard_buttons_event(
                schedule_client=schedule_client,
                time_stamp=ts,
                channel_id=cfg.slack_channel_id,
            )
            schedule.schedule_approver_notification_event(
                schedule_client=schedule_client,
                message_ts=ts,
                channel_id=cfg.slack_channel_id,
                time_to_wait=timedelta(
                    minutes=cfg.approver_renotification_initial_wait_time,
                ),
            )

    match decision.reason:
        case access_control.DecisionReason.ApprovalNotRequired:
            text = "Approval for this Permission Set & Account is not required. Request will be approved automatically."
            dm_text = "Approval for this Permission Set & Account is not required. Your request will be approved automatically."
            status_text = cfg.granted_status
        case access_control.DecisionReason.SelfApproval:
            text = "Self-approval is allowed and requester is an approver. Request will be approved automatically."
            dm_text = "Self-approval is allowed and you are an approver. Your request will be approved automatically."
            status_text = cfg.granted_status
        case access_control.DecisionReason.RequiresApproval:
            approvers, approver_emails_not_found = slack_helpers.find_approvers_in_slack(
                client,
                decision.approvers,  # type: ignore # noqa: PGH003
            )
            group_mentions = slack_helpers.build_approver_group_mentions(decision.approver_groups)

            if not approvers and not decision.approver_groups:
                text = """
                None of the approvers from configuration could be found in Slack.
                Request cannot be processed. Please deny the request and check the module configuration.
                """
                dm_text = """
                Your request cannot be processed because none of the approvers from configuration could be found in Slack.
                Please deny the request and check the module configuration.
                """
                status_text = cfg.denied_status
            else:
                mention_approvers = " ".join(f"<@{approver.id}>" for approver in approvers)
                all_mentions = " ".join(filter(None, [mention_approvers, group_mentions]))
                text = f"{all_mentions} Request awaiting approval."
                if approver_emails_not_found:
                    missing_emails = ", ".join(approver_emails_not_found)
                    text += f"""
                    Note: Some approvers ({missing_emails}) could not be found in Slack.
                    Please deny the request and check the module configuration.
                    """
                dm_text = f"Your request is awaiting approval from {all_mentions}."
                status_text = cfg.pending_status
        case access_control.DecisionReason.NoApprovers:
            text = "Nobody can approve this request."
            dm_text = "Nobody can approve this request."
            status_text = cfg.denied_status
        case access_control.DecisionReason.NoStatements:
            text = "There are no statements for this Permission Set & Account."
            dm_text = "There are no statements for this Permission Set & Account."
            status_text = cfg.denied_status

    logger.info(f"Sending message to the channel {cfg.slack_channel_id}, message: {text}")
    client.chat_postMessage(text=text, thread_ts=slack_response["ts"], channel=cfg.slack_channel_id)
    if cfg.send_dm_if_user_not_in_channel and not is_user_in_channel:
        logger.info(f"User {requester.id} is not in the channel. Sending DM with message: {dm_text}")
        client.chat_postMessage(
            channel=requester.id,
            text=f"""
            {dm_text} You are receiving this message in a DM because you are not a member of the channel <#{cfg.slack_channel_id}>.
            """,
        )

    assert slack_response is not None
    blocks = slack_helpers.HeaderSectionBlock.set_status(
        blocks=slack_response["message"]["blocks"],  # type: ignore[index]
        status_text=status_text,
    )
    client.chat_update(
        channel=cfg.slack_channel_id,
        ts=str(slack_response["ts"]),
        blocks=blocks,
        text=text,
    )

    try:
        result = access_control.execute_decision(
            decision=decision,
            permission_set_name=request.permission_set_name,
            account_id=request.account_id,
            permission_duration=request.permission_duration,
            approver=requester,
            requester=requester,
            reason=request.reason,
            thread_ts=slack_response["ts"],
        )
    except AccountAssignmentError as e:
        reason = e.failure_reason or str(e)
        client.chat_postMessage(
            channel=cfg.slack_channel_id,
            text=f"Failed to grant permissions: {reason}",
            thread_ts=slack_response["ts"],
        )
        raise

    if result.concurrent_operation:
        logger.info("Skipping follow-up — concurrent request already in progress")
        return decision

    if result.granted:
        analytics.capture(
            event="aws_access_approved",
            distinct_id=requester.email,
            properties={
                "account_id": request.account_id,
                "permission_set": permission_set.name,
                "approver_email": requester.email,
                "requester_email": requester.email,
                "duration_hours": request.permission_duration.total_seconds() / 3600,
                "self_approved": True,
            },
        )

        client.chat_postMessage(
            channel=cfg.slack_channel_id,
            text="Permissions granted.",
            thread_ts=slack_response["ts"],
        )
        if not is_user_in_channel and cfg.send_dm_if_user_not_in_channel:
            client.chat_postMessage(
                channel=requester.id,
                text="Your request was processed, permissions granted.",
            )

        # Post the "End session early" button
        if result.schedule_name:
            first_statement = list(decision.based_on_statements)[0] if decision.based_on_statements else None
            approver_emails = list(first_statement.approvers) if first_statement else []
            approver_groups = list(first_statement.approver_groups) if first_statement else []
            assert result.user_principal_id is not None
            early_revoke_payload = slack_helpers.EarlyRevokeButtonPayload(
                schedule_name=result.schedule_name,
                requester_slack_id=requester.id,
                account_id=result.account_id,
                permission_set_name=result.permission_set_name,
                permission_set_arn=result.permission_set_arn,
                instance_arn=result.instance_arn,
                user_principal_id=result.user_principal_id,
                approver_emails=approver_emails,
                approver_groups=approver_groups,
            )
            client.chat_postMessage(
                channel=cfg.slack_channel_id,
                thread_ts=slack_response["ts"],
                blocks=[slack_helpers.build_early_revoke_button(early_revoke_payload).to_dict()],
                text="End session early",
            )

    return decision


@handle_errors
def handle_request_for_access_submittion(
    body: dict,
    ack: Ack,  # noqa: ARG001
    client: WebClient,
    context: BoltContext,  # noqa: ARG001
) -> SlackResponse | None:
    logger.info("Handling request for access submission")
    requests = slack_helpers.RequestForAccessView.parse_multi(body)
    logger.info("View submitted", extra={"requests": [r.model_dump() for r in requests]})

    if not requests:
        logger.warning("No accounts selected in submission")
        return None

    requester = slack_helpers.get_user(client, id=requests[0].requester_slack_id)

    # Try to use cached user info from load_select_options_for_account_access_request
    callback_id = slack_helpers.RequestForAccessView.CALLBACK_ID
    view_key = f"{requester.id}:{callback_id}"
    cached_user_principal_id = user_view_map.get(f"{view_key}:user_principal_id")
    cached_group_ids = user_view_map.get(f"{view_key}:group_ids")

    identity_store_id = sso.get_identity_store_id(cfg, sso_client)

    if cached_user_principal_id and cached_group_ids is not None:
        logger.debug("Using cached user info", extra={"view_key": view_key})
        user_group_ids = cached_group_ids
    else:
        # Fall back to API calls if cache miss (defense in depth)
        logger.debug("Cache miss, fetching user info from API", extra={"view_key": view_key})
        user_principal_id, _ = sso.get_user_principal_id_by_email(
            identity_store_client=identity_store_client,
            identity_store_id=identity_store_id,
            email=requester.email,
            cfg=cfg,
        )
        user_group_ids = sso.get_user_group_ids(
            identity_store_client=identity_store_client,
            identity_store_id=identity_store_id,
            user_principal_id=user_principal_id,
        )

    is_user_in_channel = slack_helpers.check_if_user_is_in_channel(client, cfg.slack_channel_id, requester.id)

    # Fan out: process each account request independently
    for request in requests:
        try:
            _process_single_access_request(
                request=request,
                requester=requester,
                user_group_ids=user_group_ids,
                client=client,
                is_user_in_channel=is_user_in_channel,
            )
        except Exception:
            logger.exception(
                "Failed to process access request for account",
                extra={"account_id": request.account_id},
            )


def acknowledge_request_for_access(ack: Ack, body: dict) -> None:
    # Slack can't disable the submit button, so reject submissions with no permission set selected
    # (e.g. "Load permission sets" was never clicked) and surface an inline error instead of
    # silently dropping them. Once the permission-set block exists it is a required input, so Slack
    # already blocks submit there; this guards the case where the block is absent.
    if not slack_helpers.RequestForAccessView.parse_multi(body):
        ack(
            response_action="errors",
            errors={
                slack_helpers.RequestForAccessView.ACCOUNT_BLOCK_ID: (
                    "This form isn't fully loaded or is incomplete. Select account(s), click 'Load permission sets', "
                    "choose a permission set, and pick a duration before submitting."
                )
            },
        )
        return
    ack()


app.view(slack_helpers.RequestForAccessView.CALLBACK_ID)(
    ack=acknowledge_request_for_access,
    lazy=[handle_request_for_access_submittion],
)

app.view(slack_helpers.RequestForGroupAccessView.CALLBACK_ID)(
    ack=acknowledge_request,
    lazy=[group.handle_request_for_group_access_submittion],
)

app.action(slack_helpers.RequestForGroupAccessView.GROUP_ACTION_ID)(group.handle_group_selection)


@app.action("duration_picker_action")
def handle_duration_picker_action(ack):  # noqa: ANN201, ANN001
    ack()


def classify_auto_approved_permission_sets(  # noqa: PLR0913
    statements: frozenset[statement.Statement],
    permission_sets: list[entities.aws.PermissionSet],
    account_ids: list[str],
    requester_email: str,
    user_group_ids: set[str],
    requester_slack_id: str,
    approver_group_resolver: Callable[[frozenset[str]], set[str]] | None = None,
) -> set[str]:
    """Return ARNs of permission sets that are auto-approved for all given accounts."""
    auto_approved = set()
    for ps in permission_sets:
        if all(
            access_control.make_decision_on_access_request(
                statements,
                account_id=aid,
                permission_set_name=ps.name,
                requester_email=requester_email,
                user_group_ids=user_group_ids,
                permission_set_arn=ps.arn,
                requester_slack_id=requester_slack_id,
                approver_group_resolver=approver_group_resolver,
            ).grant
            for aid in account_ids
        ):
            auto_approved.add(ps.arn)
    return auto_approved


def _get_cached_user_info(view_key: str, user_id: str, client: "WebClient") -> tuple[set[str], str | None]:
    """Get user group IDs and email from cache, re-fetching from Identity Center on miss."""
    user_group_ids = user_view_map.get(f"{view_key}:group_ids")
    user_email = user_view_map.get(f"{view_key}:user_email")
    if user_group_ids is not None:
        return user_group_ids, user_email

    logger.info("User info cache miss (container recycled), re-fetching from Identity Center")
    identity_store_id = sso.get_identity_store_id(cfg, sso_client)
    user_email = slack_helpers.get_user(client, id=user_id).email
    user_principal_id, _ = sso.get_user_principal_id_by_email(
        identity_store_client=identity_store_client,
        identity_store_id=identity_store_id,
        email=user_email,
        cfg=cfg,
    )
    user_group_ids = sso.get_user_group_ids(
        identity_store_client=identity_store_client,
        identity_store_id=identity_store_id,
        user_principal_id=user_principal_id,
    )
    # Re-populate cache for subsequent calls in this container
    user_view_map[f"{view_key}:group_ids"] = user_group_ids
    user_view_map[f"{view_key}:user_principal_id"] = user_principal_id
    user_view_map[f"{view_key}:user_email"] = user_email
    return user_group_ids, user_email


def handle_load_permission_sets(ack: Ack, body: dict, client: WebClient) -> SlackResponse | None:
    ack()
    logger.info("Handling load-permission-sets button")

    selected_options = (
        jp.search(
            f"view.state.values.{slack_helpers.RequestForAccessView.ACCOUNT_BLOCK_ID}"
            f".{slack_helpers.RequestForAccessView.ACCOUNT_ACTION_ID}.selected_options",
            body,
        )
        or []
    )
    account_ids = [opt["value"] for opt in selected_options]
    logger.info(f"Selected accounts: {account_ids}")

    view_id = body["view"]["id"]
    view_hash = body["view"].get("hash")

    def safe_views_update(view) -> SlackResponse | None:  # noqa: ANN001, ANN202
        nonlocal view_hash
        try:
            response = client.views_update(view_id=view_id, view=view, hash=view_hash)
        except slack_sdk.errors.SlackApiError as e:
            error = e.response.get("error") if e.response else None
            # hash_conflict / view_expired = a newer handler already updated the view; skip silently.
            if error in {"hash_conflict", "view_expired", "not_found"}:
                logger.info(f"Skipping stale views_update: {error}")
                return None
            raise
        new_hash = response.data.get("view", {}).get("hash") if response.data else None  # type: ignore[union-attr]
        if new_hash:
            view_hash = new_hash
        return response

    # Button pressed with no accounts selected -> nothing to load; leave the modal as-is.
    if not account_ids:
        logger.info("Load-permission-sets pressed with no accounts selected; ignoring")
        return None

    # Immediately replace stale permission set list with a loading placeholder before any AWS calls.
    loading_response = safe_views_update(slack_helpers.RequestForAccessView.show_permission_set_loading(body["view"]["blocks"]))
    if loading_response is None:
        # A newer handler is already in flight; let it produce the final view.
        return None
    current_blocks = loading_response.data["view"]["blocks"]  # type: ignore[index]

    # Get cached user info, re-fetching from Identity Center on cache miss
    # (e.g. when Lambda container was recycled between form load and account selection)
    user_id = body.get("user", {}).get("id")
    callback_id = slack_helpers.RequestForAccessView.CALLBACK_ID
    view_key = f"{user_id}:{callback_id}"
    user_group_ids, user_email = _get_cached_user_info(view_key, user_id, client)

    # Compute intersection of permission sets across all selected accounts
    valid_ps_names = statement.get_permission_sets_for_accounts_and_user(cfg.statements, account_ids, user_group_ids)
    logger.info(f"Valid permission sets for selected accounts and user: {valid_ps_names}")

    if not valid_ps_names:
        updated_view = slack_helpers.RequestForAccessView.build_no_permission_sets_view(view_blocks=current_blocks)
        return safe_views_update(updated_view)

    if "*" in valid_ps_names:
        permission_sets = sso.get_permission_sets_from_config_with_cache(sso_client=sso_client, s3_client=s3_client, cfg=cfg)
    else:
        all_ps = sso.get_permission_sets_from_config_with_cache(sso_client=sso_client, s3_client=s3_client, cfg=cfg)
        permission_sets = [ps for ps in all_ps if ps.name in valid_ps_names or ps.arn in valid_ps_names]

    # Handle case where filtered list is empty (configured names don't exist in SSO)
    if not permission_sets:
        updated_view = slack_helpers.RequestForAccessView.build_no_permission_sets_view(view_blocks=current_blocks)
        return safe_views_update(updated_view)

    # Classify permission sets as auto-approved vs requires-approval
    auto_approved_arns: set[str] | None = None
    if user_email:
        resolver_cache: dict[frozenset[str], set[str]] = {}

        def approver_group_resolver(group_ids: frozenset[str]) -> set[str]:
            if not group_ids:
                return set()
            if group_ids in resolver_cache:
                return resolver_cache[group_ids]
            group_users, _ = slack_helpers.resolve_approver_groups(client, group_ids)
            result = {u.id for u in group_users}
            resolver_cache[group_ids] = result
            return result

        auto_approved_arns = classify_auto_approved_permission_sets(
            statements=cfg.statements,
            permission_sets=permission_sets,
            account_ids=account_ids,
            requester_email=user_email,
            user_group_ids=user_group_ids,
            requester_slack_id=user_id,
            approver_group_resolver=approver_group_resolver,
        )

    updated_view = slack_helpers.RequestForAccessView.update_with_permission_sets(
        view_blocks=current_blocks,
        permission_sets=permission_sets,
        display_names=cfg.permission_set_display_names,
        auto_approved_arns=auto_approved_arns,
    )
    return safe_views_update(updated_view)


app.action(slack_helpers.RequestForAccessView.LOAD_PS_ACTION_ID)(handle_load_permission_sets)


def handle_permission_set_selection(ack: Ack, body: dict, client: WebClient) -> SlackResponse | None:
    # The approver preview is informational. Any failure here MUST NOT block the user from
    # submitting their request, so the entire impl is wrapped in try/except below.
    ack()
    try:
        return _handle_permission_set_selection_impl(body, client)
    except Exception:
        logger.exception("Approver preview rendering failed; modal remains usable")
        return None


app.action(slack_helpers.RequestForAccessView.PERMISSION_SET_ACTION_ID)(handle_permission_set_selection)


def _handle_permission_set_selection_impl(body: dict, client: WebClient) -> SlackResponse | None:
    logger.info("Handling permission set selection")

    view_state = jp.search("view.state.values", body) or {}
    permission_set_arn = jp.search(
        f"{slack_helpers.RequestForAccessView.PERMISSION_SET_BLOCK_ID}"
        f".{slack_helpers.RequestForAccessView.PERMISSION_SET_ACTION_ID}.selected_option.value",
        view_state,
    )
    if not permission_set_arn:
        return None

    selected_options = (
        jp.search(
            f"{slack_helpers.RequestForAccessView.ACCOUNT_BLOCK_ID}"
            f".{slack_helpers.RequestForAccessView.ACCOUNT_ACTION_ID}.selected_options",
            view_state,
        )
        or []
    )
    account_ids = [opt["value"] for opt in selected_options]
    if not account_ids:
        return None

    view_id = body["view"]["id"]
    view_hash = body["view"].get("hash")

    def safe_views_update(view) -> SlackResponse | None:  # noqa: ANN001, ANN202
        nonlocal view_hash
        try:
            response = client.views_update(view_id=view_id, view=view, hash=view_hash)
        except slack_sdk.errors.SlackApiError as e:
            error = e.response.get("error") if e.response else None
            if error in {"hash_conflict", "view_expired", "not_found"}:
                logger.info(f"Skipping stale views_update: {error}")
                return None
            raise
        new_hash = response.data.get("view", {}).get("hash") if response.data else None  # type: ignore[union-attr]
        if new_hash:
            view_hash = new_hash
        return response

    loading_response = safe_views_update(slack_helpers.RequestForAccessView.show_approvers_loading(body["view"]["blocks"]))
    if loading_response is None:
        return None
    current_blocks = loading_response.data["view"]["blocks"]  # type: ignore[index]

    user_id = body.get("user", {}).get("id")
    callback_id = slack_helpers.RequestForAccessView.CALLBACK_ID
    view_key = f"{user_id}:{callback_id}"
    user_group_ids, user_email = _get_cached_user_info(view_key, user_id, client)

    all_ps = sso.get_permission_sets_from_config_with_cache(sso_client=sso_client, s3_client=s3_client, cfg=cfg)
    ps = next((p for p in all_ps if p.arn == permission_set_arn), None)
    if ps is None:
        logger.warning(f"Permission set ARN not found in config: {permission_set_arn}")
        return None

    resolver_cache: dict[frozenset[str], set[str]] = {}

    def approver_group_resolver(group_ids: frozenset[str]) -> set[str]:
        if not group_ids:
            return set()
        if group_ids in resolver_cache:
            return resolver_cache[group_ids]
        group_users, _ = slack_helpers.resolve_approver_groups(client, group_ids)
        result = {u.id for u in group_users}
        resolver_cache[group_ids] = result
        return result

    decisions = [
        access_control.make_decision_on_access_request(
            cfg.statements,
            account_id=aid,
            permission_set_name=ps.name,
            permission_set_arn=ps.arn,
            requester_email=user_email or "",
            user_group_ids=user_group_ids,
            requester_slack_id=user_id,
            approver_group_resolver=approver_group_resolver,
        )
        for aid in account_ids
    ]

    email_cache = user_view_map.setdefault(f"{view_key}:approver_email_to_slack", {})
    text = slack_helpers.build_approvers_preview_text(client, decisions, email_cache)
    updated_view = slack_helpers.RequestForAccessView.update_with_approvers(view_blocks=current_blocks, text=text)
    return safe_views_update(updated_view)


# Early Revoke Handlers
# ----------------------


def check_early_revoke_authorization(
    clicker_slack_id: str,
    requester_slack_id: str,
    approver_emails: list[str],
    client: WebClient,
    approver_groups: list[str] | None = None,
) -> bool:
    """Check if the user clicking the button is authorized to end the session.

    Returns True if:
    - cfg.allow_anyone_to_end_session_early is True, OR
    - clicker is the requester, OR
    - clicker is one of the individual approvers, OR
    - clicker is a member of one of the approver groups
    """
    if cfg.allow_anyone_to_end_session_early:
        return True

    # Requester can always end their own session
    if clicker_slack_id == requester_slack_id:
        return True

    # Check if clicker is an individual approver
    try:
        clicker = slack_helpers.get_user(client, id=clicker_slack_id)
        if clicker.email in approver_emails:
            return True
    except Exception as e:
        logger.warning(f"Failed to get user info for authorization check: {e}")

    # Check if clicker is in an approver group
    if approver_groups:
        group_users, _ = slack_helpers.resolve_approver_groups(client, frozenset(approver_groups))
        if clicker_slack_id in {u.id for u in group_users}:
            return True

    return False


@handle_errors
def handle_early_revoke_button_click(body: dict, client: WebClient, context: BoltContext) -> SlackResponse | None:  # noqa: ARG001
    """Handle the 'End session early' button click."""
    import json

    logger.info("Handling early revoke button click")

    clicker_slack_id = jp.search("user.id", body)
    channel_id = jp.search("channel.id", body)
    thread_ts = jp.search("message.thread_ts", body) or jp.search("message.ts", body)

    logger.info(
        "Early revoke button context",
        extra={"thread_ts": thread_ts, "channel_id": channel_id, "clicker_slack_id": clicker_slack_id},
    )
    if not thread_ts:
        logger.warning("Could not extract thread_ts from button click body")

    # Parse the button value
    button_value = jp.search("actions[0].value", body)
    try:
        button_payload = slack_helpers.EarlyRevokeButtonPayload.model_validate(json.loads(button_value))
    except Exception as e:
        logger.error(f"Failed to parse early revoke button payload: {e}")
        return client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text="Failed to process early revoke request. Please try again.",
        )

    # Check authorization
    if not check_early_revoke_authorization(
        clicker_slack_id=clicker_slack_id,
        requester_slack_id=button_payload.requester_slack_id,
        approver_emails=button_payload.approver_emails,
        client=client,
        approver_groups=button_payload.approver_groups,
    ):
        who_can = "requester or approvers" if button_payload.approver_emails or button_payload.approver_groups else "requester"
        return client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text=f"<@{clicker_slack_id}> You are not authorized to end this session. Only the {who_can} can do this.",
        )

    # Determine if this is account access or group access
    if button_payload.account_id and button_payload.permission_set_name:
        # Account access - get account name for modal
        try:
            account = organizations.describe_account(org_client, button_payload.account_id)
            account_name = account.name
        except Exception:
            account_name = button_payload.account_id

        private_metadata = json.dumps(
            {
                "button_payload": button_payload.model_dump(mode="json"),
                "channel_id": channel_id,
                "thread_ts": thread_ts,
            }
        )

        modal = slack_helpers.EarlyRevokeModal.build(
            account_name=account_name,
            account_id=button_payload.account_id,
            permission_set_name=button_payload.permission_set_name,
            private_metadata=private_metadata,
        )
    elif button_payload.group_id and button_payload.group_name:
        # Group access
        private_metadata = json.dumps(
            {
                "button_payload": button_payload.model_dump(mode="json"),
                "channel_id": channel_id,
                "thread_ts": thread_ts,
            }
        )

        modal = slack_helpers.EarlyRevokeModal.build(
            group_name=button_payload.group_name,
            group_id=button_payload.group_id,
            private_metadata=private_metadata,
        )
    else:
        return client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text="Invalid early revoke request: missing access details.",
        )

    # Open the modal
    trigger_id = jp.search("trigger_id", body)
    return client.views_open(trigger_id=trigger_id, view=modal)


app.action(entities.ApproverAction.EarlyRevoke.value)(
    ack=acknowledge_request,
    lazy=[handle_early_revoke_button_click],
)


# Extend Grant Handlers
# ----------------------


@handle_errors
def handle_extend_grant_button_click(body: dict, client: WebClient, context: BoltContext) -> SlackResponse | None:  # noqa: ARG001, PLR0911, PLR0915
    """Handle the 'Extend access' button click."""
    import json
    from datetime import datetime, timedelta, timezone

    logger.info("Handling extend grant button click")

    clicker_slack_id = jp.search("user.id", body)
    channel_id = jp.search("channel.id", body)
    thread_ts = jp.search("message.thread_ts", body) or jp.search("message.ts", body)

    # Parse the button value
    button_value = jp.search("actions[0].value", body)
    try:
        payload = slack_helpers.ExtendGrantButtonPayload.model_validate(json.loads(button_value))
    except Exception as e:
        logger.error(f"Failed to parse extend grant button payload: {e}")
        return client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text="Failed to process extend request. Please try again.",
        )

    # Auth: only original requester can extend
    if clicker_slack_id != payload.requester_slack_id:
        return client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text=f"<@{clicker_slack_id}> Only the original requester can extend this session.",
        )

    # Check 1hr window
    expired_at = datetime.fromisoformat(payload.expired_at)
    now = datetime.now(timezone.utc)
    if now - expired_at > timedelta(hours=1):
        return client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text="Extension window has expired. You can only extend within 1 hour of session expiry.",
        )

    # Delete extend button from thread
    slack_helpers.delete_extend_grant_button(client, channel_id, thread_ts)

    # Reconstruct approver/requester User objects
    approver = entities.slack.User.model_validate(payload.approver)
    requester = entities.slack.User.model_validate(payload.requester)
    extension_duration = timedelta(minutes=payload.extension_duration_in_minutes)
    new_extensions_count = payload.extensions_count + 1

    if payload.account_id and payload.permission_set_arn:
        # Account access extension
        assert payload.instance_arn is not None
        account_assignment = sso.UserAccountAssignment(
            instance_arn=payload.instance_arn,
            account_id=payload.account_id,
            permission_set_arn=payload.permission_set_arn,
            user_principal_id=payload.user_principal_id,
        )

        try:
            sso.create_account_assignment_and_wait_for_result(sso_client, account_assignment)
        except Exception as e:
            if errors.is_conflict_exception(e):
                logger.warning(
                    "Concurrent extend already in progress, skipping follow-up",
                    extra={"account_assignment": account_assignment},
                )
                return None
            raise

        # Required so the cross-account eks-auth-updater Lambda restores the user's entry
        # in the EKS aws-auth ConfigMap. Without it, EKS-bound extensions succeed in SSO
        # but kubectl access is never re-granted.
        event_publisher.publish_access_event(
            action="grant",
            account_id=payload.account_id,
            permission_set_name=payload.permission_set_name or "",
            permission_set_arn=payload.permission_set_arn,
            user_principal_id=payload.user_principal_id,
        )

        _, schedule_name = schedule.schedule_revoke_event(
            permission_duration=extension_duration,
            schedule_client=schedule_client,
            approver=approver,
            requester=requester,
            user_account_assignment=account_assignment,
            slack_client=client,
            thread_ts=thread_ts,
            permission_set_name=payload.permission_set_name,
            account_name=payload.account_name,
            can_extend_expired_grant=True,
            extensions_count=new_extensions_count,
        )

        # Post early revoke button for the extension
        early_revoke_payload = slack_helpers.EarlyRevokeButtonPayload(
            schedule_name=schedule_name,
            requester_slack_id=requester.id,
            account_id=payload.account_id,
            permission_set_name=payload.permission_set_name,
            permission_set_arn=payload.permission_set_arn,
            instance_arn=payload.instance_arn,
            user_principal_id=payload.user_principal_id,
        )

        import s3

        s3.log_operation(
            audit_entry=s3.AuditEntry(
                account_id=payload.account_id,
                role_name=payload.permission_set_name or "NA",
                reason="extension",
                requester_slack_id=requester.id,
                requester_email=requester.email,
                approver_slack_id=approver.id,
                approver_email=approver.email,
                operation_type="extend",
                permission_duration=extension_duration,
                sso_user_principal_id=payload.user_principal_id,
                audit_entry_type="account",
            ),
        )

    elif payload.group_id:
        # Group access extension
        identity_store_id = payload.identity_store_id or sso.get_identity_store_id(cfg, sso_client)
        try:
            membership_result = sso.add_user_to_a_group(
                payload.group_id, payload.user_principal_id, identity_store_id, identity_store_client
            )
        except Exception as e:
            if errors.is_conflict_exception(e):
                logger.warning(
                    "Concurrent group extend already in progress, skipping follow-up",
                    extra={"group_id": payload.group_id, "user_principal_id": payload.user_principal_id},
                )
                return None
            raise
        membership_id = membership_result["MembershipId"]

        group_assignment = sso.GroupAssignment(
            identity_store_id=identity_store_id,
            group_name=payload.group_name or "",
            group_id=payload.group_id,
            user_principal_id=payload.user_principal_id,
            membership_id=membership_id,
        )

        _, schedule_name = schedule.schedule_group_revoke_event(
            permission_duration=extension_duration,
            schedule_client=schedule_client,
            approver=approver,
            requester=requester,
            group_assignment=group_assignment,
            slack_client=client,
            thread_ts=thread_ts,
            can_extend_expired_grant=True,
            extensions_count=new_extensions_count,
        )

        # Post early revoke button for the extension
        early_revoke_payload = slack_helpers.EarlyRevokeButtonPayload(
            schedule_name=schedule_name,
            requester_slack_id=requester.id,
            group_id=payload.group_id,
            group_name=payload.group_name,
            identity_store_id=identity_store_id,
            membership_id=membership_id,
            user_principal_id=payload.user_principal_id,
        )

        import s3

        s3.log_operation(
            audit_entry=s3.AuditEntry(
                group_name=payload.group_name or "NA",
                group_id=payload.group_id,
                reason="extension",
                requester_slack_id=requester.id,
                requester_email=requester.email,
                approver_slack_id=approver.id,
                approver_email=approver.email,
                operation_type="extend",
                permission_duration=extension_duration,
                sso_user_principal_id=payload.user_principal_id,
                audit_entry_type="group",
            ),
        )
    else:
        return client.chat_postMessage(
            channel=channel_id,
            thread_ts=thread_ts,
            text="Invalid extend request: missing access details.",
        )

    # Update header back to GRANTED status
    message = slack_helpers.get_message_from_timestamp(
        channel_id=channel_id,
        message_ts=thread_ts,
        slack_client=client,
    )
    if message:
        blocks = slack_helpers.HeaderSectionBlock.set_status(
            blocks=message["blocks"],
            status_text=cfg.granted_status,
        )
        client.chat_update(
            channel=channel_id,
            ts=thread_ts,
            blocks=blocks,
            text="Access extended",
        )

    # Post early revoke button
    client.chat_postMessage(
        channel=channel_id,
        thread_ts=thread_ts,
        blocks=[slack_helpers.build_early_revoke_button(early_revoke_payload).to_dict()],
        text="End session early",
    )

    return client.chat_postMessage(
        channel=channel_id,
        thread_ts=thread_ts,
        text=f"Access extended for {payload.extension_duration_in_minutes} minutes.",
    )


app.action(entities.ApproverAction.ExtendGrant.value)(
    ack=acknowledge_request,
    lazy=[handle_extend_grant_button_click],
)


@handle_errors
def handle_early_revoke_modal_submission(body: dict, client: WebClient, context: BoltContext) -> SlackResponse | None:  # noqa: ARG001
    """Handle the early revoke modal submission."""
    logger.info("Handling early revoke modal submission")

    try:
        payload = slack_helpers.EarlyRevokeModalPayload.model_validate(body)
    except Exception as e:
        logger.error(f"Failed to parse early revoke modal payload: {e}")
        return None

    button_payload = payload.button_payload

    # Perform the revocation
    if button_payload.account_id and button_payload.permission_set_arn:
        # Account access revocation
        assert button_payload.instance_arn is not None
        user_account_assignment = sso.UserAccountAssignment(
            instance_arn=button_payload.instance_arn,
            account_id=button_payload.account_id,
            permission_set_arn=button_payload.permission_set_arn,
            user_principal_id=button_payload.user_principal_id,
        )

        revoker.handle_early_account_revocation(
            user_account_assignment=user_account_assignment,
            schedule_name=button_payload.schedule_name,
            revoker_slack_id=payload.revoker_slack_id,
            requester_slack_id=button_payload.requester_slack_id,
            reason=payload.reason,
            sso_client=sso_client,
            scheduler_client=schedule_client,
            org_client=org_client,
            slack_client=client,
            identitystore_client=identity_store_client,
            cfg=cfg,
            thread_ts=payload.thread_ts,
        )
    elif button_payload.group_id and button_payload.membership_id:
        # Group access revocation
        assert button_payload.group_name is not None
        assert button_payload.identity_store_id is not None
        group_assignment = sso.GroupAssignment(
            group_name=button_payload.group_name,
            group_id=button_payload.group_id,
            user_principal_id=button_payload.user_principal_id,
            membership_id=button_payload.membership_id,
            identity_store_id=button_payload.identity_store_id,
        )

        revoker.handle_early_group_revocation(
            group_assignment=group_assignment,
            schedule_name=button_payload.schedule_name,
            revoker_slack_id=payload.revoker_slack_id,
            requester_slack_id=button_payload.requester_slack_id,
            reason=payload.reason,
            sso_client=sso_client,
            scheduler_client=schedule_client,
            slack_client=client,
            identitystore_client=identity_store_client,
            cfg=cfg,
            thread_ts=payload.thread_ts,
        )


app.view(slack_helpers.EarlyRevokeModal.CALLBACK_ID)(
    ack=acknowledge_request,
    lazy=[handle_early_revoke_modal_submission],
)
