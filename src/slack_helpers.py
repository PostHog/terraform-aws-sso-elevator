import datetime
import time
from datetime import timedelta, timezone
from typing import Optional, TypeVar, Union

import jmespath as jp
import slack_sdk.errors
from mypy_boto3_identitystore import IdentityStoreClient
from mypy_boto3_sso_admin import SSOAdminClient
from pydantic import model_validator
from slack_sdk import WebClient
from slack_sdk.models.blocks import (
    ActionsBlock,
    Block,
    ButtonElement,
    ContextBlock,
    DividerBlock,
    InputBlock,
    MarkdownTextObject,
    Option,
    OptionGroup,
    PlainTextInputElement,
    PlainTextObject,
    SectionBlock,
    StaticMultiSelectElement,
    StaticSelectElement,
)
from slack_sdk.models.views import View

import config
import entities
import sso
from entities import BaseModel

# ruff: noqa: ANN102, PGH003

logger = config.get_logger(service="slack")
cfg = config.get_config()


class RequestForAccess(BaseModel):
    permission_set_name: str
    account_id: str
    reason: str
    requester_slack_id: str
    permission_duration: timedelta


class RequestForAccessView:
    __name__ = "RequestForAccountAccessView"
    CALLBACK_ID = "request_for__account_access_submitted"

    REASON_BLOCK_ID = "provide_reason"
    REASON_ACTION_ID = "provided_reason"

    ACCOUNT_BLOCK_ID = "select_account"
    ACCOUNT_ACTION_ID = "selected_account"

    PERMISSION_SET_BLOCK_ID = "select_permission_set"
    PERMISSION_SET_ACTION_ID = "selected_permission_set"

    DURATION_BLOCK_ID = "duration_picker"
    DURATION_ACTION_ID = "duration_picker_action"

    LOADING_BLOCK_ID = "loading"
    PERMISSION_SET_PLACEHOLDER_BLOCK_ID = "permission_set_placeholder"
    PERMISSION_SET_LOADING_BLOCK_ID = "permission_set_loading"

    APPROVERS_BLOCK_ID = "approvers_preview"
    APPROVERS_LOADING_BLOCK_ID = "approvers_preview_loading"

    @classmethod
    def build(cls) -> View:
        return View(
            type="modal",
            callback_id=cls.CALLBACK_ID,
            submit=PlainTextObject(text="Request"),
            submit_disabled=True,
            close=PlainTextObject(text="Cancel"),
            title=PlainTextObject(text="Request AWS Access"),
            blocks=[
                SectionBlock(
                    block_id=cls.DURATION_BLOCK_ID,
                    text=MarkdownTextObject(text="How long do you need access?"),
                    accessory=StaticSelectElement(
                        action_id=cls.DURATION_ACTION_ID,
                        initial_option=get_max_duration_block(cfg)[0],
                        options=get_max_duration_block(cfg),
                        placeholder=PlainTextObject(text="Select duration"),
                    ),
                ),
                InputBlock(
                    block_id=cls.REASON_BLOCK_ID,
                    label=PlainTextObject(text="Reason for access"),
                    element=PlainTextInputElement(
                        action_id=cls.REASON_ACTION_ID,
                        placeholder=PlainTextObject(text="What will this access be used for?"),
                        multiline=True,
                    ),
                ),
                SectionBlock(
                    block_id=cls.LOADING_BLOCK_ID,
                    text=MarkdownTextObject(
                        text=":hourglass: Loading available accounts and permission sets...",
                    ),
                ),
                DividerBlock(),
                SectionBlock(
                    text=MarkdownTextObject(
                        text="All AWS API calls are logged for security compliance.",
                    ),
                ),
            ],
        )

    @classmethod
    def build_select_account_input_block(cls, accounts: list[entities.aws.Account]) -> InputBlock:
        # TODO: handle case when there are more than 100 accounts
        # 99 is the limit for StaticMultiSelectElement
        if len(accounts) > 99:  # noqa: PLR2004
            accounts = accounts[:99]
        sorted_accounts = sorted(accounts, key=lambda account: account.name)
        return InputBlock(
            block_id=cls.ACCOUNT_BLOCK_ID,
            dispatch_action=True,
            label=PlainTextObject(text="AWS Account(s)"),
            element=StaticMultiSelectElement(
                action_id=cls.ACCOUNT_ACTION_ID,
                placeholder=PlainTextObject(text="Select account(s)"),
                max_selected_items=10,
                options=[
                    Option(text=PlainTextObject(text=f"{account.id} - {account.name}"), value=account.id) for account in sorted_accounts
                ],
            ),
        )

    @classmethod
    def _get_permission_set_display_name(
        cls,
        ps: entities.aws.PermissionSet,
        display_names: dict[str, str] | None = None,
    ) -> str:
        custom = display_names.get(ps.name) or display_names.get(ps.arn) if display_names else None
        if custom and custom != ps.name:
            return f"{custom} ({ps.name})"[:75]
        return ps.name[:75]

    @classmethod
    def _build_permission_set_option(cls, ps: entities.aws.PermissionSet, display_names: dict[str, str] | None) -> Option:
        return Option(text=PlainTextObject(text=cls._get_permission_set_display_name(ps, display_names)), value=ps.arn)

    @classmethod
    def build_select_permission_set_input_block(
        cls,
        permission_sets: list[entities.aws.PermissionSet],
        display_names: dict[str, str] | None = None,
        auto_approved_arns: set[str] | None = None,
    ) -> InputBlock:
        sort_key = lambda ps: cls._get_permission_set_display_name(ps, display_names).lower()  # noqa: E731

        if auto_approved_arns is not None:
            auto_approved = sorted([ps for ps in permission_sets if ps.arn in auto_approved_arns], key=sort_key)
            requires_approval = sorted([ps for ps in permission_sets if ps.arn not in auto_approved_arns], key=sort_key)
            groups = []
            if auto_approved:
                groups.append(
                    OptionGroup(
                        label=PlainTextObject(text="Auto approved"),
                        options=[cls._build_permission_set_option(ps, display_names) for ps in auto_approved],
                    )
                )
            if requires_approval:
                groups.append(
                    OptionGroup(
                        label=PlainTextObject(text="Requires approval"),
                        options=[cls._build_permission_set_option(ps, display_names) for ps in requires_approval],
                    )
                )
            if groups:
                return InputBlock(
                    block_id=cls.PERMISSION_SET_BLOCK_ID,
                    dispatch_action=True,
                    label=PlainTextObject(text="Permission set"),
                    element=StaticSelectElement(
                        action_id=cls.PERMISSION_SET_ACTION_ID,
                        placeholder=PlainTextObject(text="Select permission set"),
                        option_groups=groups,
                    ),
                )

        sorted_permission_sets = sorted(permission_sets, key=sort_key)
        return InputBlock(
            block_id=cls.PERMISSION_SET_BLOCK_ID,
            dispatch_action=True,
            label=PlainTextObject(text="Permission set"),
            element=StaticSelectElement(
                action_id=cls.PERMISSION_SET_ACTION_ID,
                placeholder=PlainTextObject(text="Select permission set"),
                options=[cls._build_permission_set_option(ps, display_names) for ps in sorted_permission_sets],
            ),
        )

    @classmethod
    def build_permission_set_placeholder_block(cls) -> InputBlock:
        return InputBlock(
            block_id=cls.PERMISSION_SET_PLACEHOLDER_BLOCK_ID,
            label=PlainTextObject(text="Permission set"),
            element=StaticSelectElement(
                action_id=cls.PERMISSION_SET_ACTION_ID + "_placeholder",
                placeholder=PlainTextObject(text="Select an account first"),
                options=[Option(text=PlainTextObject(text="—"), value="_disabled")],
            ),
        )

    @classmethod
    def build_permission_set_loading_block(cls) -> InputBlock:
        return InputBlock(
            block_id=cls.PERMISSION_SET_LOADING_BLOCK_ID,
            label=PlainTextObject(text="Permission set"),
            element=StaticSelectElement(
                action_id=cls.PERMISSION_SET_ACTION_ID + "_loading",
                placeholder=PlainTextObject(text=":hourglass: Loading permission sets..."),
                options=[Option(text=PlainTextObject(text="—"), value="_loading")],
            ),
        )

    @classmethod
    def show_permission_set_loading(cls, view_blocks: list) -> View:
        view = cls.build()
        view.submit_disabled = True  # type: ignore[attr-defined]
        blocks = remove_blocks(
            view_blocks,
            block_ids=[
                cls.PERMISSION_SET_PLACEHOLDER_BLOCK_ID,
                cls.PERMISSION_SET_BLOCK_ID,
                cls.PERMISSION_SET_LOADING_BLOCK_ID,
                cls.APPROVERS_BLOCK_ID,
                cls.APPROVERS_LOADING_BLOCK_ID,
                "no_eligible_accounts",
            ],
        )
        blocks = insert_blocks(
            blocks=blocks,
            blocks_to_insert=[cls.build_permission_set_loading_block()],
            after_block_id=cls.ACCOUNT_BLOCK_ID,
        )
        view.blocks = blocks
        return view

    @classmethod
    def update_with_accounts(cls, accounts: list[entities.aws.Account]) -> View:
        view = cls.build()
        view.blocks = remove_blocks(view.blocks, block_ids=[cls.LOADING_BLOCK_ID])
        view.blocks = insert_blocks(
            blocks=view.blocks,
            blocks_to_insert=[
                cls.build_select_account_input_block(accounts),
                cls.build_permission_set_placeholder_block(),
            ],
            after_block_id=cls.REASON_BLOCK_ID,
        )
        return view

    @classmethod
    def update_with_permission_sets(
        cls,
        view_blocks: list,
        permission_sets: list[entities.aws.PermissionSet],
        display_names: dict[str, str] | None = None,
        auto_approved_arns: set[str] | None = None,
    ) -> View:
        view = cls.build()
        view.submit_disabled = False  # type: ignore[attr-defined]
        # Start from the current blocks, remove placeholder
        blocks = remove_blocks(
            view_blocks,
            block_ids=[
                cls.PERMISSION_SET_PLACEHOLDER_BLOCK_ID,
                cls.PERMISSION_SET_BLOCK_ID,
                cls.PERMISSION_SET_LOADING_BLOCK_ID,
                cls.APPROVERS_BLOCK_ID,
                cls.APPROVERS_LOADING_BLOCK_ID,
            ],
        )
        # Insert permission set dropdown after account dropdown
        blocks = insert_blocks(
            blocks=blocks,
            blocks_to_insert=[
                cls.build_select_permission_set_input_block(
                    permission_sets,
                    display_names=display_names,
                    auto_approved_arns=auto_approved_arns,
                )
            ],
            after_block_id=cls.ACCOUNT_BLOCK_ID,
        )
        view.blocks = blocks
        return view

    @classmethod
    def build_approvers_preview_block(cls, text: str) -> ContextBlock:
        return ContextBlock(
            block_id=cls.APPROVERS_BLOCK_ID,
            elements=[MarkdownTextObject(text=text)],
        )

    @classmethod
    def build_approvers_loading_block(cls) -> ContextBlock:
        return ContextBlock(
            block_id=cls.APPROVERS_LOADING_BLOCK_ID,
            elements=[MarkdownTextObject(text=":hourglass: Resolving approvers...")],
        )

    @classmethod
    def show_approvers_loading(cls, view_blocks: list) -> View:
        view = cls.build()
        # Preview is informational only — never block submit while it's resolving.
        view.submit_disabled = False  # type: ignore[attr-defined]
        blocks = remove_blocks(view_blocks, block_ids=[cls.APPROVERS_BLOCK_ID, cls.APPROVERS_LOADING_BLOCK_ID])
        blocks = insert_blocks(
            blocks=blocks,
            blocks_to_insert=[cls.build_approvers_loading_block()],
            after_block_id=cls.PERMISSION_SET_BLOCK_ID,
        )
        view.blocks = blocks
        return view

    @classmethod
    def update_with_approvers(cls, view_blocks: list, text: str) -> View:
        view = cls.build()
        view.submit_disabled = False  # type: ignore[attr-defined]
        blocks = remove_blocks(view_blocks, block_ids=[cls.APPROVERS_BLOCK_ID, cls.APPROVERS_LOADING_BLOCK_ID])
        blocks = insert_blocks(
            blocks=blocks,
            blocks_to_insert=[cls.build_approvers_preview_block(text)],
            after_block_id=cls.PERMISSION_SET_BLOCK_ID,
        )
        view.blocks = blocks
        return view

    @classmethod
    def build_no_permission_sets_block(cls) -> SectionBlock:
        return SectionBlock(
            block_id=cls.PERMISSION_SET_PLACEHOLDER_BLOCK_ID,
            text=MarkdownTextObject(text=":x: No common permission sets configured for the selected account(s)."),
        )

    @classmethod
    def build_no_eligible_accounts_block(cls) -> SectionBlock:
        return SectionBlock(
            block_id="no_eligible_accounts",
            text=MarkdownTextObject(text=":x: You don't have access to request any accounts."),
        )

    @classmethod
    def build_no_eligible_accounts_view(cls) -> View:
        """Build view with warning when user has no eligible accounts."""
        return View(
            type="modal",
            callback_id=cls.CALLBACK_ID,
            submit=PlainTextObject(text="Request"),
            submit_disabled=True,
            close=PlainTextObject(text="Cancel"),
            title=PlainTextObject(text="Request AWS Access"),
            blocks=[
                cls.build_no_eligible_accounts_block(),
                DividerBlock(),
                SectionBlock(
                    text=MarkdownTextObject(
                        text="All AWS API calls are logged for security compliance.",
                    ),
                ),
            ],
        )

    @classmethod
    def build_no_permission_sets_view(cls, view_blocks: list) -> View:
        """Build view with warning and disabled submit button."""
        view = cls.build()
        view.submit_disabled = True  # type: ignore[attr-defined]
        blocks = remove_blocks(
            view_blocks,
            block_ids=[
                cls.PERMISSION_SET_PLACEHOLDER_BLOCK_ID,
                cls.PERMISSION_SET_BLOCK_ID,
                cls.PERMISSION_SET_LOADING_BLOCK_ID,
                cls.APPROVERS_BLOCK_ID,
                cls.APPROVERS_LOADING_BLOCK_ID,
            ],
        )
        blocks = insert_blocks(
            blocks=blocks,
            blocks_to_insert=[cls.build_no_permission_sets_block()],
            after_block_id=cls.ACCOUNT_BLOCK_ID,
        )
        view.blocks = blocks
        return view

    @classmethod
    def parse(cls, obj: dict) -> RequestForAccess:
        values = jp.search("view.state.values", obj)
        hhmm = jp.search(f"{cls.DURATION_BLOCK_ID}.{cls.DURATION_ACTION_ID}.selected_option.value", values)
        hours, minutes = map(int, hhmm.split(":"))
        duration = timedelta(hours=hours, minutes=minutes)
        return RequestForAccess.model_validate(
            {
                "permission_duration": duration,
                "permission_set_name": jp.search(
                    f"{cls.PERMISSION_SET_BLOCK_ID}.{cls.PERMISSION_SET_ACTION_ID}.selected_option.value", values
                ),
                "account_id": jp.search(f"{cls.ACCOUNT_BLOCK_ID}.{cls.ACCOUNT_ACTION_ID}.selected_options[0].value", values),
                "reason": jp.search(f"{cls.REASON_BLOCK_ID}.{cls.REASON_ACTION_ID}.value", values),
                "requester_slack_id": jp.search("user.id", obj),
            }
        )

    @classmethod
    def parse_multi(cls, obj: dict) -> list[RequestForAccess]:
        """Parse submission into one RequestForAccess per selected account."""
        values = jp.search("view.state.values", obj)
        hhmm = jp.search(f"{cls.DURATION_BLOCK_ID}.{cls.DURATION_ACTION_ID}.selected_option.value", values)
        hours, minutes = map(int, hhmm.split(":"))
        duration = timedelta(hours=hours, minutes=minutes)

        permission_set_name = jp.search(f"{cls.PERMISSION_SET_BLOCK_ID}.{cls.PERMISSION_SET_ACTION_ID}.selected_option.value", values)
        if permission_set_name is None:
            logger.warning("Modal submitted without a permission set selected, ignoring")
            return []
        reason = jp.search(f"{cls.REASON_BLOCK_ID}.{cls.REASON_ACTION_ID}.value", values)
        requester_slack_id = jp.search("user.id", obj)

        selected_options = jp.search(f"{cls.ACCOUNT_BLOCK_ID}.{cls.ACCOUNT_ACTION_ID}.selected_options", values) or []

        return [
            RequestForAccess(
                permission_duration=duration,
                permission_set_name=permission_set_name,
                account_id=opt["value"],
                reason=reason,
                requester_slack_id=requester_slack_id,
            )
            for opt in selected_options
        ]


T = TypeVar("T", Block, dict)


def get_block_id(block: Union[Block, dict]) -> Optional[str]:
    return block["block_id"] if isinstance(block, dict) else block.block_id


def remove_blocks(blocks: list[T], block_ids: list[str]) -> list[T]:
    return [block for block in blocks if get_block_id(block) not in block_ids]


def insert_blocks(blocks: list[T], blocks_to_insert: list[Block], after_block_id: str) -> list[T]:
    index = next(i for i, block in enumerate(blocks) if get_block_id(block) == after_block_id)
    return blocks[: index + 1] + blocks_to_insert + blocks[index + 1 :]  # type: ignore


def humanize_timedelta(td: timedelta) -> str:
    # 1d 12h 0m
    total_hours = td.days * 24 + td.seconds // 3600
    minutes = (td.seconds % 3600) // 60

    if total_hours < 24:  # noqa: PLR2004
        return f"{total_hours}h {minutes}m"
    days = total_hours // 24
    hours = total_hours % 24
    if hours > 0 or minutes > 0:
        return f"{days}d {hours}h {minutes}m"
    else:
        return f"{days}d"


def unhumanize_timedelta(td_str: str) -> timedelta:
    days, hours, minutes = 0, 0, 0
    components = td_str.split()
    for component in components:
        if "d" in component:
            days = int(component.removesuffix("d"))
        elif "h" in component:
            hours = int(component.removesuffix("h"))
        elif "m" in component:
            minutes = int(component.removesuffix("m"))
    total_hours = days * 24 + hours
    return timedelta(hours=total_hours, minutes=minutes)


def build_approval_request_message_blocks(  # noqa: PLR0913
    requester_slack_id: str,
    slack_client: WebClient,
    sso_client: SSOAdminClient,
    identity_store_client: IdentityStoreClient,
    permission_duration: timedelta,
    reason: str,
    status_text: str,
    account: Optional[entities.aws.Account] = None,
    group: Optional[entities.aws.SSOGroup] = None,
    role_name: Optional[str] = None,
    show_buttons: bool = True,
) -> list[Block]:
    fields = [
        MarkdownTextObject(text=f"*Requester*\n<@{requester_slack_id}>"),
    ]

    if group:
        fields.append(MarkdownTextObject(text=f"*Group*\n{group.name} ({group.id})"))
    elif account and role_name:
        fields.append(MarkdownTextObject(text=f"*Account*\n{account.name} ({account.id})"))
        fields.append(MarkdownTextObject(text=f"*Permission Set*\n{role_name}"))

    fields.append(MarkdownTextObject(text=f"*Duration*\n{humanize_timedelta(permission_duration)}"))
    fields.append(MarkdownTextObject(text=f"*Reason*\n{reason}"))

    _, secondary_domain_was_used = sso.get_user_principal_id_by_email(
        identity_store_client=identity_store_client,
        identity_store_id=sso.get_identity_store_id(cfg, sso_client),
        email=get_user(slack_client, id=requester_slack_id).email,
        cfg=cfg,
    )

    if secondary_domain_was_used:
        fields.append(
            MarkdownTextObject(
                text=(
                    ":warning: *Attention: Secondary Domain Fallback Used*\n"
                    "The requester's Slack email did not match any AWS SSO user.\n"
                    "A secondary fallback domain was used to locate the user in AWS SSO.\n"
                    "Proceed with caution and consider verifying the user's identity to mitigate potential security risks.\n"
                    "We do not recommend relying on this feature."
                )
            )
        )

    blocks: list[Block] = [
        HeaderSectionBlock.new(status_text),
        SectionBlock(block_id="content", fields=fields),
    ]
    if show_buttons:
        blocks.append(
            ActionsBlock(
                block_id="buttons",
                elements=[
                    ButtonElement(
                        action_id=entities.ApproverAction.Approve.value,
                        text=PlainTextObject(text="Approve"),
                        style="primary",
                        value=entities.ApproverAction.Approve.value,
                    ),
                    ButtonElement(
                        action_id=entities.ApproverAction.Deny.value,
                        text=PlainTextObject(text="Deny"),
                        style="danger",
                        value=entities.ApproverAction.Deny.value,
                    ),
                ],
            )
        )
    return blocks


class HeaderSectionBlock:
    block_id = "header"

    @classmethod
    def new(cls, status_text: str) -> SectionBlock:
        return SectionBlock(block_id=cls.block_id, text=MarkdownTextObject(text=status_text))

    @staticmethod
    def set_status(blocks: list[dict], status_text: str) -> list[dict]:
        blocks = remove_blocks(blocks, block_ids=[HeaderSectionBlock.block_id])
        b = HeaderSectionBlock.new(status_text)
        blocks.insert(0, b.to_dict())
        return blocks


def button_click_info_block(action: entities.ApproverAction, approver_slack_id: str) -> SectionBlock:
    return footer_info_block(f"<@{approver_slack_id}> pressed {action.value} button")


def footer_info_block(text: str) -> SectionBlock:
    return SectionBlock(block_id="footer", text=MarkdownTextObject(text=text))


def check_if_user_is_in_channel(client: WebClient, channel_id: str, user_id: str) -> bool:
    logger.info(f"Checking if user {user_id} is in channel {channel_id}")

    response = client.conversations_members(channel=channel_id)

    members = jp.search("members", response.data)
    logger.debug(f"Members in channel {channel_id}: {members}")
    return user_id in members


class ButtonClickedPayload(BaseModel):
    action: entities.ApproverAction
    approver_slack_id: str
    thread_ts: str
    channel_id: str
    message: dict
    request: RequestForAccess

    @model_validator(mode="before")
    @classmethod
    def validate_payload(cls, values: dict) -> dict:  # noqa: ANN101
        message = values["message"]
        fields = jp.search("message.blocks[?block_id == 'content'].fields[]", values)
        requester_mention = cls.find_in_fields(fields, "Requester")
        requester_slack_id = requester_mention.removeprefix("<@").removesuffix(">")
        humanized_permission_duration = cls.find_in_fields(fields, "Duration")
        permission_duration = unhumanize_timedelta(humanized_permission_duration)
        account = cls.find_in_fields(fields, "Account")
        account_id = account.split("(")[-1].rstrip(")")
        return {
            "action": jp.search("actions[0].value", values),
            "approver_slack_id": jp.search("user.id", values),
            "thread_ts": jp.search("message.ts", values),
            "channel_id": jp.search("channel.id", values),
            "message": message,
            "request": RequestForAccess(
                requester_slack_id=requester_slack_id,
                account_id=account_id,
                permission_set_name=cls.find_in_fields(fields, "Permission Set"),
                reason=cls.find_in_fields(fields, "Reason"),
                permission_duration=permission_duration,
            ),
        }

    @staticmethod
    def find_in_fields(fields: list[dict[str, str]], key: str) -> str:
        for field in fields:
            if field["text"].startswith(f"*{key}*"):
                return field["text"].split("\n", 1)[1].strip()
        raise ValueError(f"Failed to parse message. Could not find {key} in fields: {fields}")


def parse_user(user: dict) -> entities.slack.User:
    return entities.slack.User.model_validate(
        {"id": jp.search("user.id", user), "email": jp.search("user.profile.email", user), "real_name": jp.search("user.real_name", user)}
    )


def get_user(client: WebClient, id: str) -> entities.slack.User:
    response = client.users_info(user=id)
    return parse_user(response.data)  # type: ignore


def get_user_by_email(client: WebClient, email: str) -> entities.slack.User:
    logger.info(f"Getting slack user by email: {email}")
    start = datetime.datetime.now(timezone.utc)
    timeout_seconds = 30
    try:
        r = client.users_lookupByEmail(email=email)
        logger.info(f"Slack user found: {r}")
        return parse_user(r.data)  # type: ignore
    except slack_sdk.errors.SlackApiError as e:
        if e.response["error"] == "ratelimited":
            if datetime.datetime.now(timezone.utc) - start >= datetime.timedelta(seconds=timeout_seconds):
                raise e
            logger.info(f"Rate limited when getting slack user by email. Sleeping for 3 seconds. {e}")
            time.sleep(3)
            return get_user_by_email(client, email)
        else:
            logger.error(f"Error when getting slack user by email. {e}")
            raise e
    except Exception as e:
        raise e


def remove_buttons_from_message_blocks(
    slack_message_blocks: list[Block],
    action: entities.ApproverAction,
    approver: entities.slack.User,
) -> list[Block]:
    blocks = remove_blocks(slack_message_blocks, block_ids=["buttons"])
    blocks.append(button_click_info_block(action, approver.id))
    return blocks


def create_slack_mention_by_principal_id(
    sso_user_id: str,
    sso_client: SSOAdminClient,
    cfg: config.Config,
    identitystore_client: IdentityStoreClient,
    slack_client: WebClient,
) -> str:
    identity_store_id = sso.get_identity_store_id(cfg, sso_client)
    aws_user_emails = sso.get_user_emails(
        identitystore_client,
        identity_store_id,
        sso_user_id,
    )
    user_name = None

    for email in aws_user_emails:
        try:
            slack_user = get_user_by_email(slack_client, email)
            user_name = slack_user.real_name
        except Exception as e:
            logger.info(f"Failed to get slack user by email {email}. {e}")
            continue

    return f"{user_name}" if user_name is not None else aws_user_emails[0]


def get_message_from_timestamp(channel_id: str, message_ts: str, slack_client: slack_sdk.WebClient) -> dict | None:
    response = slack_client.conversations_history(channel=channel_id)

    if response["ok"]:
        messages = response.get("messages")
        if messages is not None:
            for message in messages:
                if "ts" in message and message["ts"] == message_ts:
                    return message

    return None


def delete_early_revoke_button(client: WebClient, channel_id: str, thread_ts: str) -> bool:
    """Find and delete the early revoke button message in a thread."""
    try:
        result = client.conversations_replies(channel=channel_id, ts=thread_ts)
        for msg in result.get("messages", []):
            blocks = msg.get("blocks", [])
            if any(b.get("block_id") == "early_revoke_button" for b in blocks):
                client.chat_delete(channel=channel_id, ts=msg["ts"])
                return True
    except slack_sdk.errors.SlackApiError as e:
        logger.warning(f"Failed to delete early revoke button: {e}")
    return False


# Plain text object supports only 99 options
# https://github.com/fivexl/terraform-aws-sso-elevator/issues/110
def get_max_duration_block(cfg: config.Config) -> list[Option]:
    if cfg.permission_duration_list_override:
        elements = cfg.permission_duration_list_override
        if len(elements) > 100:  # noqa: PLR2004
            elements = elements[:99] + elements[-1:]
        return [Option(text=PlainTextObject(text=s), value=s) for s in elements]
    else:
        base_durations = [0.25, 0.5, 1, 2, 4, 8, 12, 24]  # hours
        max_hours = cfg.max_permissions_duration_time

        # Filter to max, add max if not present
        durations = [d for d in base_durations if d <= max_hours]
        if max_hours not in durations:
            durations.append(max_hours)
            durations.sort()

        def format_display(hours: float) -> str:
            """Human-readable: '15 min', '1 hour', '2 hours'"""
            if hours < 1:
                return f"{int(hours * 60)} min"
            elif hours == 1:
                return "1 hour"
            else:
                return f"{int(hours)} hours"

        def format_value(hours: float) -> str:
            """HH:MM for backend parsing"""
            h = int(hours)
            m = int((hours - h) * 60)
            return f"{h:02d}:{m:02d}"

        return [Option(text=PlainTextObject(text=format_display(d)), value=format_value(d)) for d in durations]


def find_approvers_in_slack(client: WebClient, approver_emails: list[str]) -> tuple[list[entities.slack.User], list[str]]:
    approvers = []
    approver_emails_not_found = []

    for email in approver_emails:
        try:
            approver = get_user_by_email(client, email)
            approvers.append(approver)
        except Exception:
            logger.warning(f"Approver with email {email} not found in Slack")
            approver_emails_not_found.append(email)

    return approvers, approver_emails_not_found


def get_usergroup_members(client: WebClient, usergroup_id: str) -> list[str]:
    """Get list of user IDs in a Slack usergroup.

    Args:
        client: Slack WebClient
        usergroup_id: Slack usergroup ID (e.g., 'SAZ94GDB8')

    Returns:
        List of Slack user IDs in the group
    """
    logger.info(f"Getting members of Slack usergroup: {usergroup_id}")
    deadline = datetime.datetime.now(timezone.utc) + datetime.timedelta(seconds=30)

    while True:
        try:
            response = client.usergroups_users_list(usergroup=usergroup_id)
            users = response.get("users", [])
            logger.info(f"Found {len(users)} members in usergroup {usergroup_id}")
            return users
        except slack_sdk.errors.SlackApiError as e:
            if e.response["error"] == "ratelimited":
                if datetime.datetime.now(timezone.utc) >= deadline:
                    logger.error(f"Timeout after rate limiting when getting usergroup {usergroup_id}")
                    raise e
                logger.info(f"Rate limited when getting usergroup members. Sleeping for 3 seconds. {e}")
                time.sleep(3)
                continue
            elif e.response["error"] == "no_such_subteam":
                logger.warning(f"Slack usergroup {usergroup_id} not found")
                return []
            else:
                logger.error(f"Error when getting usergroup members: {e}")
                raise e


def resolve_approver_groups(client: WebClient, group_ids: frozenset[str]) -> tuple[list[entities.slack.User], list[str]]:
    """Resolve Slack usergroup IDs to User objects.

    Args:
        client: Slack WebClient
        group_ids: Set of Slack usergroup IDs

    Returns:
        Tuple of (list of User objects, list of group IDs that could not be resolved)
    """
    users: list[entities.slack.User] = []
    seen_user_ids: set[str] = set()
    failed_groups: list[str] = []

    for group_id in group_ids:
        try:
            member_ids = get_usergroup_members(client, group_id)
            # Empty groups are valid - they just don't contribute any users
            # Only treat as failure if get_usergroup_members raises an exception
            if not member_ids:
                logger.info(f"Usergroup {group_id} has no members")
                continue

            for user_id in member_ids:
                if user_id in seen_user_ids:
                    continue
                try:
                    response = client.users_info(user=user_id)
                    user_data = (response.data or {}).get("user", {}) if isinstance(response.data, dict) else {}
                    if user_data.get("is_bot") or user_data.get("is_app_user") or user_data.get("deleted"):
                        seen_user_ids.add(user_id)
                        continue
                    users.append(parse_user(response.data))  # type: ignore[arg-type]
                    seen_user_ids.add(user_id)
                except Exception as e:
                    logger.warning(f"Failed to get user info for {user_id}: {e}")
        except Exception as e:
            logger.warning(f"Failed to resolve usergroup {group_id}: {e}")
            failed_groups.append(group_id)

    return users, failed_groups


def build_approver_group_mentions(group_ids: frozenset[str]) -> str:
    """Build Slack mention string for usergroups.

    Uses <!subteam^GROUP_ID> format which shows as @group-name in Slack
    and notifies all group members.

    Args:
        group_ids: Set of Slack usergroup IDs

    Returns:
        Space-separated string of group mentions
    """
    return " ".join(f"<!subteam^{group_id}>" for group_id in group_ids)


def build_approvers_preview_text(
    client: WebClient,
    decisions: list,
    email_cache: dict[str, str] | None = None,
) -> str:
    """Build the markdown text shown in the approver-preview ContextBlock.

    Accepts one or more `access_control.AccessRequestDecision` instances and
    unions their approvers/approver_groups for the preview. Decisions argument
    is typed as list to avoid a circular import on access_control.
    """
    import access_control  # local to avoid module-level circular import

    if not decisions:
        return ":warning: No approvers configured for this request."

    reasons = {d.reason for d in decisions}

    if all(d.grant for d in decisions):
        if reasons == {access_control.DecisionReason.SelfApproval}:
            return ":white_check_mark: *You can self-approve* — request will be granted automatically."
        return ":white_check_mark: *Auto-approved* — no approval needed."

    all_emails: set[str] = set()
    all_groups: set[str] = set()
    for d in decisions:
        if d.grant:
            continue
        all_emails.update(d.approvers)
        all_groups.update(d.approver_groups)

    if not all_emails and not all_groups:
        return ":warning: No approvers configured for this request."

    mentions, unresolved = format_approver_mentions(
        client=client,
        approver_emails=frozenset(all_emails),
        approver_group_ids=frozenset(all_groups),
        email_cache=email_cache,
        separator=", ",
    )

    if not mentions:
        return ":warning: No approvers configured for this request."

    text = f":information_source: _This request can be approved by_ _{mentions}_"
    if unresolved:
        missing = ", ".join(unresolved)
        text += f"\n_(could not match in Slack: {missing})_"
    return text


def format_approver_mentions(
    client: WebClient,
    approver_emails: frozenset[str] | set[str] | list[str],
    approver_group_ids: frozenset[str],
    email_cache: dict[str, str] | None = None,
    separator: str = " ",
) -> tuple[str, list[str]]:
    """Format approver emails + Slack usergroup IDs into a Slack mention string.

    Args:
        client: Slack WebClient.
        approver_emails: Approver emails to resolve to Slack users.
        approver_group_ids: Slack usergroup IDs (formatted as <!subteam^…>).
        email_cache: Optional dict mapping email → Slack user ID. Cached entries
            skip the users_lookupByEmail call; new resolutions are written back.
        separator: String inserted between mentions. Default " " for channel pings,
            ", " for the in-modal preview.

    Returns:
        (mention_str, unresolved_emails)
    """
    emails = list(approver_emails)
    user_mentions: list[str] = []
    unresolved: list[str] = []

    for email in emails:
        cached_id = email_cache.get(email) if email_cache is not None else None
        if cached_id:
            user_mentions.append(f"<@{cached_id}>")
            continue
        try:
            user = get_user_by_email(client, email)
        except Exception:
            logger.warning(f"Approver with email {email} not found in Slack")
            unresolved.append(email)
            continue
        user_mentions.append(f"<@{user.id}>")
        if email_cache is not None:
            email_cache[email] = user.id

    group_mentions = [f"<!subteam^{gid}>" for gid in approver_group_ids]
    mention_str = separator.join(filter(None, user_mentions + group_mentions))
    return mention_str, unresolved


# Group
# -----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----
# -----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----
# -----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----
# -----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----
# -----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----
# -----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----#-----


class EarlyRevokeButtonPayload(BaseModel):
    """Payload for early revoke button click."""

    schedule_name: str
    requester_slack_id: str
    account_id: Optional[str] = None
    permission_set_name: Optional[str] = None
    permission_set_arn: Optional[str] = None
    instance_arn: Optional[str] = None
    user_principal_id: str
    # For group access
    group_id: Optional[str] = None
    group_name: Optional[str] = None
    identity_store_id: Optional[str] = None
    membership_id: Optional[str] = None
    # For looking up approvers
    approver_emails: list[str] = []
    approver_groups: list[str] = []

    @model_validator(mode="before")
    @classmethod
    def parse_json_value(cls, values: dict) -> dict:
        # When receiving from button click, value comes as JSON string
        if isinstance(values, str):
            import json

            return json.loads(values)
        return values


def build_early_revoke_button(payload: EarlyRevokeButtonPayload) -> ActionsBlock:
    """Build an 'End session early' button for the approval thread."""
    import json

    return ActionsBlock(
        block_id="early_revoke_button",
        elements=[
            ButtonElement(
                action_id=entities.ApproverAction.EarlyRevoke.value,
                text=PlainTextObject(text="End session early"),
                value=json.dumps(payload.model_dump(mode="json")),
            ),
        ],
    )


class ExtendGrantButtonPayload(BaseModel):
    """Payload for extend grant button click."""

    requester_slack_id: str
    expired_at: str  # ISO timestamp
    extension_duration_in_minutes: int
    extensions_count: int
    # Account fields
    account_id: Optional[str] = None
    permission_set_name: Optional[str] = None
    permission_set_arn: Optional[str] = None
    instance_arn: Optional[str] = None
    user_principal_id: str = ""
    account_name: Optional[str] = None
    # Group fields
    group_id: Optional[str] = None
    group_name: Optional[str] = None
    identity_store_id: Optional[str] = None
    # Approver/requester info for scheduling
    approver: Optional[dict] = None
    requester: Optional[dict] = None

    @model_validator(mode="before")
    @classmethod
    def parse_json_value(cls, values: dict) -> dict:
        if isinstance(values, str):
            import json

            return json.loads(values)
        return values


def build_extend_grant_button(payload: ExtendGrantButtonPayload) -> ActionsBlock:
    """Build an 'Extend access' button for the approval thread."""
    import json

    return ActionsBlock(
        block_id="extend_grant_button",
        elements=[
            ButtonElement(
                action_id=entities.ApproverAction.ExtendGrant.value,
                text=PlainTextObject(text=f"Extend access ({payload.extension_duration_in_minutes} min)"),
                value=json.dumps(payload.model_dump(mode="json")),
            ),
        ],
    )


def delete_extend_grant_button(client: WebClient, channel_id: str, thread_ts: str) -> bool:
    """Find and delete the extend grant button message in a thread."""
    try:
        result = client.conversations_replies(channel=channel_id, ts=thread_ts)
        for msg in result.get("messages", []):
            blocks = msg.get("blocks", [])
            if any(b.get("block_id") == "extend_grant_button" for b in blocks):
                client.chat_delete(channel=channel_id, ts=msg["ts"])
                return True
    except slack_sdk.errors.SlackApiError as e:
        logger.warning(f"Failed to delete extend grant button: {e}")
    return False


class EarlyRevokeModal:
    """Modal view for early revocation with optional reason field."""

    CALLBACK_ID = "early_revoke_modal"
    REASON_BLOCK_ID = "early_revoke_reason"
    REASON_ACTION_ID = "early_revoke_reason_input"

    @classmethod
    def build(  # noqa: PLR0913
        cls,
        account_name: Optional[str] = None,
        account_id: Optional[str] = None,
        permission_set_name: Optional[str] = None,
        group_name: Optional[str] = None,
        group_id: Optional[str] = None,
        private_metadata: str = "",
    ) -> View:
        """Build the early revoke modal view."""
        if account_name and account_id and permission_set_name:
            context_text = f"*Account:* {account_name} ({account_id})\n*Role:* {permission_set_name}"
        elif group_name and group_id:
            context_text = f"*Group:* {group_name} ({group_id})"
        else:
            context_text = "Access details unavailable"

        return View(
            type="modal",
            callback_id=cls.CALLBACK_ID,
            private_metadata=private_metadata,
            submit=PlainTextObject(text="Revoke"),
            close=PlainTextObject(text="Cancel"),
            title=PlainTextObject(text="Revoke Access Early"),
            blocks=[
                SectionBlock(
                    block_id="context",
                    text=MarkdownTextObject(text="You are about to revoke access to:"),
                ),
                SectionBlock(
                    block_id="details",
                    text=MarkdownTextObject(text=context_text),
                ),
                DividerBlock(),
                InputBlock(
                    block_id=cls.REASON_BLOCK_ID,
                    optional=True,
                    label=PlainTextObject(text="Reason"),
                    element=PlainTextInputElement(
                        action_id=cls.REASON_ACTION_ID,
                        placeholder=PlainTextObject(text="e.g. Task completed, no longer needed"),
                        multiline=True,
                    ),
                ),
            ],
        )


class EarlyRevokeModalPayload(BaseModel):
    """Payload parsed from early revoke modal submission."""

    revoker_slack_id: str
    reason: Optional[str] = None
    button_payload: EarlyRevokeButtonPayload
    channel_id: str
    thread_ts: str

    @model_validator(mode="before")
    @classmethod
    def parse_view_submission(cls, values: dict) -> dict:
        import json

        # Parse reason from view state
        view_state = jp.search("view.state.values", values) or {}
        reason = jp.search(
            f"{EarlyRevokeModal.REASON_BLOCK_ID}.{EarlyRevokeModal.REASON_ACTION_ID}.value",
            view_state,
        )

        # Parse button payload from private_metadata
        private_metadata = jp.search("view.private_metadata", values) or "{}"
        metadata = json.loads(private_metadata)

        return {
            "revoker_slack_id": jp.search("user.id", values),
            "reason": reason,
            "button_payload": EarlyRevokeButtonPayload.model_validate(metadata.get("button_payload", {})),
            "channel_id": metadata.get("channel_id", ""),
            "thread_ts": metadata.get("thread_ts", ""),
        }


class RequestForGroupAccess(entities.BaseModel):
    group_id: str
    reason: str
    requester_slack_id: str
    permission_duration: timedelta


class RequestForGroupAccessView:
    __name__ = "RequestForGroupAccessView"
    CALLBACK_ID = "request_for_group_access_submitted"

    REASON_BLOCK_ID = "provide_reason"
    REASON_ACTION_ID = "provided_reason"

    GROUP_BLOCK_ID = "select_group"
    GROUP_ACTION_ID = "selected_group"

    DURATION_BLOCK_ID = "duration_picker"
    DURATION_ACTION_ID = "duration_picker_action"

    LOADING_BLOCK_ID = "loading"

    APPROVERS_BLOCK_ID = "approvers_preview"
    APPROVERS_LOADING_BLOCK_ID = "approvers_preview_loading"

    @classmethod
    def build(cls) -> View:  # noqa: ANN102
        return View(
            type="modal",
            callback_id=cls.CALLBACK_ID,
            submit=PlainTextObject(text="Request"),
            close=PlainTextObject(text="Cancel"),
            title=PlainTextObject(text="Request Group Access"),
            blocks=[
                SectionBlock(
                    block_id=cls.DURATION_BLOCK_ID,
                    text=MarkdownTextObject(text="How long do you need access?"),
                    accessory=StaticSelectElement(
                        action_id=cls.DURATION_ACTION_ID,
                        initial_option=get_max_duration_block(cfg)[0],
                        options=get_max_duration_block(cfg),
                        placeholder=PlainTextObject(text="Select duration"),
                    ),
                ),
                InputBlock(
                    block_id=cls.REASON_BLOCK_ID,
                    label=PlainTextObject(text="Reason for access"),
                    element=PlainTextInputElement(
                        action_id=cls.REASON_ACTION_ID,
                        placeholder=PlainTextObject(text="What will this access be used for?"),
                        multiline=True,
                    ),
                ),
                DividerBlock(),
                SectionBlock(
                    text=MarkdownTextObject(
                        text="All AWS API calls are logged for security compliance.",
                    ),
                ),
                SectionBlock(
                    block_id=cls.LOADING_BLOCK_ID,
                    text=MarkdownTextObject(
                        text=":hourglass: Loading available groups...",
                    ),
                ),
            ],
        )

    @classmethod
    def update_with_groups(cls, groups: list[entities.aws.SSOGroup]) -> View:  # noqa: ANN102
        view = cls.build()
        view.blocks = remove_blocks(view.blocks, block_ids=[cls.LOADING_BLOCK_ID])
        view.blocks = insert_blocks(
            blocks=view.blocks,
            blocks_to_insert=[
                cls.build_select_group_input_block(groups),
            ],
            after_block_id=cls.REASON_BLOCK_ID,
        )
        return view

    @classmethod
    def build_select_group_input_block(cls, groups: list[entities.aws.SSOGroup]) -> InputBlock:  # noqa: ANN102
        # TODO: handle case when there are more than 100 groups
        # 99 is the limit for StaticSelectElement
        # https://slack.dev/python-slack-sdk/api-docs/slack_sdk/models/blocks/block_elements.html#:~:text=StaticSelectElement(InputInteractiveElement)%3A%0A%20%20%20%20type%20%3D%20%22static_select%22-,options_max_length%20%3D%20100,-option_groups_max_length%20%3D%20100%0A%0A%20%20%20%20%40property%0A%20%20%20%20def%20attributes(
        if len(groups) > 99:  # noqa: PLR2004
            groups = groups[:99]
        sorted_groups = sorted(groups, key=lambda groups: groups.name)
        return InputBlock(
            block_id=cls.GROUP_BLOCK_ID,
            dispatch_action=True,
            label=PlainTextObject(text="SSO Group"),
            element=StaticSelectElement(
                action_id=cls.GROUP_ACTION_ID,
                placeholder=PlainTextObject(text="Select group"),
                options=[Option(text=PlainTextObject(text=f"{group.name}"), value=group.id) for group in sorted_groups],
            ),
        )

    @classmethod
    def build_approvers_preview_block(cls, text: str) -> ContextBlock:  # noqa: ANN102
        return ContextBlock(
            block_id=cls.APPROVERS_BLOCK_ID,
            elements=[MarkdownTextObject(text=text)],
        )

    @classmethod
    def build_approvers_loading_block(cls) -> ContextBlock:  # noqa: ANN102
        return ContextBlock(
            block_id=cls.APPROVERS_LOADING_BLOCK_ID,
            elements=[MarkdownTextObject(text=":hourglass: Resolving approvers...")],
        )

    @classmethod
    def show_approvers_loading(cls, view_blocks: list) -> View:  # noqa: ANN102
        view = cls.build()
        blocks = remove_blocks(view_blocks, block_ids=[cls.APPROVERS_BLOCK_ID, cls.APPROVERS_LOADING_BLOCK_ID, cls.LOADING_BLOCK_ID])
        blocks = insert_blocks(
            blocks=blocks,
            blocks_to_insert=[cls.build_approvers_loading_block()],
            after_block_id=cls.GROUP_BLOCK_ID,
        )
        view.blocks = blocks
        return view

    @classmethod
    def update_with_approvers(cls, view_blocks: list, text: str) -> View:  # noqa: ANN102
        view = cls.build()
        blocks = remove_blocks(view_blocks, block_ids=[cls.APPROVERS_BLOCK_ID, cls.APPROVERS_LOADING_BLOCK_ID, cls.LOADING_BLOCK_ID])
        blocks = insert_blocks(
            blocks=blocks,
            blocks_to_insert=[cls.build_approvers_preview_block(text)],
            after_block_id=cls.GROUP_BLOCK_ID,
        )
        view.blocks = blocks
        return view

    @classmethod
    def parse(cls, obj: dict) -> RequestForGroupAccess:  # noqa: ANN102
        values = jp.search("view.state.values", obj)
        hhmm = jp.search(f"{cls.DURATION_BLOCK_ID}.{cls.DURATION_ACTION_ID}.selected_option.value", values)
        hours, minutes = map(int, hhmm.split(":"))
        duration = timedelta(hours=hours, minutes=minutes)
        return RequestForGroupAccess.model_validate(
            {
                "permission_duration": duration,
                "group_id": jp.search(f"{cls.GROUP_BLOCK_ID}.{cls.GROUP_ACTION_ID}.selected_option.value", values),
                "reason": jp.search(f"{cls.REASON_BLOCK_ID}.{cls.REASON_ACTION_ID}.value", values),
                "requester_slack_id": jp.search("user.id", obj),
            }
        )


class ButtonGroupClickedPayload(BaseModel):
    action: entities.ApproverAction
    approver_slack_id: str
    thread_ts: str
    channel_id: str
    message: dict
    request: RequestForGroupAccess

    @model_validator(mode="before")
    @classmethod
    def validate_payload(cls, values: dict) -> dict:  # noqa: ANN101
        message = values["message"]
        fields = jp.search("message.blocks[?block_id == 'content'].fields[]", values)
        requester_mention = cls.find_in_fields(fields, "Requester")
        requester_slack_id = requester_mention.removeprefix("<@").removesuffix(">")
        humanized_permission_duration = cls.find_in_fields(fields, "Duration")
        permission_duration = unhumanize_timedelta(humanized_permission_duration)
        group = cls.find_in_fields(fields, "Group")
        group_id = group.split("(")[-1].rstrip(")")
        return {
            "action": jp.search("actions[0].value", values),
            "approver_slack_id": jp.search("user.id", values),
            "thread_ts": jp.search("message.ts", values),
            "channel_id": jp.search("channel.id", values),
            "message": message,
            "request": RequestForGroupAccess(
                requester_slack_id=requester_slack_id,
                group_id=group_id,
                reason=cls.find_in_fields(fields, "Reason"),
                permission_duration=permission_duration,
            ),
        }

    @staticmethod
    def find_in_fields(fields: list[dict[str, str]], key: str) -> str:
        for field in fields:
            if field["text"].startswith(f"*{key}*"):
                return field["text"].split("\n", 1)[1].strip()
        raise ValueError(f"Failed to parse message. Could not find {key} in fields: {fields}")
