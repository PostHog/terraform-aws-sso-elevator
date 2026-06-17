import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import botocore.exceptions
import jmespath as jp
import slack_sdk
from croniter import croniter
from mypy_boto3_events import EventBridgeClient
from mypy_boto3_events import type_defs as events_type_defs
from mypy_boto3_scheduler import EventBridgeSchedulerClient
from mypy_boto3_scheduler import type_defs as scheduler_type_defs
from pydantic import ValidationError

import config
import entities
import errors
import slack_helpers
import sso
from events import (
    ApproverNotificationEvent,
    DiscardButtonsEvent,
    Event,
    GroupRevokeEvent,
    RevokeEvent,
    ScheduledRevokeEvent,
    ScheduledGroupRevokeEvent,
)

logger = config.get_logger(service="schedule")
cfg = config.get_config()

# Revoke schedules use ActionAfterCompletion=NONE so they persist after firing until the
# revoker explicitly deletes them post-revocation. EventBridge's previous auto-delete on
# fire raced with the revoker's ~30-50s cold-start + SSO API latency, producing false
# "inconsistent assignment" alerts. A schedule whose at() time is past by more than this
# grace period is treated as stuck (Lambda timed out / OOM'd / permanently failed) and
# excluded from matching so the inconsistency check / daily sweep can act on it.
_FIRED_SCHEDULE_GRACE_PERIOD = timedelta(minutes=10)


def _is_at_schedule_still_in_flight(schedule_expression: str) -> bool:
    if not schedule_expression.startswith("at("):
        return True
    try:
        at_time = datetime.fromisoformat(schedule_expression[3:-1]).replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return at_time >= datetime.now(timezone.utc) - _FIRED_SCHEDULE_GRACE_PERIOD


def get_event_bridge_rule(event_bridge_client: EventBridgeClient, rule_name: str) -> events_type_defs.DescribeRuleResponseTypeDef:
    return event_bridge_client.describe_rule(Name=rule_name)


# DEPRECATED: Use get_event_bridge_rule instead. This function contains a typo and will be removed in a future version.
def get_event_brige_rule(event_brige_client: EventBridgeClient, rule_name: str) -> events_type_defs.DescribeRuleResponseTypeDef:
    return get_event_bridge_rule(event_brige_client, rule_name)


def get_next_cron_run_time(cron_expression: str, base_time: datetime) -> datetime:
    # Replace ? with * to comply with croniter
    cron_expression = cron_expression.replace("?", "*")
    cron_iter = croniter(cron_expression, base_time)
    next_run_time = cron_iter.get_next(datetime)
    logger.debug(f"Next run time: {next_run_time}")
    return next_run_time


def check_rule_expression_and_get_next_run(rule: events_type_defs.DescribeRuleResponseTypeDef) -> datetime | str:
    schedule_expression = rule["ScheduleExpression"]
    current_time = datetime.now(timezone.utc)
    logger.debug(f"Current time: {current_time}")
    logger.debug(f"Schedule expression: {schedule_expression}")

    if schedule_expression.startswith("rate"):
        return schedule_expression
    elif schedule_expression.startswith("cron"):
        clean_expression = schedule_expression.replace("cron(", "").replace(")", "")
        try:
            return get_next_cron_run_time(clean_expression, current_time)
        except Exception as e:
            logger.warning(f"Unable to parse cron expression: {clean_expression}", extra={"error": e})
            return schedule_expression
    else:
        raise ValueError("Unknown schedule expression format!")


def get_schedules(client: EventBridgeSchedulerClient) -> list[scheduler_type_defs.GetScheduleOutputTypeDef]:
    paginator = client.get_paginator("list_schedules")
    scheduled_events = []
    for page in paginator.paginate(GroupName=cfg.schedule_group_name):
        schedules_names = jp.search("Schedules[*].Name", page)
        for schedule_name in schedules_names:
            if not schedule_name:
                continue
            try:
                full_schedule = client.get_schedule(GroupName=cfg.schedule_group_name, Name=schedule_name)
            except botocore.exceptions.ClientError as e:
                # The schedule was deleted between list_schedules and this get_schedule call
                # (a revoker firing + deleting it, or a concurrent supersession). It no longer
                # exists, so skip it. Letting this propagate would abort — and roll back — an
                # unrelated, just-granted assignment whose scheduling triggered this enumeration.
                if errors.is_resource_not_found_exception(e):
                    logger.info("Schedule vanished during enumeration, skipping", extra={"schedule_name": schedule_name})
                    continue
                raise
            scheduled_events.append(full_schedule)
    return scheduled_events


def get_scheduled_events(client: EventBridgeSchedulerClient) -> list[ScheduledRevokeEvent | ScheduledGroupRevokeEvent]:
    scheduled_events = get_schedules(client)
    logger.debug("Scheduled events", extra={"scheduled_events": scheduled_events})
    scheduled_revoke_events: list[ScheduledRevokeEvent | ScheduledGroupRevokeEvent] = []
    for full_schedule in scheduled_events:
        if full_schedule["Name"].startswith("discard-buttons"):
            continue
        if not _is_at_schedule_still_in_flight(full_schedule.get("ScheduleExpression", "")):
            logger.warning(
                "Ignoring stuck past-due schedule",
                extra={"schedule_name": full_schedule["Name"], "schedule_expression": full_schedule.get("ScheduleExpression")},
            )
            continue

        event = json.loads(jp.search("Target.Input", full_schedule))

        try:
            event = Event.model_validate(event)
        except ValidationError as e:
            logger.warning("Got unexpected event", extra={"event": event, "error": e})
            continue

        if isinstance(event.root, ScheduledRevokeEvent):
            scheduled_revoke_events.append(event.root)
        elif isinstance(event.root, ScheduledGroupRevokeEvent):
            scheduled_revoke_events.append(event.root)
    logger.debug("Scheduled revoke events", extra={"scheduled_revoke_events": scheduled_revoke_events})
    return scheduled_revoke_events


def delete_schedule(client: EventBridgeSchedulerClient, schedule_name: str) -> None:
    try:
        client.delete_schedule(GroupName=cfg.schedule_group_name, Name=schedule_name)
        logger.info("Schedule deleted", extra={"schedule_name": schedule_name})
    except botocore.exceptions.ClientError as e:
        if jp.search("Error.Code", e.response) == "ResourceNotFoundException":
            logger.info("Schedule for deletion was not found", extra={"schedule_name": schedule_name})
        else:
            raise e


# AWS EventBridge schedule names: max 64 chars. `{prefix}{YYYY-MM-DD-HH-MM-SS}-{8-hex}`
# gives us a 48-char name for the longest existing prefix (`sso-elevator-revoker`).
def _build_schedule_name(prefix: str) -> str:
    return f"{prefix}{datetime.now(timezone.utc).strftime('%Y-%m-%d-%H-%M-%S')}-{uuid.uuid4().hex[:8]}"


_CREATE_SCHEDULE_MAX_ATTEMPTS = 3


def _create_schedule_with_retry(
    client: EventBridgeSchedulerClient,
    name_prefix: str,
    build_input: Callable[[str], str],
    create_kwargs: dict,
) -> tuple[Any, str]:
    """Create a schedule with a fresh random-suffixed name. Retry on ConflictException
    with a newly-rolled name. `build_input` is a callable that receives the generated
    schedule name and returns the JSON string for `Target.Input` — so the name embedded
    inside the payload matches the schedule name actually used."""
    last_error: Exception | None = None
    for attempt in range(1, _CREATE_SCHEDULE_MAX_ATTEMPTS + 1):
        schedule_name = _build_schedule_name(name_prefix)
        target = dict(create_kwargs["Target"])
        target["Input"] = build_input(schedule_name)
        call_kwargs = {**create_kwargs, "Name": schedule_name, "Target": target}
        try:
            result = client.create_schedule(**call_kwargs)
            return result, schedule_name
        except botocore.exceptions.ClientError as e:
            if jp.search("Error.Code", e.response) == "ConflictException":
                logger.warning(
                    "Schedule name collision, retrying with a fresh name",
                    extra={"schedule_name": schedule_name, "attempt": attempt},
                )
                last_error = e
                continue
            raise
    raise RuntimeError(
        f"Failed to create schedule after {_CREATE_SCHEDULE_MAX_ATTEMPTS} attempts due to repeated ConflictException"
    ) from last_error


def get_and_delete_scheduled_revoke_event_if_already_exist(
    client: EventBridgeSchedulerClient,
    event: sso.UserAccountAssignment | sso.GroupAssignment,
) -> list[str]:
    """Delete any existing scheduled revoke for this assignment.

    Returns the thread_ts of each orphaned grant message so the caller can flip its
    header to SUPERSEDED. The extend-grant flow reuses the original thread_ts, so the
    caller is expected to skip any orphan whose ts matches the new request's thread_ts.
    """
    orphaned_thread_ts: list[str] = []
    for scheduled_event in get_scheduled_events(client):
        logger.debug("Checking if schedule already exist", extra={"scheduled_event": scheduled_event})
        if isinstance(scheduled_event, ScheduledRevokeEvent) and scheduled_event.revoke_event.user_account_assignment == event:
            logger.info("Schedule already exist, deleting it", extra={"schedule_name": scheduled_event.revoke_event.schedule_name})
            delete_schedule(client, scheduled_event.revoke_event.schedule_name)
            if scheduled_event.revoke_event.thread_ts:
                orphaned_thread_ts.append(scheduled_event.revoke_event.thread_ts)
        if isinstance(scheduled_event, ScheduledGroupRevokeEvent) and scheduled_event.revoke_event.group_assignment == event:
            logger.info("Schedule already exist, deleting it", extra={"schedule_name": scheduled_event.revoke_event.schedule_name})
            delete_schedule(client, scheduled_event.revoke_event.schedule_name)
            if scheduled_event.revoke_event.thread_ts:
                orphaned_thread_ts.append(scheduled_event.revoke_event.thread_ts)
    return orphaned_thread_ts


def mark_superseded(slack_client: slack_sdk.WebClient, thread_ts: str) -> None:
    """Flip an orphaned grant message's header to SUPERSEDED and remove its early-revoke button.

    Called when a newer request replaces the schedule for the same assignment, leaving the
    old grant message with no revoker to update it on expiry.
    """
    message = slack_helpers.get_message_from_timestamp(
        channel_id=cfg.slack_channel_id,
        message_ts=thread_ts,
        slack_client=slack_client,
    )
    if message is None:
        logger.warning("Could not find orphaned grant message to mark superseded", extra={"thread_ts": thread_ts})
        return
    blocks = slack_helpers.HeaderSectionBlock.set_status(
        blocks=message["blocks"],
        status_text=cfg.superseded_status,
    )
    slack_client.chat_update(
        channel=cfg.slack_channel_id,
        ts=thread_ts,
        blocks=blocks,
        text="Superseded by newer request",
    )
    slack_helpers.delete_early_revoke_button(slack_client, cfg.slack_channel_id, thread_ts)


def event_bridge_schedule_after(td: timedelta) -> str:
    now = datetime.now(timezone.utc)
    return f"at({(now + td).replace(microsecond=0).isoformat().replace('+00:00', '')})"


def schedule_revoke_event(  # noqa: PLR0913
    schedule_client: EventBridgeSchedulerClient,
    permission_duration: timedelta,
    approver: entities.slack.User,
    requester: entities.slack.User,
    user_account_assignment: sso.UserAccountAssignment,
    slack_client: slack_sdk.WebClient,
    thread_ts: str | None = None,
    permission_set_name: str | None = None,
    account_name: str | None = None,
    can_extend_expired_grant: bool = False,
    extensions_count: int = 0,
) -> tuple[scheduler_type_defs.CreateScheduleOutputTypeDef, str]:
    """Schedule a revoke event.

    Returns:
        Tuple of (CreateScheduleOutput, schedule_name)
    """
    logger.info("Scheduling revoke event")
    orphaned_thread_ts = get_and_delete_scheduled_revoke_event_if_already_exist(schedule_client, user_account_assignment)
    for orphan_ts in orphaned_thread_ts:
        # Extend-grant flow reuses thread_ts — don't flip the message we're about to keep using.
        if orphan_ts == thread_ts:
            continue
        mark_superseded(slack_client, orphan_ts)

    def build_input(schedule_name: str) -> str:
        revoke_event = RevokeEvent(
            schedule_name=schedule_name,
            approver=approver,
            requester=requester,
            user_account_assignment=user_account_assignment,
            permission_duration=permission_duration,
            thread_ts=thread_ts,
            permission_set_name=permission_set_name,
            account_name=account_name,
            can_extend_expired_grant=can_extend_expired_grant,
            extensions_count=extensions_count,
        )
        logger.debug("Creating schedule", extra={"revoke_event": revoke_event})
        return json.dumps({"action": "event_bridge_revoke", "revoke_event": revoke_event.json()})

    return _create_schedule_with_retry(
        schedule_client,
        name_prefix=cfg.revoker_function_name,
        build_input=build_input,
        create_kwargs={
            "ActionAfterCompletion": "NONE",
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "GroupName": cfg.schedule_group_name,
            "ScheduleExpression": event_bridge_schedule_after(permission_duration),
            "State": "ENABLED",
            "Target": scheduler_type_defs.TargetTypeDef(
                Arn=cfg.revoker_function_arn,
                RoleArn=cfg.schedule_policy_arn,
                Input="",  # replaced by build_input
            ),
        },
    )


def schedule_group_revoke_event(  # noqa: PLR0913
    schedule_client: EventBridgeSchedulerClient,
    permission_duration: timedelta,
    approver: entities.slack.User,
    requester: entities.slack.User,
    group_assignment: sso.GroupAssignment,
    slack_client: slack_sdk.WebClient,
    thread_ts: str | None = None,
    can_extend_expired_grant: bool = False,
    extensions_count: int = 0,
) -> tuple[scheduler_type_defs.CreateScheduleOutputTypeDef, str]:
    """Schedule a group revoke event.

    Returns:
        Tuple of (CreateScheduleOutput, schedule_name)
    """
    logger.info("Scheduling revoke event")
    orphaned_thread_ts = get_and_delete_scheduled_revoke_event_if_already_exist(schedule_client, group_assignment)
    for orphan_ts in orphaned_thread_ts:
        if orphan_ts == thread_ts:
            continue
        mark_superseded(slack_client, orphan_ts)

    def build_input(schedule_name: str) -> str:
        revoke_event = GroupRevokeEvent(
            schedule_name=schedule_name,
            approver=approver,
            requester=requester,
            group_assignment=group_assignment,
            permission_duration=permission_duration,
            thread_ts=thread_ts,
            can_extend_expired_grant=can_extend_expired_grant,
            extensions_count=extensions_count,
        )
        logger.debug("Creating schedule", extra={"revoke_event": revoke_event})
        return json.dumps({"action": "event_bridge_group_revoke", "revoke_event": revoke_event.json()})

    return _create_schedule_with_retry(
        schedule_client,
        name_prefix=cfg.revoker_function_name,
        build_input=build_input,
        create_kwargs={
            "ActionAfterCompletion": "NONE",
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "GroupName": cfg.schedule_group_name,
            "ScheduleExpression": event_bridge_schedule_after(permission_duration),
            "State": "ENABLED",
            "Target": scheduler_type_defs.TargetTypeDef(
                Arn=cfg.revoker_function_arn,
                RoleArn=cfg.schedule_policy_arn,
                Input="",  # replaced by build_input
            ),
        },
    )


def schedule_discard_buttons_event(
    schedule_client: EventBridgeSchedulerClient,
    time_stamp: str,
    channel_id: str,
) -> scheduler_type_defs.CreateScheduleOutputTypeDef | None:
    if cfg.request_expiration_hours == 0:
        logger.info("Request expiration is disabled, not scheduling discard buttons event")
        return
    permission_duration = timedelta(hours=cfg.request_expiration_hours)

    logger.info("Scheduling discard buttons event")

    def build_input(schedule_name: str) -> str:
        logger.debug(
            "Creating schedule",
            extra={
                "schedule_name": schedule_name,
                "permission_duration": permission_duration,
                "time_stamp": time_stamp,
                "channel_id": channel_id,
            },
        )
        return json.dumps(
            DiscardButtonsEvent(
                action="discard_buttons_event",
                schedule_name=schedule_name,
                time_stamp=time_stamp,
                channel_id=channel_id,
            ).dict()
        )

    result, _ = _create_schedule_with_retry(
        schedule_client,
        name_prefix="discard-buttons",
        build_input=build_input,
        create_kwargs={
            "ActionAfterCompletion": "DELETE",
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "GroupName": cfg.schedule_group_name,
            "ScheduleExpression": event_bridge_schedule_after(permission_duration),
            "State": "ENABLED",
            "Target": scheduler_type_defs.TargetTypeDef(
                Arn=cfg.revoker_function_arn,
                RoleArn=cfg.schedule_policy_arn,
                Input="",  # replaced by build_input
            ),
        },
    )
    return result


def schedule_discard_extend_button_event(
    schedule_client: EventBridgeSchedulerClient,
    time_stamp: str,
    channel_id: str,
) -> scheduler_type_defs.CreateScheduleOutputTypeDef:
    permission_duration = timedelta(hours=1)

    logger.info("Scheduling discard extend button event")

    def build_input(schedule_name: str) -> str:
        return json.dumps(
            DiscardButtonsEvent(
                action="discard_buttons_event",
                schedule_name=schedule_name,
                time_stamp=time_stamp,
                channel_id=channel_id,
                block_id="extend_grant_button",
            ).dict()
        )

    result, _ = _create_schedule_with_retry(
        schedule_client,
        name_prefix="discard-buttons-extend",
        build_input=build_input,
        create_kwargs={
            "ActionAfterCompletion": "DELETE",
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "GroupName": cfg.schedule_group_name,
            "ScheduleExpression": event_bridge_schedule_after(permission_duration),
            "State": "ENABLED",
            "Target": scheduler_type_defs.TargetTypeDef(
                Arn=cfg.revoker_function_arn,
                RoleArn=cfg.schedule_policy_arn,
                Input="",  # replaced by build_input
            ),
        },
    )
    return result


def schedule_approver_notification_event(
    schedule_client: EventBridgeSchedulerClient,
    message_ts: str,
    channel_id: str,
    time_to_wait: timedelta,
) -> scheduler_type_defs.CreateScheduleOutputTypeDef | None:
    # If the initial wait time is 0, we don't schedule the event
    if cfg.approver_renotification_initial_wait_time == 0:
        logger.info("Approver renotification is disabled, not scheduling approver notification event")
        return

    logger.info("Scheduling approver notification event")

    def build_input(schedule_name: str) -> str:
        logger.debug(
            "Creating schedule",
            extra={
                "schedule_name": schedule_name,
                "time_to_wait": time_to_wait,
                "time_stamp": message_ts,
                "channel_id": channel_id,
            },
        )
        return json.dumps(
            ApproverNotificationEvent(
                action="approvers_renotification",
                schedule_name=schedule_name,
                time_stamp=message_ts,
                channel_id=channel_id,
                time_to_wait_in_seconds=time_to_wait.total_seconds(),
            ).dict()
        )

    result, _ = _create_schedule_with_retry(
        schedule_client,
        name_prefix="approvers-renotification",
        build_input=build_input,
        create_kwargs={
            "ActionAfterCompletion": "DELETE",
            "FlexibleTimeWindow": {"Mode": "OFF"},
            "GroupName": cfg.schedule_group_name,
            "ScheduleExpression": event_bridge_schedule_after(time_to_wait),
            "State": "ENABLED",
            "Target": scheduler_type_defs.TargetTypeDef(
                Arn=cfg.revoker_function_arn,
                RoleArn=cfg.schedule_policy_arn,
                Input="",  # replaced by build_input
            ),
        },
    )
    return result
