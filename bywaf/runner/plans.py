"""Plan and policy approval helpers for runner commandlets.

Provides plan generation, policy audit events, optional repair application, and
operator approval flow for commandlets that implement `plan()`.

Used by:
- runner.core: gates commandlet execution when plans require confirmation.
- tests: validate plan-only, approval, repair, and audit behavior.
"""

from __future__ import annotations

import getpass

from ..command_parser import CommandInvocation
from ..events import Event
from ..plugin import CommandContext
from ..specs import PlanRepair, PlanReport


def handle_plan_if_needed(
    context: CommandContext,
    plugin,
    args: list[str],
    input_events: list[Event],
    invocation: CommandInvocation,
) -> list[str] | None:
    """Run a commandlet plan hook, audit it, and enforce approval if needed."""
    planner = getattr(plugin, "plan", None)
    if planner is None:
        if invocation.plan_only:
            context.output(f"{plugin.spec.name}: no plan available")
            return None
        return args
    report = planner(context, args, input_events)
    if not isinstance(report, PlanReport):
        raise ValueError(f"{plugin.spec.name} plan() must return PlanReport")
    must_approve = report.requires_confirmation or bool(report.warnings)
    if not invocation.plan_only and not must_approve:
        return args
    request = publish_plan_requested(context, report)
    publish_policy_evaluated(context, request, report)
    context.output(format_plan_report(report))
    repaired_args = maybe_apply_plan_repair(context, request, report, invocation)
    if invocation.plan_only:
        return None
    if not must_approve:
        return repaired_args or args
    if invocation.approved:
        publish_plan_decision(context, request, True, "cli-yes", "--yes")
        return repaired_args or args
    if context.background:
        publish_plan_decision(context, request, False, "background", "missing --yes")
        raise ValueError(f"{plugin.spec.name} plan requires --yes for background execution")
    answer = input("Approve this plan? type YES: ")
    approved = answer == "YES"
    publish_plan_decision(context, request, approved, "interactive", answer)
    if not approved:
        raise ValueError("plan denied")
    return repaired_args or args


def maybe_apply_plan_repair(
    context: CommandContext,
    request: Event,
    report: PlanReport,
    invocation: CommandInvocation,
) -> list[str] | None:
    """Apply the first suggested repair when the operator or --yes accepts it."""
    if not report.repairs:
        return None
    repair = report.repairs[0]
    if invocation.approved:
        publish_plan_repair(context, request, repair, approved=True, method="cli-yes", answer="--yes")
        return list(repair.patched_args)
    if invocation.plan_only or context.background:
        return None
    answer = input(f"Apply suggested repair '{repair.name}'? type YES: ")
    approved = answer == "YES"
    publish_plan_repair(context, request, repair, approved=approved, method="interactive", answer=answer)
    return list(repair.patched_args) if approved else None


def publish_plan_requested(context: CommandContext, report: PlanReport) -> Event:
    """Persist the plan report shown to the operator."""
    if context._db is None:
        raise ValueError("plan auditing requires an active database")
    return context._db.publish(
        "plan.requested",
        {
            "commandlet": context.source,
            "action": report.action,
            "summary": report.summary,
            "items": [
                {"kind": item.kind, "value": item.value, "details": item.details}
                for item in report.items
            ],
            "warnings": list(report.warnings),
            "repairs": [
                {
                    "name": repair.name,
                    "description": repair.description,
                    "before": repair.before,
                    "after": repair.after,
                }
                for repair in report.repairs
            ],
            "requires_confirmation": report.requires_confirmation,
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_policy_evaluated(context: CommandContext, request: Event, report: PlanReport) -> Event:
    """Persist the framework policy decision for a plan."""
    if context._db is None:
        raise ValueError("policy auditing requires an active database")
    decision = "warn" if report.warnings else "allow"
    return context._db.publish(
        "policy.evaluated",
        {
            "request_event_id": request.id,
            "decision": decision,
            "warnings": list(report.warnings),
            "repairs": [repair.name for repair in report.repairs],
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_plan_decision(context: CommandContext, request: Event, approved: bool, method: str, answer: str) -> Event:
    """Persist the operator's approval or denial of a plan."""
    if context._db is None:
        raise ValueError("plan approval auditing requires an active database")
    return context._db.publish(
        "plan.approved" if approved else "plan.denied",
        {
            "request_event_id": request.id,
            "approved": approved,
            "approval_method": method,
            "answer": answer,
            "approved_by": getpass.getuser(),
            "job_id": context.job_id,
            "pipeline_id": context.pipeline_id,
            "command_run_id": context.command_run_id,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def publish_plan_repair(
    context: CommandContext,
    request: Event,
    repair: PlanRepair,
    *,
    approved: bool,
    method: str,
    answer: str,
) -> Event:
    """Persist the operator's decision about a suggested plan repair."""
    if context._db is None:
        raise ValueError("plan repair auditing requires an active database")
    return context._db.publish(
        "plan.repair.applied" if approved else "plan.repair.denied",
        {
            "request_event_id": request.id,
            "repair": repair.name,
            "description": repair.description,
            "approved": approved,
            "approval_method": method,
            "answer": answer,
            "approved_by": getpass.getuser(),
            "before": repair.before,
            "after": repair.after,
        },
        "framework",
        pipeline_id=context.pipeline_id,
        command_run_id=context.command_run_id,
        parent_command_run_id=context.parent_command_run_id,
    )


def format_plan_report(report: PlanReport) -> str:
    """Return a compact human-readable plan report."""
    lines = [f"Plan: {report.action}", report.summary]
    if report.items:
        lines.append("Items:")
        lines.extend(f"  {item.kind}: {item.value}" for item in report.items)
    if report.warnings:
        lines.append("Warnings:")
        lines.extend(f"  {warning}" for warning in report.warnings)
    if report.repairs:
        lines.append("Suggested repairs:")
        lines.extend(f"  {repair.name}: {repair.description}" for repair in report.repairs)
    return "\n".join(lines)
