"""Deterministic, contract-conforming plan generation from policy evaluations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from contract_validator import _step_sort_key
from policy_engine import (
    DeletionStatus,
    EvidenceDisposition,
    PolicyAction,
    PolicyDecision,
    RequestEvaluation,
)


class PlanningError(ValueError):
    """Raised when available evidence cannot support a valid output plan."""


@dataclass(frozen=True)
class RemediationPlan:
    status: DeletionStatus
    steps: tuple[dict[str, Any], ...]
    unresolved: tuple[str, ...] = ()


_ABSENT_STATES = {"absent", "not_found", "not present"}
_UNKNOWN_CLAIMS = {"success", "complete", "completed", "done", "ok"}


def _resource_target(decision: PolicyDecision) -> tuple[str, str]:
    system_id = decision.target_system_id or decision.fact.system_id
    resource_id = decision.fact.resource_id
    if not system_id or not resource_id:
        raise PlanningError(
            f"{decision.fact.file_id}: policy decision lacks a supported "
            "system_id or resource_id"
        )
    return system_id, resource_id


def _step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def _add_unique(
    steps: dict[tuple[str, str, str, str], dict[str, Any]],
    step: dict[str, Any],
) -> None:
    key = (
        step["phase"],
        step["system_id"],
        step["resource_id"],
        step["operation"],
    )
    existing = steps.get(key)
    if existing is None or (
        not existing["evidence_id"]
        and step["evidence_id"]
    ) or (
        existing["evidence_id"]
        and step["evidence_id"]
        and step["evidence_id"] < existing["evidence_id"]
    ):
        steps[key] = step


def _number_and_sort(
    steps: dict[tuple[str, str, str, str], dict[str, Any]],
) -> tuple[dict[str, Any], ...]:
    ordered = sorted(steps.values(), key=_step_sort_key)
    for number, step in enumerate(ordered, start=1):
        step["step_no"] = number
    return tuple(ordered)


def _compliant_verification(decision: PolicyDecision) -> tuple[str, str] | None:
    state = (decision.fact.record_state or "").strip().casefold().replace("-", "_")
    if state in _UNKNOWN_CLAIMS:
        return None
    if state in _ABSENT_STATES:
        return "VERIFY_RECORD_ABSENT", "ABSENT"
    if decision.action is PolicyAction.DELETE:
        # An explicitly observed absent state is required for DELETE compliance.
        return "VERIFY_RECORD_ABSENT", "ABSENT"
    if decision.action is PolicyAction.REDACT:
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    if decision.action is PolicyAction.ANONYMIZE:
        return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
    if decision.action is PolicyAction.RETAIN:
        return "VERIFY_RECORD_PRESENT", "PRESENT"
    return None


def _backup_restore_is_blocked(decision: PolicyDecision) -> bool:
    if decision.rule.data_category != "BACKUP_ARCHIVE":
        return False
    blocked_values = {"0", "false", "no", "inactive", "disabled", "blocked", "denied"}
    restore_fields = {
        "restore_allowed",
        "restore_access_enabled",
        "restore_state",
    }
    return any(
        field.name.casefold() in restore_fields
        and field.value.strip().casefold() in blocked_values
        for field in decision.fact.observed_fields
    )


def plan_remediation(evaluation: RequestEvaluation) -> RemediationPlan:
    """Create ordered steps; unresolved evidence never receives invented actions."""
    if evaluation.status is DeletionStatus.NOT_APPLICABLE:
        return RemediationPlan(DeletionStatus.NOT_APPLICABLE, ())

    if evaluation.status is DeletionStatus.COMPLETE:
        steps: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for decision in evaluation.decisions:
            if decision.disposition is not EvidenceDisposition.COMPLIANT:
                continue
            target = _resource_target(decision)
            verification = _compliant_verification(decision)
            if verification is None:
                continue
            operation, state = verification
            _add_unique(
                steps,
                _step(
                    "VERIFICATION",
                    *target,
                    operation,
                    state,
                    decision.fact.file_id,
                ),
            )
            if _backup_restore_is_blocked(decision):
                _add_unique(
                    steps,
                    _step(
                        "VERIFICATION",
                        *target,
                        "VERIFY_RESTORE_BLOCKED",
                        "BLOCKED",
                        decision.fact.file_id,
                    ),
                )
        if evaluation.unresolved_evidence or evaluation.unresolved_lineage:
            raise PlanningError(
                "Cannot plan COMPLETE while evidence remains unresolved: "
                + "; ".join(evaluation.unresolved_evidence)
            )
        if not steps:
            raise PlanningError(
                "COMPLETE evaluation has no evidence-backed verification steps"
            )
        return RemediationPlan(
            DeletionStatus.COMPLETE,
            _number_and_sort(steps),
        )

    steps = {}
    remediation_targets: list[tuple[str, str, str]] = []
    for decision in evaluation.decisions:
        if decision.disposition is not EvidenceDisposition.VIOLATION:
            continue
        if decision.action is PolicyAction.RETAIN:
            raise PlanningError(
                f"{decision.fact.file_id}: a required retained record is missing; "
                "the allowed operations do not define a safe restoration action"
            )
        system_id, resource_id = _resource_target(decision)
        finding_operation = (
            "REPORT_REMAINING_RECORD"
            if decision.action is PolicyAction.DELETE
            else "REPORT_EXPOSED_PII"
        )
        _add_unique(
            steps,
            _step(
                "FINDING",
                system_id,
                resource_id,
                finding_operation,
                "PRESENT",
                decision.fact.file_id,
            ),
        )
        if decision.action is PolicyAction.DELETE:
            operation, state = "DELETE_RECORD", "ABSENT"
            verify_operation, verify_state = "VERIFY_RECORD_ABSENT", "ABSENT"
        elif decision.action is PolicyAction.REDACT:
            operation, state = "REDACT_RECORD", "REDACTED"
            verify_operation, verify_state = "VERIFY_RECORD_REDACTED", "REDACTED"
        elif decision.action is PolicyAction.ANONYMIZE:
            operation, state = "ANONYMIZE_RECORD", "ANONYMIZED"
            verify_operation, verify_state = (
                "VERIFY_RECORD_ANONYMIZED",
                "ANONYMIZED",
            )
        else:
            raise PlanningError(
                f"{decision.fact.file_id}: no permitted remediation for "
                f"{decision.action}"
            )
        _add_unique(
            steps,
            _step(
                "REMEDIATION", system_id, resource_id, operation, state, ""
            ),
        )
        _add_unique(
            steps,
            _step(
                "VERIFICATION",
                system_id,
                resource_id,
                verify_operation,
                verify_state,
                "",
            ),
        )
        remediation_targets.append((system_id, resource_id, operation))

    # A confirmed active path is actionable only when its source configuration
    # supplied both the service and resource identifiers.
    flow_systems = dict(evaluation.flow_systems)
    for path in evaluation.confirmed_paths:
        for edge in path.edges:
            system_id = flow_systems.get(edge.edge_id)
            if not system_id or not edge.resource_id:
                raise PlanningError(
                    f"{edge.edge_id}: confirmed flow has no supported remediation target"
                )
            _add_unique(
                steps,
                _step(
                    "FINDING",
                    system_id,
                    edge.resource_id,
                    "REPORT_ACTIVE_DATA_FLOW",
                    "ACTIVE",
                    edge.source_evidence_id,
                ),
            )
            _add_unique(
                steps,
                _step(
                    "REMEDIATION",
                    system_id,
                    edge.resource_id,
                    "DISABLE_DATA_FLOW",
                    "DISABLED",
                    "",
                ),
            )
            _add_unique(
                steps,
                _step(
                    "VERIFICATION",
                    system_id,
                    edge.resource_id,
                    "VERIFY_DATA_FLOW_DISABLED",
                    "DISABLED",
                    "",
                ),
            )

    for decision in evaluation.restore_risks:
        system_id, resource_id = _resource_target(decision)
        _add_unique(
            steps,
            _step(
                "FINDING",
                system_id,
                resource_id,
                "REPORT_RESTORE_RISK",
                "ACTIVE",
                decision.fact.file_id,
            ),
        )
        _add_unique(
            steps,
            _step(
                "REMEDIATION",
                system_id,
                resource_id,
                "BLOCK_RESTORE",
                "BLOCKED",
                "",
            ),
        )
        _add_unique(
            steps,
            _step(
                "VERIFICATION",
                system_id,
                resource_id,
                "VERIFY_RESTORE_BLOCKED",
                "BLOCKED",
                "",
            ),
        )

    if not any(step["phase"] == "FINDING" for step in steps.values()):
        raise PlanningError(
            "INCOMPLETE evaluation has no evidence-backed finding that maps to "
            "an allowed operation; unresolved details: "
            + "; ".join(evaluation.unresolved_evidence)
        )
    if not any(step["phase"] == "REMEDIATION" for step in steps.values()):
        raise PlanningError(
            "INCOMPLETE evaluation has no supported remediation operation"
        )
    if not any(step["phase"] == "VERIFICATION" for step in steps.values()):
        raise PlanningError(
            "INCOMPLETE evaluation has no supported post-remediation verification"
        )

    return RemediationPlan(
        DeletionStatus.INCOMPLETE,
        _number_and_sort(steps),
        evaluation.unresolved_evidence,
    )


__all__ = ["PlanningError", "RemediationPlan", "plan_remediation"]
