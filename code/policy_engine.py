"""Deterministic interpretation of deletion policy against supplied evidence.

Policy decisions consume already-extracted, identity-scoped evidence. They do
not infer absence from missing facts or treat workflow/activity results as
proof. Evidence coverage and lineage uncertainty remain explicit inputs to
request status evaluation. A conditional rule whose false branch has no
specified treatment (for example, an inactive legal hold) remains unresolved.
The policy has no output status for uncertainty; the evaluator uses
INCOMPLETE, while the planner refuses to invent a finding or remediation when
the allowed operation table cannot represent that uncertainty.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping

from evidence_model import EvidenceFact, parse_timestamp
from lineage_graph import ResurrectionAnalysis, ResurrectionPath, UnresolvedLineage


class PolicyError(ValueError):
    """Raised when the supplied policy cannot be interpreted safely."""


class PolicyAction(str, Enum):
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class EvidenceDisposition(str, Enum):
    COMPLIANT = "COMPLIANT"
    VIOLATION = "VIOLATION"
    UNRESOLVED = "UNRESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: PolicyAction


@dataclass(frozen=True)
class PolicyRecord:
    """One fact with the result of the separate identity-resolution stage."""

    fact: EvidenceFact
    identity_status: str = "confirmed"
    applies_to_subject: bool | None = True
    temporal_status: str = "in_scope"
    condition_values: Mapping[str, Any] = field(default_factory=dict)
    target_system_id: str | None = None
    target_system_source_id: str | None = None
    target_system_source_file: str | None = None
    target_system_source_location: str | None = None


@dataclass(frozen=True)
class PolicyDecision:
    rule: PolicyRule
    fact: EvidenceFact
    action: PolicyAction | None
    disposition: EvidenceDisposition
    condition_met: bool | None
    reason: str
    prohibited_identifiers: tuple[str, ...] = ()
    target_system_id: str | None = None
    target_system_source_id: str | None = None
    target_system_source_file: str | None = None
    target_system_source_location: str | None = None


@dataclass(frozen=True)
class RequestEvaluation:
    case_id: str
    status: DeletionStatus
    applicable: bool
    decisions: tuple[PolicyDecision, ...]
    confirmed_paths: tuple[ResurrectionPath, ...] = ()
    unresolved_lineage: tuple[UnresolvedLineage, ...] = ()
    unresolved_evidence: tuple[str, ...] = ()
    flow_systems: tuple[tuple[str, str], ...] = ()
    restore_risks: tuple[PolicyDecision, ...] = ()


_ALLOWED_ACTIONS = {action.value: action for action in PolicyAction}
_DIRECT_IDENTIFIER_NAMES = {
    "account_email",
    "address",
    "customer_email",
    "customer_id",
    "customer_reference",
    "display_name",
    "email",
    "email_hash",
    "full_name",
    "given_name",
    "lookup_key",
    "lookup_value",
    "name",
    "owner_email",
    "owner_phone",
    "phone",
    "requester_email",
    "requester_name",
    "requester_phone",
    "subject_id",
    "subject_reference",
    "surname",
}
_EMAIL_NAMES = {
    "account_email", "customer_email", "email", "owner_email", "requester_email"
}
_ABSENT_STATES = {"absent", "not_found", "not present"}
_PRESENT_STATES = {"present", "active", "retained", "available"}
_REDACTED_STATES = {"redacted", "masked", "scrubbed"}
_ANONYMIZED_STATES = {"anonymized", "anonymised", "deidentified", "de-identified"}
_TRUE_VALUES = {"1", "true", "yes", "active", "enabled", "allowed"}
_FALSE_VALUES = {"0", "false", "no", "inactive", "disabled", "blocked", "denied"}
_SUPPORT_ORDER_CONTEXT = re.compile(
    r"\baffected order includes:\s*\S",
    re.IGNORECASE,
)

_DELETION_INTENT = re.compile(
    r"\b(?:delete|delet(?:e|ion|ing)|erase|erasure|remove|removal|"
    r"forget|forgotten|wipe|purge|close\s+(?:my|the)\s+account|"
    r"eliminar|borrar|suprimir|cancelar\s+(?:mi|la)\s+cuenta|"
    r"effacer|supprimer|löschen|loeschen|eliminar\s+mis\s+datos)\b",
    re.IGNORECASE,
)
_NEGATED_DELETION = re.compile(
    r"\b(?:do\s+not|don't|dont|never|not|no|without)\s+"
    r"(?:(?:want|request|authorize|need)\s+)?"
    r"(?:please\s+)?(?:a\s+)?"
    r"(?:delete|deletion|deleting|erase|erasure|remove|removal|"
    r"purge|wipe|eliminar|borrar|suprimir)\b",
    re.IGNORECASE,
)
_MARKETING_OPT_OUT = re.compile(
    r"\b(?:unsubscribe|opt[\s-]?out|remove\s+(?:me|my\s+email)|"
    r"stop\s+(?:sending|emailing))\b.{0,40}\bmarketing\b|"
    r"\bmarketing\b.{0,40}\b(?:unsubscribe|opt[\s-]?out|remove|stop)\b",
    re.IGNORECASE,
)
_EXPLICIT_DELETION_VERB = re.compile(
    r"\b(?:delete|erase|purge|wipe|eliminar|borrar|suprimir|effacer|"
    r"supprimer|löschen|loeschen)\b",
    re.IGNORECASE,
)


def load_policy_rules(path: str | Path | None = None) -> tuple[PolicyRule, ...]:
    """Load and validate the actual policy table instead of embedding rules."""
    source = (
        Path(path)
        if path is not None
        else Path(__file__).resolve().parents[1] / "dataset" / "deletion_rules.csv"
    )
    try:
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            expected = ["rule_id", "data_category", "condition", "required_action"]
            if reader.fieldnames != expected:
                raise PolicyError(
                    f"{source}: expected columns {','.join(expected)}"
                )
            rules: list[PolicyRule] = []
            seen: set[str] = set()
            for line_no, row in enumerate(reader, start=2):
                rule_id = (row.get("rule_id") or "").strip()
                category = (row.get("data_category") or "").strip()
                condition = (row.get("condition") or "").strip()
                raw_action = (row.get("required_action") or "").strip().upper()
                if not rule_id or not category or not condition:
                    raise PolicyError(f"{source}: incomplete rule on line {line_no}")
                if rule_id in seen:
                    raise PolicyError(f"{source}: duplicate rule_id {rule_id!r}")
                if raw_action not in _ALLOWED_ACTIONS:
                    raise PolicyError(
                        f"{source}: unsupported action {raw_action!r} on line {line_no}"
                    )
                seen.add(rule_id)
                rules.append(
                    PolicyRule(
                        rule_id,
                        category,
                        condition,
                        _ALLOWED_ACTIONS[raw_action],
                    )
                )
    except OSError as exc:
        raise PolicyError(f"Cannot read policy rules {source}: {exc}") from exc
    if not rules:
        raise PolicyError(f"{source}: policy contains no rules")
    return tuple(rules)


def is_deletion_request(request_text: Any) -> bool:
    """Recognize explicit deletion intent; a negative request is not applicable."""
    if not isinstance(request_text, str):
        return False
    if _NEGATED_DELETION.search(request_text):
        return False
    if (
        _MARKETING_OPT_OUT.search(request_text)
        and not _EXPLICIT_DELETION_VERB.search(request_text)
        and not re.search(
            r"\bclose\s+(?:my|the)\s+account\b",
            request_text,
            re.IGNORECASE,
        )
    ):
        return False
    return _DELETION_INTENT.search(request_text) is not None


def _field_values(fact: EvidenceFact) -> dict[str, tuple[str, ...]]:
    values: dict[str, set[str]] = {}
    for observed in fact.observed_fields:
        values.setdefault(observed.name.casefold(), set()).add(observed.value.strip())
    return {key: tuple(sorted(value for value in items if value)) for key, items in values.items()}


def _first(values: Mapping[str, tuple[str, ...]], *names: str) -> str | None:
    for name in names:
        found = values.get(name.casefold())
        if found:
            return found[0]
    return None


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    normalized = str(value).strip().casefold()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return None


def _is_after(value: Any, cutoff: Any) -> bool:
    observed = parse_timestamp(value)
    boundary = parse_timestamp(cutoff)
    if observed is None or boundary is None:
        return False
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    if boundary.tzinfo is None:
        boundary = boundary.replace(tzinfo=timezone.utc)
    return observed > boundary


def _condition(
    rule: PolicyRule,
    record: PolicyRecord,
    as_of: Any,
) -> bool | None:
    override = record.condition_values.get(rule.rule_id)
    if override is not None:
        return _boolean(override)

    fact = record.fact
    values = _field_values(fact)
    category = rule.data_category
    if rule.condition.casefold() == "always":
        return True

    if category == "SUPPORT_MESSAGE":
        explicit = _first(
            values, "shared_context", "shared_customer_context", "contains_order_context"
        )
        if explicit is not None:
            return _boolean(explicit)
        message = _first(values, "message_text", "message", "body")
        if message is not None and _SUPPORT_ORDER_CONTEXT.search(message):
            return True
        return _boolean(
            record.condition_values.get("shared_context")
        )

    if category == "SUPPORT_ATTACHMENT":
        explicit = _first(
            values, "belongs_only_to_subject", "subject_only", "exclusive_subject"
        )
        if explicit is None:
            explicit = record.condition_values.get("belongs_only_to_subject")
        return _boolean(explicit)

    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        explicit = _first(values, "still_attributable", "attributable_to_user")
        if explicit is not None:
            return _boolean(explicit)
        identifiers = _prohibited_identifiers(fact, category)
        if identifiers or any(
            candidate.field_name.casefold()
            in {"user_id", "customer_id", "customer_reference"}
            for candidate in fact.candidate_identifiers
        ):
            return True
        state = (fact.record_state or "").strip().casefold()
        if state in _ANONYMIZED_STATES:
            return False
        return None

    if category == "EMAIL_DELIVERY_LOG":
        return any(
            candidate.field_name.casefold() in _EMAIL_NAMES
            for candidate in fact.candidate_identifiers
        ) or any(name in _EMAIL_NAMES for name in fact.personal_fields)

    if category == "SECURITY_AUDIT_LOG":
        explicit = record.condition_values.get("retention_active")
        if explicit is not None:
            return _boolean(explicit)
        expiry = parse_timestamp(
            _first(
                values, "retention_until", "retention_expires_at", "retention_expiry"
            )
        )
        cutoff = parse_timestamp(as_of)
        if expiry is not None and cutoff is not None:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if cutoff.tzinfo is None:
                cutoff = cutoff.replace(tzinfo=timezone.utc)
            return cutoff <= expiry
        days = _first(values, "retention_days", "retention_period_days")
        created = parse_timestamp(_first(values, "created_at", "event_time"))
        if days is not None and created is not None and cutoff is not None:
            try:
                duration_days = int(days)
            except ValueError:
                return None
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            if cutoff.tzinfo is None:
                cutoff = cutoff.replace(tzinfo=timezone.utc)
            return cutoff <= created + timedelta(days=duration_days)
        return None

    if category == "LEGAL_HOLD_RECORD":
        explicit = _first(values, "legal_hold_active", "active_legal_hold")
        if explicit is None:
            explicit = record.condition_values.get("legal_hold_active")
        return _boolean(explicit)

    if category == "BACKUP_ARCHIVE":
        explicit = _first(
            values, "restore_access_blockable", "restore_blockable", "can_block_restore"
        )
        if explicit is None:
            explicit = record.condition_values.get("restore_access_blockable")
        return _boolean(explicit)

    if category == "ACCOUNT_TOMBSTONE":
        deleted = _first(values, "account_deleted", "deleted")
        if deleted is None:
            deleted = record.condition_values.get("account_deleted")
        if deleted is None:
            account_status = _first(values, "account_status")
            if account_status is not None:
                normalized_status = account_status.casefold()
                if normalized_status == "deleted":
                    deleted = "true"
                elif normalized_status == "active":
                    deleted = "false"
        references_needed = _first(
            values, "stable_reference_required", "retained_reference_required"
        )
        if references_needed is None:
            references_needed = record.condition_values.get("stable_reference_required")
        deleted_value = _boolean(deleted)
        references_value = _boolean(references_needed)
        if deleted_value is False or references_value is False:
            return False
        if deleted_value is True and references_value is True:
            return True
        return None
    return None


def _prohibited_identifiers(fact: EvidenceFact, category: str) -> tuple[str, ...]:
    names = {
        name.casefold()
        for name in fact.personal_fields
        if name.casefold() in _DIRECT_IDENTIFIER_NAMES
    }
    names.update(
        candidate.field_name.casefold()
        for candidate in fact.candidate_identifiers
        if candidate.field_name.casefold() in _DIRECT_IDENTIFIER_NAMES
    )
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        names.update(
            candidate.field_name.casefold()
            for candidate in fact.candidate_identifiers
            if candidate.field_name.casefold()
            in {"user_id", "customer_id", "customer_reference"}
        )
    if category == "EMAIL_DELIVERY_LOG":
        names.intersection_update(_EMAIL_NAMES)
    return tuple(sorted(names))


def _record_state(fact: EvidenceFact) -> str:
    state = (fact.record_state or "").strip().casefold().replace("-", "_")
    if state in _ABSENT_STATES:
        return "ABSENT"
    if state in _REDACTED_STATES:
        return "REDACTED"
    if state in _ANONYMIZED_STATES:
        return "ANONYMIZED"
    if state in _PRESENT_STATES:
        return "PRESENT"
    # Activity results and workflow labels are claims, not record-state proof.
    if state in {"success", "complete", "completed", "done", "ok"}:
        return "UNKNOWN"
    return "PRESENT"


def evaluate_policy_record(
    record: PolicyRecord,
    rule: PolicyRule,
    *,
    as_of: Any = None,
) -> PolicyDecision:
    """Evaluate one identity-scoped fact against one loaded rule."""
    fact = record.fact

    def decision(
        action: PolicyAction | None,
        disposition: EvidenceDisposition,
        condition_met: bool | None,
        reason: str,
        prohibited_identifiers: tuple[str, ...] = (),
    ) -> PolicyDecision:
        return PolicyDecision(
            rule,
            fact,
            action,
            disposition,
            condition_met,
            reason,
            prohibited_identifiers,
            record.target_system_id,
            record.target_system_source_id,
            record.target_system_source_file,
            record.target_system_source_location,
        )

    if record.applies_to_subject is False:
        return decision(
            None, EvidenceDisposition.NOT_APPLICABLE, False,
            "evidence establishes that the record does not concern this subject",
        )
    if record.applies_to_subject is not True or record.identity_status != "confirmed":
        return decision(
            None, EvidenceDisposition.UNRESOLVED, None,
            "subject linkage is not uniquely confirmed",
        )

    condition_met = _condition(rule, record, as_of)
    if condition_met is None:
        return decision(
            None, EvidenceDisposition.UNRESOLVED, None,
            f"condition for {rule.rule_id} is not established by supplied evidence",
        )
    if condition_met is False:
        if rule.data_category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
            if not _prohibited_identifiers(fact, rule.data_category):
                return decision(
                    rule.required_action, EvidenceDisposition.COMPLIANT,
                    False, "record is no longer attributable to the subject",
                )
        if rule.data_category == "EMAIL_DELIVERY_LOG":
            if not _prohibited_identifiers(fact, rule.data_category):
                return decision(
                    rule.required_action, EvidenceDisposition.COMPLIANT,
                    False, "delivery log contains no user email address",
                )
        return decision(
            None, EvidenceDisposition.UNRESOLVED, False,
            f"condition for {rule.rule_id} is false; the supplied policy does not "
            "specify an alternative treatment",
        )

    action = rule.required_action
    state = _record_state(fact)
    identifiers = _prohibited_identifiers(fact, rule.data_category)
    stable_user_reference_present = (
        rule.data_category == "ACCOUNT_TOMBSTONE"
        and record.condition_values.get("stable_user_id_reference_present") is True
    )
    if stable_user_reference_present:
        identifiers = tuple(
            item for item in identifiers if item != "subject_reference"
        )

    if action is PolicyAction.DELETE:
        if state == "ABSENT":
            disposition, reason = EvidenceDisposition.COMPLIANT, "record is explicitly absent"
        elif state == "UNKNOWN":
            disposition, reason = EvidenceDisposition.UNRESOLVED, "record state is not authoritative"
        else:
            disposition, reason = EvidenceDisposition.VIOLATION, "record remains and policy requires deletion"
    elif action is PolicyAction.REDACT:
        if state == "ABSENT":
            disposition, reason = EvidenceDisposition.COMPLIANT, "record is explicitly absent"
        elif state == "UNKNOWN":
            disposition, reason = EvidenceDisposition.UNRESOLVED, "record state is not authoritative"
        elif identifiers:
            disposition, reason = EvidenceDisposition.VIOLATION, (
                "record remains with identifiers prohibited by the redaction rule"
            )
        elif state == "REDACTED" or fact.observed_fields:
            disposition, reason = EvidenceDisposition.COMPLIANT, (
                "record remains and the observed field inventory contains no prohibited identifiers"
            )
        else:
            disposition, reason = EvidenceDisposition.UNRESOLVED, (
                "record presence is known but its identifier fields were not checked"
            )
    elif action is PolicyAction.ANONYMIZE:
        if state == "ABSENT":
            disposition, reason = EvidenceDisposition.COMPLIANT, "record is explicitly absent"
        elif state == "UNKNOWN":
            disposition, reason = EvidenceDisposition.UNRESOLVED, "record state is not authoritative"
        elif identifiers:
            disposition, reason = EvidenceDisposition.VIOLATION, (
                "record remains attributable through observed identifiers"
            )
        elif state == "ANONYMIZED" or fact.observed_fields:
            disposition, reason = EvidenceDisposition.COMPLIANT, (
                "record remains and the observed field inventory has no subject identifiers"
            )
        else:
            disposition, reason = EvidenceDisposition.UNRESOLVED, (
                "record attribution could not be checked"
            )
    else:
        if state == "ABSENT":
            disposition, reason = EvidenceDisposition.VIOLATION, (
                "policy requires the retained record to remain available"
            )
        elif state == "UNKNOWN":
            disposition, reason = EvidenceDisposition.UNRESOLVED, (
                "record availability is not authoritative"
            )
        else:
            disposition, reason = EvidenceDisposition.COMPLIANT, (
                "policy-required record remains available"
            )

    if rule.data_category == "ACCOUNT_TOMBSTONE":
        non_user_id = tuple(
            item for item in identifiers if item != "user_id"
        )
        # Only the stable internal user_id is permitted on this tombstone.
        candidates = {
            item.field_name.casefold() for item in fact.candidate_identifiers
        }
        if (
            "user_id" not in candidates
            and not stable_user_reference_present
            and disposition is EvidenceDisposition.COMPLIANT
        ):
            disposition, reason = EvidenceDisposition.UNRESOLVED, (
                "tombstone evidence does not confirm the permitted stable user_id reference"
            )
        elif non_user_id:
            identifiers = non_user_id
            disposition, reason = EvidenceDisposition.VIOLATION, (
                "tombstone retains prohibited direct identifiers; only stable user_id may remain"
            )

    return decision(
        action,
        disposition,
        condition_met,
        reason,
        identifiers if disposition is EvidenceDisposition.VIOLATION else (),
    )


def evaluate_request(
    request: Mapping[str, Any],
    records: Iterable[PolicyRecord],
    *,
    rules: Iterable[PolicyRule] | str | Path | None = None,
    lineage_analysis: ResurrectionAnalysis | None = None,
    as_of: Any = None,
    evidence_complete: bool = False,
) -> RequestEvaluation:
    """Evaluate status without treating missing evidence as proof of absence.

    ``evidence_complete`` is an explicit upstream assertion that the evidence
    collection/inventory was completed. It defaults to false. A missing
    lineage analysis or unresolved lineage also prevents COMPLETE.
    """
    case_id = str(request.get("case_id") or "")
    if not is_deletion_request(request.get("request_text")):
        return RequestEvaluation(
            case_id, DeletionStatus.NOT_APPLICABLE, False, ()
        )
    if as_of is None:
        as_of = request.get("audit_at")

    policy_rules = (
        load_policy_rules(rules)
        if isinstance(rules, (str, Path)) or rules is None
        else tuple(rules)
    )
    rules_by_category = {
        rule.data_category.casefold(): rule for rule in policy_rules
    }
    decisions: list[PolicyDecision] = []
    unresolved: list[str] = []
    restore_risks: list[PolicyDecision] = []
    record_rows = tuple(records)
    for record in record_rows:
        if record.applies_to_subject is False:
            continue
        if record.temporal_status != "in_scope":
            unresolved.append(
                f"{record.fact.file_id}/{record.fact.resource_id or ''}: "
                f"evidence time is {record.temporal_status}"
            )
            continue
        if as_of is not None and (
            _is_after(record.fact.captured_at, as_of)
            or _is_after(record.fact.event_timestamp, as_of)
        ):
            unresolved.append(
                f"{record.fact.file_id}/{record.fact.resource_id or ''}: "
                "observation is after the audit cutoff"
            )
            continue
        if record.applies_to_subject is None or record.identity_status != "confirmed":
            unresolved.append(
                f"{record.fact.file_id}/{record.fact.resource_id or ''}: "
                "subject identity is unresolved"
            )
            continue
        categories = {category.casefold() for category in record.fact.data_categories}
        if "data_flow" in categories:
            continue
        matching = next(
            (rules_by_category[name] for name in sorted(categories) if name in rules_by_category),
            None,
        )
        if matching is None:
            unresolved.append(
                f"{record.fact.file_id}/{record.fact.resource_id or ''}: "
                f"no supplied policy rule matches categories {sorted(categories)}"
            )
            continue
        decision = evaluate_policy_record(record, matching, as_of=as_of)
        decisions.append(decision)
        if decision.disposition is EvidenceDisposition.UNRESOLVED:
            unresolved.append(
                f"{decision.fact.file_id}/{decision.fact.resource_id or ''}: {decision.reason}"
            )
        if (
            matching.data_category == "BACKUP_ARCHIVE"
            and decision.condition_met is True
            and _record_state(decision.fact) == "PRESENT"
        ):
            values = _field_values(decision.fact)
            restore_allowed = _boolean(
                _first(values, "restore_allowed", "restore_access_enabled", "restore_state")
            )
            if restore_allowed is True:
                restore_risks.append(decision)
            elif restore_allowed is None:
                unresolved.append(
                    f"{decision.fact.file_id}/{decision.fact.resource_id or ''}: "
                    "restore state is unknown"
                )

    confirmed_paths = lineage_analysis.confirmed_paths if lineage_analysis else ()
    unresolved_lineage = (
        lineage_analysis.unresolved_lineage if lineage_analysis else ()
    )
    possible_paths = lineage_analysis.possible_paths if lineage_analysis else ()
    if lineage_analysis is None:
        unresolved.append("lineage analysis was not supplied")
    unresolved.extend(
        f"{item.edge.edge_id}: {item.reason}" for item in unresolved_lineage
    )
    unresolved.extend(
        f"{path.finding}: {','.join(path.supporting_evidence_ids)}"
        for path in possible_paths
    )
    if not evidence_complete:
        unresolved.append("evidence inventory completeness was not established")
    if not decisions:
        unresolved.append(
            "no identity-scoped, policy-backed resource observations support verification"
        )

    flow_systems: dict[str, str] = {}
    fact_by_id = {
        record.fact.file_id: record.fact
        for record in record_rows
        if record.applies_to_subject is True
        and record.identity_status == "confirmed"
        and record.temporal_status == "in_scope"
        and not (
            as_of is not None
            and (
                _is_after(record.fact.captured_at, as_of)
                or _is_after(record.fact.event_timestamp, as_of)
            )
        )
    }
    for path in confirmed_paths:
        for edge in path.edges:
            fact = fact_by_id.get(edge.source_evidence_id)
            if fact and fact.system_id and edge.resource_id:
                flow_systems[edge.edge_id] = fact.system_id
            else:
                unresolved.append(
                    f"{edge.edge_id}: confirmed flow lacks a source-backed system/resource target"
                )

    has_violation = any(
        decision.disposition is EvidenceDisposition.VIOLATION
        for decision in decisions
    )
    if has_violation or confirmed_paths or restore_risks or unresolved:
        status = DeletionStatus.INCOMPLETE
    else:
        status = DeletionStatus.COMPLETE
    return RequestEvaluation(
        case_id,
        status,
        True,
        tuple(
            sorted(
                decisions,
                key=lambda item: (
                    item.fact.system_id or "",
                    item.fact.resource_id or "",
                    item.rule.rule_id,
                    item.fact.file_id,
                ),
            )
        ),
        tuple(confirmed_paths),
        tuple(unresolved_lineage),
        tuple(sorted(set(unresolved))),
        tuple(sorted(flow_systems.items())),
        tuple(
            sorted(
                restore_risks,
                key=lambda item: (
                    item.fact.system_id or "",
                    item.fact.resource_id or "",
                    item.fact.file_id,
                ),
            )
        ),
    )


__all__ = [
    "DeletionStatus",
    "EvidenceDisposition",
    "PolicyAction",
    "PolicyDecision",
    "PolicyError",
    "PolicyRecord",
    "PolicyRule",
    "RequestEvaluation",
    "evaluate_policy_record",
    "evaluate_request",
    "is_deletion_request",
    "load_policy_rules",
]
