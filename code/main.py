"""Run the deterministic, evidence-backed deletion audit pipeline."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import tempfile
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from contract_validator import validate_output
from evidence_ingestion import ingest_manifest_entry
from evidence_manifest import EvidenceIngestionError, ManifestEntry, load_manifest
from evidence_model import EvidenceFact, ExtractionWarning, parse_timestamp
from identity_timeline import (
    IdentityResolution,
    IdentityResolver,
    TimelineEvent,
    load_activity_events,
    load_identity_resolver,
    reconstruct_timeline,
)
from lineage_graph import (
    analyze_resurrection_paths,
    build_lineage_graph,
    resource_evidence_from_facts,
)
from policy_engine import (
    DeletionStatus,
    EvidenceDisposition,
    PolicyRecord,
    PolicyRule,
    evaluate_policy_record,
    evaluate_request,
    is_deletion_request,
    load_policy_rules,
)
from remediation_planner import PlanningError, plan_remediation


REQUEST_COLUMNS = (
    "case_id",
    "email",
    "requested_at",
    "reported_status",
    "reported_at",
    "audit_at",
    "request_text",
)
OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")
EXPECTED_POLICY_RULES = 15
_OCR_LIMITATION = "OCR_UNAVAILABLE"
_POLICY_CATEGORY_ALIASES = {
    "backup_catalog": "BACKUP_ARCHIVE",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "customer_exports": "USER_EXPORT",
    "customer_export_jobs": "USER_EXPORT",
    "connector_subscriptions": "DATA_FLOW",
    "customer_profiles": "USER_PROFILE",
    "customer_profiles_failover_replica": "USER_PROFILE",
    "customer_profiles_primary": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "security_audit_records": "SECURITY_AUDIT_LOG",
    "search_documents_primary": "SEARCH_INDEX_ENTRY",
    "support_conversations": "SUPPORT_MESSAGE",
    "support_records": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
}
_TABLE_SYSTEM_ALIASES = {
    "customer_profiles": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_exports": "export_service",
    "customer_export_jobs": "export_service",
    "customer_analytics_profiles": "analytics_platform",
    "customer_analytics_reports": "analytics_platform",
    "support_conversations": "support_platform",
    "support_records": "support_platform",
    "ticket_attachments": "support_platform",
    "backup_catalog": "backup_service",
    "backup_restore_entries": "backup_service",
    "security_audit_events": "security_service",
    "security_audit_records": "security_service",
    "deleted_customer_references": "account_service",
}
_SERVICE_EXPORT_CATEGORIES = {
    "account_service/profile_lookups": "USER_PROFILE",
    "analytics_platform/profiles": "ANALYTICS_PROFILE",
    "backup_service/restore_entries": "BACKUP_ARCHIVE",
    "export_service/exports": "USER_EXPORT",
    "integration_service/connectors": "DATA_FLOW",
    "security_service/audit_records": "SECURITY_AUDIT_LOG",
    "support_platform/tickets": "SUPPORT_MESSAGE",
}
_SERVICE_EVENT_CATEGORIES = {
    ("account_service", "profile_lookup_completed"): "USER_PROFILE",
    ("analytics_platform", "analytics_profile_read_completed"): "ANALYTICS_PROFILE",
    ("backup_service", "restore_policy_read_completed"): "BACKUP_ARCHIVE",
    ("export_service", "export_metadata_read_completed"): "USER_EXPORT",
    ("integration_service", "connector_config_read_completed"): "DATA_FLOW",
    ("security_service", "audit_record_read_completed"): "SECURITY_AUDIT_LOG",
    ("support_platform", "support_ticket_read_completed"): "SUPPORT_MESSAGE",
}
_NON_RESOURCE_READ_EVENTS = {
    "profile_lookup_started",
    "analytics_profile_read_started",
    "analytics_profile_scan_started",
    "connector_config_read_started",
    "index_query_started",
    "audit_record_read_started",
    "audit_record_query_started",
    "support_ticket_read_started",
    "restore_policy_read_started",
    "export_metadata_read_started",
}


class PipelineInputError(ValueError):
    """Raised when required pipeline input files do not meet their schemas."""


class CaseProcessingError(ValueError):
    """A case cannot be safely represented using the allowed output contract."""

    def __init__(
        self,
        case_id: str,
        stage: str,
        reason: str,
        reason_code: str,
    ) -> None:
        self.case_id = case_id
        self.stage = stage
        self.reason_code = reason_code
        super().__init__(reason)


@dataclass(frozen=True)
class CaseFailure:
    case_id: str
    stage: str
    error_type: str
    reason_code: str
    error_message: str
    cause_type: str
    cause_message: str


@dataclass(frozen=True)
class PipelineResult:
    request_count: int
    evidence_file_count: int
    ingested_evidence_count: int
    evidence_fact_count: int
    evidence_warning_counts: tuple[tuple[str, int], ...]
    evidence_failure_count: int
    unresolved_identity_count: int
    uncertain_case_count: int
    status_counts: tuple[tuple[str, int], ...]
    rows: tuple[dict[str, str], ...]
    failures: tuple[CaseFailure, ...]
    output_path: Path | None
    output_written: bool


def _structured_log(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: Any,
) -> None:
    logger.log(
        level,
        json.dumps({"event": event, **fields}, sort_keys=True, ensure_ascii=True),
    )


def _read_requests(path: Path) -> tuple[dict[str, str], ...]:
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != REQUEST_COLUMNS:
                raise PipelineInputError(
                    f"{path}: expected columns {','.join(REQUEST_COLUMNS)}"
                )
            rows: list[dict[str, str]] = []
            seen: set[str] = set()
            for line_no, row in enumerate(reader, start=2):
                if None in row:
                    raise PipelineInputError(
                        f"{path}: unexpected extra field on line {line_no}"
                    )
                normalized = {
                    key: (value or "").strip()
                    for key, value in row.items()
                    if key is not None
                }
                case_id = normalized["case_id"]
                if not case_id:
                    raise PipelineInputError(
                        f"{path}: empty case_id on line {line_no}"
                    )
                if case_id in seen:
                    raise PipelineInputError(
                        f"{path}: duplicate case_id {case_id!r}"
                    )
                if not normalized["request_text"]:
                    raise PipelineInputError(
                        f"{path}: empty request_text for {case_id}"
                    )
                seen.add(case_id)
                rows.append(normalized)
    except OSError as exc:
        raise PipelineInputError(f"Cannot read requests {path}: {exc}") from exc

    if not rows:
        raise PipelineInputError(f"{path}: no deletion requests were found")
    return tuple(sorted(rows, key=lambda row: row["case_id"]))


def _normalize_utc(value: Any) -> datetime | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _known_future_observation(
    fact: EvidenceFact,
    cutoff: datetime,
) -> bool:
    return any(
        observed is not None and observed > cutoff
        for observed in (
            _normalize_utc(fact.captured_at),
            _normalize_utc(fact.event_timestamp),
        )
    )


def _evidence_complete_at_cutoff(
    request: Mapping[str, str],
    incomplete_evidence_ids: set[str],
    manifest_by_id: Mapping[str, ManifestEntry],
) -> bool:
    cutoff = _normalize_utc(request.get("audit_at"))
    if cutoff is None:
        return False
    return not any(
        (captured_at := _normalize_utc(manifest_by_id[file_id].captured_at))
        is not None
        and captured_at <= cutoff
        for file_id in incomplete_evidence_ids
        if file_id in manifest_by_id
    )


def _identity_fact_events(
    timeline: Iterable[TimelineEvent],
) -> dict[tuple[str, str | None], TimelineEvent]:
    return {
        (event.source_id, event.source_location): event
        for event in timeline
        if event.event_type == "evidence_observation"
    }


def _activity_resource_links(
    timeline: Iterable[TimelineEvent],
    user_id: str,
) -> dict[tuple[str, str], tuple[TimelineEvent, ...]]:
    links: dict[tuple[str, str], list[TimelineEvent]] = {}
    for event in timeline:
        if event.event_type != "process_activity" or user_id not in event.user_ids:
            continue
        details = dict(event.details)
        resource_id = details.get("resource_id", "").strip()
        systems = {
            details.get("source_system", "").strip(),
            details.get("target_system", "").strip(),
        } - {""}
        for system_id in systems:
            links.setdefault((resource_id, system_id), []).append(event)
    return {
        key: tuple(sorted(events, key=lambda event: event.source_id))
        for key, events in links.items()
        if key[0]
    }


def _activity_resource_targets(
    timeline: Iterable[TimelineEvent],
    user_id: str,
) -> dict[str, tuple[str, TimelineEvent]]:
    candidates: dict[str, dict[str, list[TimelineEvent]]] = {}
    for event in timeline:
        if (
            event.event_type != "process_activity"
            or user_id not in event.user_ids
            or event.identity_status != "confirmed"
            or event.cutoff_status != "in_scope"
        ):
            continue
        details = dict(event.details)
        resource_id = details.get("resource_id", "").strip()
        system_id = details.get("target_system", "").strip()
        if not resource_id or not system_id:
            continue
        if details.get("event_type", "").strip().upper() == "SYNC_RECORD":
            continue
        candidates.setdefault(resource_id, {}).setdefault(system_id, []).append(event)

    targets: dict[str, tuple[str, TimelineEvent]] = {}
    for resource_id, systems in candidates.items():
        if len(systems) != 1:
            continue
        system_id, events = next(iter(systems.items()))
        source_event = max(
            events,
            key=lambda event: (
                event.event_time or datetime.min.replace(tzinfo=timezone.utc),
                event.source_id,
            ),
        )
        targets[resource_id] = (system_id, source_event)
    return targets


def _policy_records(
    facts: Iterable[EvidenceFact],
    timeline: Iterable[TimelineEvent],
    user_id: str,
    rules: tuple[PolicyRule, ...],
    activity_links: Mapping[tuple[str, str], tuple[TimelineEvent, ...]],
    resolver: IdentityResolver,
    as_of: datetime,
) -> tuple[PolicyRecord, ...]:
    events = _identity_fact_events(timeline)
    activity_targets = _activity_resource_targets(timeline, user_id)
    rules_by_category = {
        rule.data_category.casefold(): rule for rule in rules
    }
    records: list[PolicyRecord] = []
    for fact in facts:
        event = events.get((fact.file_id, fact.source_location))
        if event is not None and user_id in event.user_ids:
            identity_status = event.identity_status
            temporal_status = event.cutoff_status
        else:
            activity_events = activity_links.get(
                (fact.resource_id or "", fact.system_id or ""),
                (),
            )
            if not activity_events:
                continue
            fact_resolution = resolver.resolve_fact(fact, as_of=as_of)
            if (
                fact_resolution.candidate_user_ids
                and user_id not in fact_resolution.candidate_user_ids
            ):
                continue
            identity_status = (
                fact_resolution.status
                if fact_resolution.candidate_user_ids
                else (
                    "confirmed"
                    if all(item.identity_status == "confirmed" for item in activity_events)
                    else "ambiguous"
                )
            )
            fact_temporal_status = (
                "unknown_time"
                if fact.captured_at is None and fact.event_timestamp is None
                else "in_scope"
            )
            temporal_status = (
                "in_scope"
                if fact_temporal_status == "in_scope"
                and all(item.cutoff_status == "in_scope" for item in activity_events)
                else "unknown_time"
            )
        target_system_id: str | None = None
        target_source_id: str | None = None
        target_source_file: str | None = None
        target_source_location: str | None = None
        if not fact.system_id and fact.resource_id:
            target = activity_targets.get(fact.resource_id)
            if target is not None:
                target_system_id, target_event = target
                target_source_id = target_event.source_id
                target_source_file = target_event.source_file
                target_source_location = target_event.source_location
        matching_categories = tuple(
            sorted(
                {
                    category
                    for category in fact.data_categories
                    if category.casefold() in rules_by_category
                },
                key=str.casefold,
            )
        )
        if matching_categories:
            for category in matching_categories:
                condition_values: dict[str, Any] = {}
                if category.casefold() == "account_tombstone":
                    condition_values["stable_user_id_reference_present"] = (
                        _has_confirmed_stable_user_reference(
                            fact,
                            resolver,
                            user_id,
                            as_of=as_of,
                        )
                    )
                records.append(
                    PolicyRecord(
                        replace(fact, data_categories=(category,)),
                        identity_status=identity_status,
                        applies_to_subject=True,
                        temporal_status=temporal_status,
                        condition_values=condition_values,
                        target_system_id=target_system_id,
                        target_system_source_id=target_source_id,
                        target_system_source_file=target_source_file,
                        target_system_source_location=target_source_location,
                    )
                )
            unknown_categories = tuple(
                category
                for category in fact.data_categories
                if category.casefold() not in rules_by_category
            )
            if unknown_categories:
                records.append(
                    PolicyRecord(
                        replace(fact, data_categories=unknown_categories),
                        identity_status=identity_status,
                        applies_to_subject=True,
                        temporal_status=temporal_status,
                        target_system_id=target_system_id,
                        target_system_source_id=target_source_id,
                        target_system_source_file=target_source_file,
                        target_system_source_location=target_source_location,
                    )
                )
        else:
            records.append(
                PolicyRecord(
                    fact,
                    identity_status=identity_status,
                    applies_to_subject=True,
                    temporal_status=temporal_status,
                    target_system_id=target_system_id,
                    target_system_source_id=target_source_id,
                    target_system_source_file=target_source_file,
                    target_system_source_location=target_source_location,
                )
            )
    return tuple(records)


def _field_values(fact: EvidenceFact) -> dict[str, set[str]]:
    values: dict[str, set[str]] = {}
    for field in fact.observed_fields:
        values.setdefault(field.name.casefold(), set()).add(field.value.strip())
    return values


def _normalize_evidence_fact(
    fact: EvidenceFact,
    *,
    policy_categories: Iterable[str] = (),
) -> EvidenceFact:
    """Map explicit inventory labels to policy categories without losing provenance."""
    field_names = {field.name.casefold() for field in fact.observed_fields}
    categories: set[str] = set()
    source_categories = fact.data_categories
    values = _field_values(fact)
    system_id = fact.system_id
    record_state = fact.record_state
    service = next(iter(values.get("service", set())), "")
    event = next(iter(values.get("event", set())), "")
    if system_id is None and service:
        system_id = service
    event_category = _SERVICE_EVENT_CATEGORIES.get((service, event))
    if (
        service == "search_service"
        and event == "index_query_completed"
        and values.get("result") == {"hit"}
    ):
        event_category = "SEARCH_INDEX_ENTRY"
    if not source_categories and event_category is not None:
        source_categories = (event_category,)
    source_location_parts = fact.source_location.strip("/").split("/")
    if (
        len(source_location_parts) >= 3
        and source_location_parts[0] == "service_exports"
    ):
        service_id = source_location_parts[1]
        if system_id is None:
            system_id = service_id
        service_category = _SERVICE_EXPORT_CATEGORIES.get(
            f"{service_id}/{source_location_parts[2]}"
        )
        if (
            service_id == "search_service"
            and source_location_parts[2] == "index_queries"
            and "hits" in source_location_parts[3:]
            and "documents" in source_location_parts[3:]
        ):
            service_category = "SEARCH_INDEX_ENTRY"
        if not source_categories and service_category is not None:
            source_categories = (service_category,)
        if (
            service_id == "account_service"
            and source_location_parts[2] == "profile_lookups"
            and values.get("status_code") == {"404"}
            and record_state is None
        ):
            record_state = "ABSENT"
        elif (
            service_id == "account_service"
            and source_location_parts[2] == "profile_lookups"
            and values.get("status_code") == {"200"}
            and record_state is None
        ):
            record_state = "PRESENT"
    elif (
        not source_categories
        and Path(fact.source_path).name.casefold().startswith("customer_export_jobs_")
    ):
        source_categories = ("USER_EXPORT",)
    if (
        not source_categories
        and "security_service" in values.get("service", set())
        and "audit_record_read_completed" in values.get("event", set())
    ):
        source_categories = ("SECURITY_AUDIT_LOG",)
    if not source_categories and fact.source_location.startswith("table:"):
        table_name = fact.source_location[len("table:"):].split("/", 1)[0]
        if system_id is None:
            system_id = _TABLE_SYSTEM_ALIASES.get(table_name.casefold())
        if table_name.casefold() in _POLICY_CATEGORY_ALIASES:
            source_categories = (table_name,)
    if system_id is None:
        # The JSON inventory explicitly names its collection.  This is an
        # authoritative source target, unlike a connector label or inferred
        # lineage edge.
        collection = next(iter(values.get("collection", set())), "")
        system_id = _TABLE_SYSTEM_ALIASES.get(collection.casefold())
    if not source_categories:
        known_categories = {
            category.casefold()
            for category in policy_categories
        } | {
            category.casefold()
            for category in _POLICY_CATEGORY_ALIASES.values()
        } | {"data_flow"}
        for field_name in ("data_category", "record_type", "category", "data_type"):
            labels = values.get(field_name, set())
            mapped_labels = tuple(
                label
                for label in labels
                if label.casefold() in known_categories
                or label.casefold() in _POLICY_CATEGORY_ALIASES
            )
            if mapped_labels:
                source_categories = mapped_labels
                break
    if record_state is None:
            if (
                service == "account_service"
                and event == "profile_lookup_completed"
                and values.get("rows") == {"0"}
            ):
                record_state = "ABSENT"
            elif event_category is not None and event.endswith("_completed"):
                record_state = "PRESENT"
            elif (
                event == "record_lookup"
                and service in {"downstream_delivery_service", "search_index_service"}
            ):
                result = next(iter(values.get("result", set())), "").casefold()
                record_state = {
                    "active": "PRESENT",
                    "anonymized": "ANONYMIZED",
                    "found": "PRESENT",
                    "identifiable": "PRESENT",
                    "not_found": "ABSENT",
                }.get(result)
    for category in source_categories:
        normalized = _POLICY_CATEGORY_ALIASES.get(
            category.casefold(),
            category,
        )
        if (
            category.casefold() == "connector_configurations"
            and field_names
            & {"subject_selector", "subject_reference", "lookup_value"}
            and "mode" in field_names
            and field_names & {"destination", "target_system", "target_system_id", "to_system"}
            and field_names & {"enabled", "active", "is_active"}
        ):
            normalized = "DATA_FLOW"
        categories.add(normalized)
    return replace(
        fact,
        data_categories=tuple(sorted(categories, key=str.casefold)),
        system_id=system_id,
        record_state=record_state,
    )


def _is_non_resource_read_attempt(fact: EvidenceFact) -> bool:
    events = _field_values(fact).get("event", set())
    if fact.data_categories:
        return False
    if events & _NON_RESOURCE_READ_EVENTS:
        return True
    if (
        fact.source_location.startswith("/service_exports/search_service/index_queries/")
        and "/hits/documents/" not in fact.source_location
    ):
        return True
    values = _field_values(fact)
    return (
        "search_service" in values.get("service", set())
        and events & {"index_query_started", "index_query_completed"}
        and values.get("result") != {"hit"}
    )


def _prohibited_resources(
    records: Iterable[PolicyRecord],
    rules: tuple[PolicyRule, ...],
    as_of: datetime,
) -> dict[str, bool]:
    rules_by_category = {
        rule.data_category.casefold(): rule for rule in rules
    }
    prohibited: dict[str, bool] = {}
    for record in records:
        resource_id = record.fact.resource_id
        category = next(iter(record.fact.data_categories), "").casefold()
        rule = rules_by_category.get(category)
        if (
            not resource_id
            or rule is None
            or record.identity_status != "confirmed"
            or record.temporal_status != "in_scope"
        ):
            continue
        decision = evaluate_policy_record(record, rule, as_of=as_of)
        if decision.disposition is EvidenceDisposition.VIOLATION:
            prohibited[resource_id] = True
        elif resource_id not in prohibited and decision.disposition is EvidenceDisposition.COMPLIANT:
            prohibited[resource_id] = False
        if category == "backup_archive":
            restore_allowed = _field_values(record.fact).get("restore_allowed", set())
            if restore_allowed & {"true", "1", "yes", "enabled", "allowed"}:
                prohibited[resource_id] = True
    return prohibited


def _has_confirmed_stable_user_reference(
    fact: EvidenceFact,
    resolver: IdentityResolver,
    user_id: str,
    *,
    as_of: datetime,
) -> bool:
    for candidate in fact.candidate_identifiers:
        if candidate.field_name.casefold() not in {"subject_reference", "user_id"}:
            continue
        resolution = resolver.resolve_identifier(
            candidate.field_name,
            candidate.value,
            at=fact.event_timestamp,
            as_of=as_of,
        )
        if resolution.status == "confirmed" and resolution.user_id == user_id:
            return True
    return False


def _case_row(
    request: Mapping[str, str],
    facts: tuple[EvidenceFact, ...],
    activity: tuple[dict[str, Any], ...],
    resolver: IdentityResolver,
    rules: tuple[PolicyRule, ...],
    *,
    evidence_complete: bool,
) -> tuple[dict[str, str], bool, int]:
    case_id = request["case_id"]
    if not is_deletion_request(request["request_text"]):
        return {
            "case_id": case_id,
            "deletion_status": DeletionStatus.NOT_APPLICABLE.value,
            "steps_json": "[]",
        }, False, 0

    cutoff = _normalize_utc(request["audit_at"])
    if cutoff is None:
        raise CaseProcessingError(
            case_id,
            "request",
            "audit_at is missing or invalid",
            "invalid_audit_cutoff",
        )

    identity: IdentityResolution = resolver.resolve_request(
        request,
        as_of=cutoff,
    )
    if identity.status != "confirmed" or identity.user_id is None:
        raise CaseProcessingError(
            case_id,
            "identity",
            "request email does not resolve to one stable subject at the cutoff",
            "identity_unresolved",
        )

    timeline = reconstruct_timeline(
        request,
        resolver,
        activity_events=activity,
    )
    case_facts = tuple(
        fact
        for fact in facts
        if not _known_future_observation(fact, cutoff)
    )
    subject_events = _identity_fact_events(timeline)
    activity_links = _activity_resource_links(timeline, identity.user_id)
    subject_facts = tuple(
        fact
        for fact in case_facts
        if (fact.file_id, fact.source_location) in subject_events
        or (fact.resource_id or "", fact.system_id or "") in activity_links
    )
    subject_facts = tuple(
        fact for fact in subject_facts if not _is_non_resource_read_attempt(fact)
    )
    records = _policy_records(
        subject_facts,
        timeline,
        identity.user_id,
        rules,
        activity_links,
        resolver,
        cutoff,
    )
    prohibited_by_resource = _prohibited_resources(records, rules, cutoff)
    resources = resource_evidence_from_facts(
        subject_facts,
        resolver,
        identity.user_id,
        as_of=cutoff,
        prohibited_by_resource=prohibited_by_resource,
    )
    graph = build_lineage_graph(
        activity,
        case_facts,
        timeline,
        resolver,
        as_of=cutoff,
    )
    lineage = analyze_resurrection_paths(graph, identity.user_id, resources)
    confirmed_flow_ids = {
        edge.source_evidence_id
        for edge in graph.edges
        if (
            edge.process_type == "DATA_FLOW_CONFIG"
            and edge.activity_state == "ACTIVE"
            and edge.confidence == "confirmed"
            and identity.user_id in edge.applicable_user_ids
        )
    }
    flow_records = tuple(
        PolicyRecord(
            fact,
            identity_status="confirmed",
            applies_to_subject=True,
            temporal_status="in_scope",
        )
        for fact in case_facts
        if fact.file_id in confirmed_flow_ids
        and any(category.casefold() == "data_flow" for category in fact.data_categories)
    )
    evaluation = evaluate_request(
        request,
        (*records, *flow_records),
        rules=rules,
        lineage_analysis=lineage,
        as_of=cutoff,
        evidence_complete=evidence_complete,
    )
    try:
        plan = plan_remediation(evaluation)
    except PlanningError as exc:
        raise CaseProcessingError(
            case_id,
            "planning",
            str(exc),
            "planning_not_representable",
        ) from exc
    if plan.status is not evaluation.status:
        raise CaseProcessingError(
            case_id,
            "planning",
            "planner status does not match policy evaluation",
            "planner_status_mismatch",
        )

    row = {
        "case_id": case_id,
        "deletion_status": plan.status.value,
        "steps_json": json.dumps(
            list(plan.steps),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ),
    }
    uncertain = bool(
        evaluation.unresolved_evidence
        or evaluation.unresolved_lineage
        or lineage.possible_paths
    )
    ambiguous_facts = sum(
        1
        for record in records
        if record.identity_status != "confirmed"
    )
    return row, uncertain, ambiguous_facts


def _write_output(path: Path, rows: Iterable[Mapping[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _write_output_requests(
    path: Path,
    requests: Iterable[Mapping[str, str]],
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=REQUEST_COLUMNS)
        writer.writeheader()
        writer.writerows(requests)


def _failure_classification(failure: CaseFailure) -> str:
    """Classify a non-representable case without turning it into a prediction."""
    message = failure.error_message.casefold()
    if "missing or uncertain source system" in message:
        return "ambiguous policy condition"
    if "condition for rule_" in message or "no identity-scoped" in message:
        return "genuine evidence gap"
    if "evidence inventory completeness" in message:
        return "unsupported evidence format"
    if failure.stage == "identity":
        return "genuine evidence gap"
    return "contract/schema defect"


def _write_failure_diagnostics(path: Path, failures: Iterable[CaseFailure]) -> None:
    """Write a case-level report for failures without exposing request PII."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "case_id",
                "failure_stage",
                "exception_type",
                "reason_code",
                "classification",
                "error_message",
                "cause_type",
                "cause_message",
            ),
        )
        writer.writeheader()
        for failure in sorted(failures, key=lambda item: item.case_id):
            writer.writerow(
                {
                    "case_id": failure.case_id,
                    "failure_stage": failure.stage,
                    "exception_type": failure.error_type,
                    "reason_code": failure.reason_code,
                    "classification": _failure_classification(failure),
                    "error_message": failure.error_message,
                    "cause_type": failure.cause_type,
                    "cause_message": failure.cause_message,
                }
            )


def _validate_generated_rows(
    rows: tuple[dict[str, str], ...],
    requests: tuple[dict[str, str], ...],
    requests_path: Path,
    dataset_dir: Path,
    *,
    expected_case_count: int | None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="ghost-pipeline-validation-") as temp:
        temporary_root = Path(temp)
        output_path = temporary_root / "output.csv"
        _write_output(output_path, rows)
        if len(rows) == len(requests):
            validate_output(
                output_path,
                requests_path,
                dataset_dir / "evidence_files.csv",
                dataset_dir / "system_activity.csv",
                dataset_dir / "user_audit_log.csv",
                expected_case_count=expected_case_count,
            )
            return

        request_ids = {row["case_id"] for row in rows}
        subset_path = temporary_root / "requests.csv"
        _write_output_requests(
            subset_path,
            (request for request in requests if request["case_id"] in request_ids),
        )
        validate_output(
            output_path,
            subset_path,
            dataset_dir / "evidence_files.csv",
            dataset_dir / "system_activity.csv",
            dataset_dir / "user_audit_log.csv",
            expected_case_count=len(rows),
        )


def run_pipeline(
    dataset_dir: str | Path,
    *,
    requests_path: str | Path | None = None,
    output_path: str | Path | None = None,
    diagnostics_path: str | Path | None = None,
    expected_case_count: int | None = 518,
    logger: logging.Logger | None = None,
) -> PipelineResult:
    """Audit requests independently and write only a fully valid output file.

    A malformed evidence file is recorded and skipped without terminating the
    other file extractions. Since its unknown contents could affect any subject,
    the evidence inventory is marked incomplete; cases that cannot be safely
    planned are reported and prevent output replacement.
    """
    log = logger or logging.getLogger("ghost_data_pipeline")
    dataset = Path(dataset_dir).resolve()
    request_file = (
        Path(requests_path).resolve()
        if requests_path is not None
        else dataset / "deletion_requests.csv"
    )
    destination = Path(output_path).resolve() if output_path is not None else None
    protected_outputs = {
        (dataset / "output.csv").resolve(),
        (dataset / "sample_output.csv").resolve(),
    }
    if destination in protected_outputs:
        raise PipelineInputError(
            "Refusing to overwrite dataset/output.csv or dataset/sample_output.csv"
        )

    requests = _read_requests(request_file)
    if expected_case_count is not None and len(requests) != expected_case_count:
        raise PipelineInputError(
            f"{request_file}: expected {expected_case_count} request rows, "
            f"found {len(requests)}"
        )
    _structured_log(
        log,
        logging.INFO,
        "pipeline_started",
        request_count=len(requests),
        dataset=str(dataset),
    )

    manifest: tuple[ManifestEntry, ...] = load_manifest(
        dataset / "evidence_files.csv"
    ).entries
    facts: list[EvidenceFact] = []
    warnings: list[ExtractionWarning] = []
    evidence_failures: list[tuple[str, str]] = []
    for entry in manifest:
        try:
            extraction = ingest_manifest_entry(entry)
        except EvidenceIngestionError as exc:
            evidence_failures.append((entry.file_id, type(exc).__name__))
            _structured_log(
                log,
                logging.ERROR,
                "evidence_file_failed",
                evidence_id=entry.file_id,
                error_type=type(exc).__name__,
            )
            continue
        facts.extend(extraction.facts)
        warnings.extend(extraction.warnings)
        for warning in extraction.warnings:
            _structured_log(
                log,
                logging.WARNING,
                "evidence_extraction_warning",
                evidence_id=warning.file_id,
                warning_code=warning.code,
            )

    warning_counts = Counter(warning.code for warning in warnings)
    incomplete_evidence_ids = {file_id for file_id, _ in evidence_failures}
    incomplete_evidence_ids.update(
        warning.file_id
        for warning in warnings
        if warning.code == _OCR_LIMITATION
    )
    manifest_by_id = {entry.file_id: entry for entry in manifest}
    _structured_log(
        log,
        logging.INFO,
        "evidence_ingested",
        manifest_entries=len(manifest),
        files_ingested=len(manifest) - len(evidence_failures),
        evidence_failures=len(evidence_failures),
        fact_count=len(facts),
        warning_counts=dict(sorted(warning_counts.items())),
        files_with_incomplete_extraction=len(incomplete_evidence_ids),
    )

    rules = load_policy_rules(dataset / "deletion_rules.csv")
    if len(rules) != EXPECTED_POLICY_RULES:
        raise PipelineInputError(
            f"Expected {EXPECTED_POLICY_RULES} policy rules; found {len(rules)}"
        )
    policy_categories = {rule.data_category for rule in rules}
    evidence_facts = tuple(
        _normalize_evidence_fact(fact, policy_categories=policy_categories)
        for fact in facts
    )
    resolver = load_identity_resolver(
        dataset / "user_identities.csv",
        dataset / "user_audit_log.csv",
        evidence_facts=evidence_facts,
    )
    activity = load_activity_events(dataset / "system_activity.csv")
    rule_categories = {rule.data_category.casefold() for rule in rules}
    _structured_log(
        log,
        logging.INFO,
        "pipeline_inputs_loaded",
        identity_count=len(resolver.user_ids),
        activity_count=len(activity),
        policy_rule_count=len(rules),
        policy_categories=len(rule_categories),
    )

    output_rows: list[dict[str, str]] = []
    failures: list[CaseFailure] = []
    unresolved_identity_count = 0
    uncertain_case_count = 0
    ambiguous_fact_count = 0
    for index, request in enumerate(requests, start=1):
        try:
            row, uncertain, ambiguous_facts = _case_row(
                request,
                evidence_facts,
                activity,
                resolver,
                rules,
                evidence_complete=_evidence_complete_at_cutoff(
                    request,
                    incomplete_evidence_ids,
                    manifest_by_id,
                ),
            )
        except CaseProcessingError as exc:
            cause = exc.__cause__
            failures.append(
                CaseFailure(
                    exc.case_id,
                    exc.stage,
                    type(exc).__name__,
                    exc.reason_code,
                    str(exc),
                    type(cause).__name__ if cause is not None else "",
                    str(cause) if cause is not None else "",
                )
            )
            if exc.stage == "identity":
                unresolved_identity_count += 1
            _structured_log(
                log,
                logging.ERROR,
                "case_failed",
                case_id=request["case_id"],
                stage=exc.stage,
                error_type=type(exc).__name__,
                reason_code=exc.reason_code,
                error_message=str(exc),
                cause_type=type(cause).__name__ if cause is not None else "",
                cause_message=str(cause) if cause is not None else "",
            )
        else:
            output_rows.append(row)
            uncertain_case_count += int(uncertain)
            ambiguous_fact_count += ambiguous_facts
        if index % 50 == 0 or index == len(requests):
            _structured_log(
                log,
                logging.INFO,
                "pipeline_progress",
                processed=index,
                total=len(requests),
                successful_rows=len(output_rows),
                failed_cases=len(failures),
            )

    ordered_rows = tuple(sorted(output_rows, key=lambda row: row["case_id"]))
    ordered_failures = tuple(sorted(failures, key=lambda item: item.case_id))
    status_counts = Counter(row["deletion_status"] for row in ordered_rows)
    destination_written = False
    _validate_generated_rows(
        ordered_rows,
        requests,
        request_file,
        dataset,
        expected_case_count=(
            expected_case_count if not ordered_failures else None
        ),
    )

    if not ordered_failures and destination is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                newline="",
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
                delete=False,
            ) as handle:
                temporary_path = Path(handle.name)
                writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
                writer.writeheader()
                writer.writerows(ordered_rows)
            validate_output(
                temporary_path,
                request_file,
                dataset / "evidence_files.csv",
                dataset / "system_activity.csv",
                dataset / "user_audit_log.csv",
                expected_case_count=expected_case_count,
            )
            os.replace(temporary_path, destination)
            destination_written = True
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()

    _structured_log(
        log,
        logging.INFO if not ordered_failures else logging.ERROR,
        "pipeline_finished",
        request_count=len(requests),
        successful_rows=len(ordered_rows),
        status_counts=dict(sorted(status_counts.items())),
        unresolved_identities=unresolved_identity_count,
        ambiguous_evidence_matches=ambiguous_fact_count,
        uncertain_cases=uncertain_case_count,
        failed_cases=len(ordered_failures),
        output_written=destination_written,
        output_path=str(destination) if destination_written else None,
    )
    result = PipelineResult(
        request_count=len(requests),
        evidence_file_count=len(manifest),
        ingested_evidence_count=len(manifest) - len(evidence_failures),
        evidence_fact_count=len(evidence_facts),
        evidence_warning_counts=tuple(sorted(warning_counts.items())),
        evidence_failure_count=len(evidence_failures),
        unresolved_identity_count=unresolved_identity_count,
        uncertain_case_count=uncertain_case_count,
        status_counts=tuple(sorted(status_counts.items())),
        rows=ordered_rows,
        failures=ordered_failures,
        output_path=destination if destination_written else None,
        output_written=destination_written,
    )
    if diagnostics_path is not None:
        _write_failure_diagnostics(Path(diagnostics_path).resolve(), result.failures)
    return result


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset",
        type=Path,
        default=repo_root / "dataset",
        help="dataset directory (default: repository dataset/)",
    )
    parser.add_argument(
        "--requests",
        type=Path,
        help="request CSV (default: dataset/deletion_requests.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "output.csv",
        help="validated output path (default: repository-root output.csv)",
    )
    parser.add_argument(
        "--diagnostics",
        type=Path,
        help="optional case-level CSV report for non-representable requests",
    )
    parser.add_argument(
        "--expected-cases",
        type=int,
        default=518,
        help="expected number of request rows (default: 518)",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(level=args.log_level, format="%(message)s")
    try:
        result = run_pipeline(
            args.dataset,
            requests_path=args.requests,
            output_path=args.output,
            diagnostics_path=args.diagnostics,
            expected_case_count=args.expected_cases,
        )
    except (PipelineInputError, EvidenceIngestionError, ValueError) as exc:
        _structured_log(
            logging.getLogger("ghost_data_pipeline"),
            logging.ERROR,
            "pipeline_aborted",
            error_type=type(exc).__name__,
        )
        return 1
    if result.failures:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
