"""Deterministic, evidence-backed data-lineage and resurrection-path analysis."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from evidence_model import EvidenceFact, parse_timestamp
from identity_timeline import (
    IdentityLink,
    IdentityResolution,
    IdentityResolver,
    TimelineEvent,
    load_activity_events,
)


_TRANSFER_EVENT_TYPES = {
    "CREATE_EXPORT",
    "INDEX_RECORD",
    "RESTORE_BACKUP",
    "SYNC_RECORD",
}
_ACTIVE_FLOW_MODES = {"continuous_sync"}
_SOURCE_FIELDS = ("source_system", "source_system_id", "from_system")
_DESTINATION_FIELDS = (
    "target_system",
    "target_system_id",
    "destination",
    "to_system",
)
_TRUE_VALUES = {"1", "true", "yes", "enabled", "active"}
_FALSE_VALUES = {"0", "false", "no", "disabled", "inactive"}


def _utc(value: Any) -> datetime | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _field_values(fact: EvidenceFact) -> dict[str, tuple[str, ...]]:
    values: dict[str, set[str]] = {}
    for field in fact.observed_fields:
        values.setdefault(field.name.casefold(), set()).add(field.value)
    return {
        name: tuple(sorted(items))
        for name, items in values.items()
    }


def _first_field(values: Mapping[str, tuple[str, ...]], names: tuple[str, ...]) -> str | None:
    for name in names:
        observed = values.get(name)
        if observed:
            return observed[0].strip() or None
    return None


def _bool_value(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().casefold()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return None


def _fact_is_data_flow(fact: EvidenceFact) -> bool:
    values = _field_values(fact)
    labels = set(fact.data_categories)
    labels.update(value for value in values.get("record_type", ()))
    return any(label.strip().casefold() == "data_flow" for label in labels)


def _resolve_selector(
    fact: EvidenceFact,
    resolver: IdentityResolver,
    *,
    at: datetime | None,
    as_of: datetime | None,
) -> IdentityResolution:
    values = _field_values(fact)
    selectors = []
    for field_name in ("subject_selector", "subject_reference", "lookup_value"):
        selectors.extend(values.get(field_name, ()))

    candidates: set[str] = set()
    ambiguous = False
    matched_links = []
    for selector in sorted(set(selectors)):
        if "@" in selector:
            result = resolver.resolve_identifier(
                "email", selector, at=at, as_of=as_of
            )
            results = (result,)
        else:
            results = (
                resolver.resolve_identifier(
                    "user_id", selector, at=at, as_of=as_of
                ),
                resolver.resolve_identifier(
                    "email", selector, at=at, as_of=as_of
                ),
                resolver.resolve_identifier(
                    "phone", selector, at=at, as_of=as_of
                ),
                resolver.resolve_identifier(
                    "email_hash", selector, at=at, as_of=as_of
                ),
            )
        for result in results:
            candidates.update(result.candidate_user_ids)
            ambiguous = ambiguous or result.status == "ambiguous"
            matched_links.extend(result.matched_links)

    sorted_candidates = tuple(sorted(candidates))
    if ambiguous or len(sorted_candidates) > 1:
        status, user_id, reason = (
            "ambiguous",
            None,
            "flow subject selector has multiple or uncertain identity matches",
        )
    elif sorted_candidates:
        status, user_id, reason = (
            "confirmed",
            sorted_candidates[0],
            "flow subject selector exactly matches one stable user",
        )
    else:
        status, user_id, reason = (
            "unmatched",
            None,
            "flow has no subject selector linked to a known stable user",
        )
    return IdentityResolution(
        status,
        "subject_selector",
        "|".join(sorted(set(selectors))),
        None,
        user_id,
        sorted_candidates,
        tuple(matched_links),
        reason,
    )


@dataclass(frozen=True)
class ResourceEvidence:
    """A user's resource observation; policy judgment is caller-supplied."""

    resource_id: str
    system_id: str
    user_id: str
    contains_personal_data: bool
    contains_prohibited_data: bool | None
    evidence_id: str
    source_file: str
    source_location: str
    observed_at: datetime | None
    captured_at: datetime | None
    identity_status: str
    temporal_status: str = "in_scope"
    identity_links: tuple[IdentityLink, ...] = ()
    record_state: str | None = None
    data_categories: tuple[str, ...] = ()
    candidate_user_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class LineageEdge:
    """One directed, provenance-bearing flow or observed transfer operation."""

    edge_id: str
    source_node: str | None
    destination_node: str | None
    activity_id: str
    resource_id: str | None
    process_type: str
    activity_state: str
    reported_result: str | None
    valid_from: datetime | None
    valid_to: datetime | None
    observed_at: datetime | None
    captured_at: datetime | None
    source_evidence_id: str
    source_file: str
    source_location: str
    confidence: str
    identity_status: str
    applicable_user_ids: tuple[str, ...]
    propagation_supported: bool
    ambiguity_reason: str
    identity_links: tuple[IdentityLink, ...] = ()


@dataclass(frozen=True)
class LineageGraph:
    as_of: datetime | None
    edges: tuple[LineageEdge, ...]
    activity_observations: tuple[TimelineEvent, ...] = ()


@dataclass(frozen=True)
class ResurrectionPath:
    user_id: str
    confidence: str
    nodes: tuple[str, ...]
    edges: tuple[LineageEdge, ...]
    source_resources: tuple[ResourceEvidence, ...]
    destination_resources: tuple[ResourceEvidence, ...]
    supporting_evidence_ids: tuple[str, ...]
    finding: str


@dataclass(frozen=True)
class UnresolvedLineage:
    user_id: str
    edge: LineageEdge
    reason: str


@dataclass(frozen=True)
class ResurrectionAnalysis:
    user_id: str
    confirmed_paths: tuple[ResurrectionPath, ...]
    possible_paths: tuple[ResurrectionPath, ...]
    unresolved_lineage: tuple[UnresolvedLineage, ...]


@dataclass(frozen=True)
class RemediationSimulation:
    """A read-only hypothetical graph result, never an applied system change."""

    hypothetical: bool
    removed_edge_ids: tuple[str, ...]
    before: ResurrectionAnalysis
    after: ResurrectionAnalysis
    broken_confirmed_paths: tuple[ResurrectionPath, ...]
    remaining_confirmed_paths: tuple[ResurrectionPath, ...]


def _edge_sort_key(edge: LineageEdge) -> tuple[str, ...]:
    return (
        edge.source_node or "",
        edge.destination_node or "",
        edge.activity_id,
        edge.resource_id or "",
        edge.process_type,
        edge.activity_state,
        edge.source_evidence_id,
        edge.source_file,
        edge.source_location,
        edge.edge_id,
    )


def _edge_id(
    source_node: str | None,
    destination_node: str | None,
    source_evidence_id: str,
    activity_id: str,
    process_type: str,
) -> str:
    return "|".join(
        (
            source_node or "?",
            destination_node or "?",
            source_evidence_id,
            activity_id,
            process_type,
        )
    )


def _flow_config_edge(
    fact: EvidenceFact,
    resolver: IdentityResolver,
    *,
    as_of: datetime | None,
) -> LineageEdge:
    values = _field_values(fact)
    source = _first_field(values, _SOURCE_FIELDS)
    destination = _first_field(values, _DESTINATION_FIELDS)
    mode = _first_field(values, ("mode",))
    enabled = _bool_value(_first_field(values, ("enabled", "active", "is_active")))
    recorded_at = _utc(fact.event_timestamp) or _utc(fact.captured_at)
    valid_from = _utc(_first_field(values, ("valid_from", "starts_at"))) or recorded_at
    valid_to = _utc(_first_field(values, ("valid_to", "valid_until", "ends_at")))
    source_id = fact.resource_id or fact.file_id
    identity = _resolve_selector(
        fact, resolver, at=recorded_at, as_of=as_of
    )
    if enabled is False:
        activity_state = "INACTIVE"
    elif enabled is True and mode and mode.casefold() in _ACTIVE_FLOW_MODES:
        activity_state = "ACTIVE"
    else:
        activity_state = "UNKNOWN"

    complete_endpoints = bool(source and destination)
    complete_state = activity_state == "ACTIVE"
    if complete_endpoints and complete_state and identity.status == "confirmed":
        confidence = "confirmed"
        reason = ""
        propagation_supported = True
    elif (
        complete_endpoints
        and complete_state
        and identity.status == "ambiguous"
        and identity.candidate_user_ids
    ):
        confidence = "ambiguous"
        reason = identity.reason
        propagation_supported = True
    else:
        confidence = "ambiguous" if identity.status == "ambiguous" else "unsupported"
        missing = []
        if not source:
            missing.append("source system")
        if not destination:
            missing.append("destination system")
        if activity_state != "ACTIVE":
            missing.append("explicit enabled continuous-sync state")
        if identity.status != "confirmed":
            missing.append("unique subject identity")
        reason = (
            "missing or uncertain " + ", ".join(missing)
            if missing
            else identity.reason
        )
        propagation_supported = False

    # A capture after the request cutoff is filtered by the graph builder.
    # Missing capture/event time does not establish that the configuration
    # existed at a historical cutoff.
    if recorded_at is None:
        confidence = "unsupported"
        activity_state = "UNKNOWN"
        propagation_supported = False
        reason = "flow configuration observation has no usable timestamp"
    elif as_of is not None and recorded_at > as_of:
        confidence = "unsupported"
        activity_state = "UNKNOWN"
        propagation_supported = False
        reason = "flow configuration was observed after the as-of cutoff"
    elif as_of is not None and valid_from is not None and valid_from > as_of:
        confidence = "unsupported"
        activity_state = "UNKNOWN"
        propagation_supported = False
        reason = "flow validity begins after the as-of cutoff"
    elif as_of is not None and valid_to is not None and valid_to <= as_of:
        confidence = "unsupported"
        activity_state = "INACTIVE"
        propagation_supported = False
        reason = "flow validity ended before the as-of cutoff"
    elif (
        as_of is not None
        and recorded_at < as_of
        and valid_to is None
        and activity_state == "INACTIVE"
    ):
        confidence = "ambiguous"
        activity_state = "UNKNOWN"
        reason = (
            "inactive configuration was observed before the cutoff, with no "
            "validity interval proving the state persisted"
        )
    elif confidence == "confirmed" and (
        as_of is None
        or not (
            as_of == recorded_at
            or (
                valid_from is not None
                and valid_to is not None
                and valid_from <= as_of < valid_to
            )
        )
    ):
        confidence = "ambiguous"
        reason = (
            "active configuration was observed at a different time, with no "
            "validity interval proving it remained active at the cutoff"
        )

    return LineageEdge(
        _edge_id(source, destination, fact.file_id, source_id, "DATA_FLOW_CONFIG"),
        source,
        destination,
        source_id,
        fact.resource_id,
        "DATA_FLOW_CONFIG",
        activity_state,
        _first_field(values, ("result", "status", "state")),
        valid_from,
        valid_to,
        recorded_at,
        _utc(fact.captured_at),
        fact.file_id,
        fact.source_path,
        fact.source_location,
        confidence,
        identity.status,
        identity.candidate_user_ids,
        propagation_supported,
        reason,
        tuple(
            sorted(
                set(identity.matched_links),
                key=lambda link: (
                    link.user_id,
                    link.field_name,
                    link.normalized_value,
                    link.source,
                    link.source_file or "",
                    link.source_location or "",
                    link.audit_id or "",
                ),
            )
        ),
    )


def _activity_edge(
    activity: Mapping[str, Any],
    timeline_event: TimelineEvent,
    *,
    as_of: datetime | None,
) -> LineageEdge | None:
    process_type = str(activity.get("event_type") or "").strip().upper()
    if process_type not in _TRANSFER_EVENT_TYPES:
        return None
    source = str(activity.get("source_system") or "").strip() or None
    destination = str(activity.get("target_system") or "").strip() or None
    event_time = _utc(activity.get("event_time"))
    reported_result = str(activity.get("reported_result") or "").strip() or None
    identity_status = timeline_event.identity_status
    complete = bool(source and destination)
    if (
        complete
        and identity_status == "confirmed"
        and reported_result
        and reported_result.upper() == "SUCCESS"
    ):
        confidence = "ambiguous"
        reason = (
            "directed transfer is reported for this subject, but one event "
            "does not establish a persistent active flow"
        )
    else:
        confidence = "ambiguous" if identity_status == "ambiguous" else "unsupported"
        reason = (
            "activity row lacks explicit source/destination, unique subject "
            "identity, or a successful reported result"
        )
    if event_time is None:
        confidence = "unsupported"
        reason = "activity event has no usable timestamp"
    elif as_of is not None and event_time > as_of:
        return None

    activity_id = str(activity.get("activity_id") or timeline_event.source_id)
    source_file = str(activity.get("_source_file") or "system_activity.csv")
    source_location = str(activity.get("_source_location") or "")
    resource_id = str(activity.get("resource_id") or "").strip()
    return LineageEdge(
        _edge_id(source, destination, activity_id, activity_id, process_type),
        source,
        destination,
        activity_id,
        resource_id or None,
        process_type,
        "OBSERVED",
        reported_result,
        event_time,
        None,
        event_time,
        None,
        activity_id,
        source_file,
        source_location,
        confidence,
        identity_status,
        timeline_event.user_ids,
        False,
        reason,
    )


def build_lineage_graph(
    activity_events: Iterable[Mapping[str, Any]],
    evidence_facts: Iterable[EvidenceFact],
    timeline: Iterable[TimelineEvent],
    resolver: IdentityResolver,
    *,
    as_of: Any = None,
) -> LineageGraph:
    """Build only observed or explicitly configured edges known by ``as_of``.

    An observed transfer activity is retained as an observation, never upgraded
    to a persistent active flow based on ``reported_result`` alone.
    """
    cutoff = _utc(as_of)
    timeline_events = tuple(timeline)
    activity_rows = tuple(activity_events)
    timeline_by_activity = {
        event.source_id: event
        for event in timeline_events
        if event.event_type == "process_activity"
    }
    activity_observations = tuple(
        sorted(
            (
                event
                for event in timeline_events
                if event.event_type == "process_activity"
                and not (
                    cutoff is not None
                    and _utc(event.event_time) is not None
                    and _utc(event.event_time) > cutoff
                )
            ),
            key=lambda event: (
                _utc(event.event_time)
                or datetime.min.replace(tzinfo=timezone.utc),
                event.source_id,
                event.source_file or "",
                event.source_location or "",
            ),
        )
    )
    edges: list[LineageEdge] = []

    for activity in activity_rows:
        activity_id = str(activity.get("activity_id") or "")
        timeline_event = timeline_by_activity.get(activity_id)
        if timeline_event is None:
            continue
        event_time = _utc(activity.get("event_time"))
        if cutoff is not None and event_time is not None and event_time > cutoff:
            continue
        edge = _activity_edge(activity, timeline_event, as_of=cutoff)
        if edge is not None:
            edges.append(edge)

    for fact in evidence_facts:
        if not _fact_is_data_flow(fact):
            continue
        captured_at = _utc(fact.captured_at)
        event_time = _utc(fact.event_timestamp)
        if cutoff is not None and captured_at is not None and captured_at > cutoff:
            continue
        if cutoff is not None and event_time is not None and event_time > cutoff:
            continue
        edge = _flow_config_edge(fact, resolver, as_of=cutoff)
        if edge.activity_state == "ACTIVE" and edge.resource_id:
            conflicting_disable = any(
                str(activity.get("event_type") or "").strip().upper()
                == "DISABLE_DATA_FLOW"
                and str(activity.get("resource_id") or "").strip()
                == edge.resource_id
                and str(activity.get("activity_id") or "")
                in timeline_by_activity
                and (
                    _utc(activity.get("event_time")) is None
                    or edge.observed_at is None
                    or _utc(activity.get("event_time")) >= edge.observed_at
                )
                and (
                    cutoff is None
                    or _utc(activity.get("event_time")) is None
                    or _utc(activity.get("event_time")) <= cutoff
                )
                for activity in activity_rows
            )
            if conflicting_disable:
                edge = replace(
                    edge,
                    confidence="ambiguous",
                    ambiguity_reason=(
                        "a matching flow-disable activity is reported, but the "
                        "activity result does not verify the flow's final state"
                    ),
                )
        edges.append(edge)

    return LineageGraph(
        cutoff,
        tuple(sorted(edges, key=_edge_sort_key)),
        activity_observations,
    )


def resource_evidence_from_facts(
    evidence_facts: Iterable[EvidenceFact],
    resolver: IdentityResolver,
    user_id: str,
    *,
    as_of: Any = None,
    prohibited_by_resource: Mapping[str, bool] | None = None,
) -> tuple[ResourceEvidence, ...]:
    """Create identity-linked resources without making policy decisions.

    ``contains_prohibited_data`` is ``None`` unless the caller supplies a
    policy-stage judgment keyed by resource ID.
    """
    cutoff = _utc(as_of)
    prohibited = prohibited_by_resource or {}
    observations: list[ResourceEvidence] = []
    for fact in evidence_facts:
        captured_at = _utc(fact.captured_at)
        observed_at = _utc(fact.event_timestamp)
        if cutoff is not None and captured_at is not None and captured_at > cutoff:
            continue
        if cutoff is not None and observed_at is not None and observed_at > cutoff:
            continue
        resolution = resolver.resolve_fact(fact, as_of=cutoff)
        if (
            user_id not in resolution.candidate_user_ids
            or not fact.system_id
            or not fact.resource_id
        ):
            continue
        contains_personal_data = bool(fact.personal_fields)
        if not contains_personal_data:
            contains_personal_data = any(
                candidate.field_name.casefold()
                in {"email", "email_hash", "phone", "name", "owner_email"}
                for candidate in fact.candidate_identifiers
            )
        observations.append(
            ResourceEvidence(
                fact.resource_id,
                fact.system_id,
                user_id,
                contains_personal_data,
                prohibited.get(fact.resource_id),
                fact.file_id,
                fact.source_path,
                fact.source_location,
                observed_at,
                captured_at,
                resolution.status,
                (
                    "unknown_time"
                    if cutoff is not None
                    and captured_at is None
                    and observed_at is None
                    else "in_scope"
                ),
                resolution.matched_links,
                fact.record_state,
                fact.data_categories,
                resolution.candidate_user_ids,
            )
        )
    return tuple(
        sorted(
            observations,
            key=lambda item: (
                item.system_id,
                item.resource_id,
                item.evidence_id,
                item.source_location,
            ),
        )
    )


def _path_key(path: ResurrectionPath) -> tuple[Any, ...]:
    return (
        path.nodes,
        tuple(edge.edge_id for edge in path.edges),
        tuple(resource.resource_id for resource in path.source_resources),
        tuple(resource.resource_id for resource in path.destination_resources),
    )


def analyze_resurrection_paths(
    graph: LineageGraph,
    user_id: str,
    resources: Iterable[ResourceEvidence],
) -> ResurrectionAnalysis:
    """Find confirmed/possible paths from proven prohibited-data sources.

    System connectivity alone is insufficient: every traversed edge must be
    active, propagate to this user, and be explicitly supported. Every source
    system in a multi-hop path also needs evidence of prohibited data for that
    user. This function does not decide policy or deletion status.
    """
    resource_rows = tuple(
        sorted(
            (
                item
                for item in resources
                if item.user_id == user_id
                and item.identity_status in {"confirmed", "ambiguous"}
                and (
                    not item.candidate_user_ids
                    or user_id in item.candidate_user_ids
                )
                and item.temporal_status == "in_scope"
            ),
            key=lambda item: (
                item.system_id,
                item.resource_id,
                item.evidence_id,
                item.source_location,
            ),
        )
    )
    resources_by_system: dict[str, tuple[ResourceEvidence, ...]] = {}
    for system in sorted({item.system_id for item in resource_rows}):
        resources_by_system[system] = tuple(
            item for item in resource_rows if item.system_id == system
        )
    source_resources_by_system: dict[str, tuple[ResourceEvidence, ...]] = {}
    for system in sorted(
        {
            item.system_id
            for item in resource_rows
            if item.contains_personal_data and item.contains_prohibited_data is True
        }
    ):
        source_resources_by_system[system] = tuple(
            item
            for item in resource_rows
            if item.system_id == system
            and item.contains_personal_data
            and item.contains_prohibited_data is True
        )
    source_resource_groups = tuple(
        (
            system,
            identity_status,
            tuple(
                item
                for item in source_resources_by_system[system]
                if item.identity_status == identity_status
            ),
        )
        for system in sorted(source_resources_by_system)
        for identity_status in ("confirmed", "ambiguous")
        if any(
            item.identity_status == identity_status
            for item in source_resources_by_system[system]
        )
    )

    active_edges = tuple(
        edge
        for edge in graph.edges
        if user_id in edge.applicable_user_ids
        and edge.activity_state == "ACTIVE"
    )
    adjacency: dict[str, tuple[LineageEdge, ...]] = {}
    for source in sorted(
        {
            edge.source_node
            for edge in active_edges
            if edge.source_node is not None
        }
    ):
        adjacency[source] = tuple(
            sorted(
                (
                    edge
                    for edge in active_edges
                    if edge.source_node == source
                ),
                key=_edge_sort_key,
            )
        )

    confirmed: list[ResurrectionPath] = []
    possible: list[ResurrectionPath] = []

    def visit(
        nodes: tuple[str, ...],
        path_edges: tuple[LineageEdge, ...],
        source_resources: tuple[ResourceEvidence, ...],
        confidence: str,
    ) -> None:
        current = nodes[-1]
        for edge in adjacency.get(current, ()):
            if edge.destination_node is None:
                continue
            if (
                not edge.propagation_supported
                or edge.confidence not in {"confirmed", "ambiguous"}
            ):
                continue
            destination = edge.destination_node
            if destination in nodes:
                continue
            next_edges = path_edges + (edge,)
            next_nodes = nodes + (destination,)
            next_confidence = (
                "confirmed"
                if confidence == "confirmed" and edge.confidence == "confirmed"
                else "ambiguous"
            )
            destination_resources = resources_by_system.get(destination, ())
            evidence_ids = {
                item.evidence_id for item in source_resources
            } | {item.evidence_id for item in destination_resources}
            evidence_ids.update(item.source_evidence_id for item in next_edges)
            finding = (
                "confirmed active process can repopulate a downstream system"
                if next_confidence == "confirmed"
                else "ambiguous active-process candidate could repopulate a downstream system"
            )
            path = ResurrectionPath(
                user_id,
                next_confidence,
                next_nodes,
                next_edges,
                source_resources,
                destination_resources,
                tuple(sorted(evidence_ids)),
                finding,
            )
            (confirmed if next_confidence == "confirmed" else possible).append(path)

            # A further hop needs separate evidence that this user's prohibited
            # data is already present at the intermediate system.
            intermediate_sources = source_resources_by_system.get(destination, ())
            for identity_status in ("confirmed", "ambiguous"):
                identity_group = tuple(
                    item
                    for item in intermediate_sources
                    if item.identity_status == identity_status
                )
                if identity_group:
                    source_confidence = (
                        "confirmed"
                        if next_confidence == "confirmed"
                        and identity_status == "confirmed"
                        else "ambiguous"
                    )
                    visit(
                        next_nodes,
                        next_edges,
                        source_resources + identity_group,
                        source_confidence,
                    )

    for source_system, identity_status, source_resources in source_resource_groups:
        visit(
            (source_system,),
            (),
            source_resources,
            "confirmed" if identity_status == "confirmed" else "ambiguous",
        )

    unresolved: list[UnresolvedLineage] = []
    for edge in graph.edges:
        if user_id not in edge.applicable_user_ids:
            continue
        if (
            edge.activity_state in {"ACTIVE", "UNKNOWN"}
            and (
                not edge.source_node
                or not edge.destination_node
                or not edge.propagation_supported
                or edge.confidence != "confirmed"
            )
        ):
            unresolved.append(
                UnresolvedLineage(
                    user_id,
                    edge,
                    edge.ambiguity_reason
                    or "edge does not establish a confirmed active user-specific flow",
                )
            )

    return ResurrectionAnalysis(
        user_id,
        tuple(sorted(confirmed, key=_path_key)),
        tuple(sorted(possible, key=_path_key)),
        tuple(
            sorted(
                unresolved,
                key=lambda item: (
                    item.edge.source_node or "",
                    item.edge.destination_node or "",
                    item.edge.edge_id,
                ),
            )
        ),
    )


def simulate_edge_removals(
    graph: LineageGraph,
    user_id: str,
    resources: Iterable[ResourceEvidence],
    *,
    edge_ids: Iterable[str] = (),
    activity_ids: Iterable[str] = (),
) -> RemediationSimulation:
    """Analyze hypothetical flow removal without mutating the supplied graph."""
    removed = set(edge_ids)
    removed_activities = set(activity_ids)
    removed_edges = tuple(
        sorted(
            {
                edge.edge_id
                for edge in graph.edges
                if edge.edge_id in removed or edge.activity_id in removed_activities
            }
        )
    )
    simulated_graph = replace(
        graph,
        edges=tuple(edge for edge in graph.edges if edge.edge_id not in removed_edges),
    )
    resource_rows = tuple(resources)
    before = analyze_resurrection_paths(graph, user_id, resource_rows)
    after = analyze_resurrection_paths(simulated_graph, user_id, resource_rows)
    after_signatures = {
        tuple(edge.edge_id for edge in path.edges)
        for path in after.confirmed_paths
    }
    broken = tuple(
        path
        for path in before.confirmed_paths
        if tuple(edge.edge_id for edge in path.edges) not in after_signatures
    )
    return RemediationSimulation(
        True,
        removed_edges,
        before,
        after,
        tuple(sorted(broken, key=_path_key)),
        after.confirmed_paths,
    )


__all__ = [
    "LineageEdge",
    "LineageGraph",
    "RemediationSimulation",
    "ResurrectionAnalysis",
    "ResurrectionPath",
    "ResourceEvidence",
    "UnresolvedLineage",
    "analyze_resurrection_paths",
    "build_lineage_graph",
    "load_activity_events",
    "resource_evidence_from_facts",
    "simulate_edge_removals",
]
