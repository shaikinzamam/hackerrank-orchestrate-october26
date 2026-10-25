import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

from evidence_model import EvidenceFact, IdentifierCandidate, ObservedField, parse_timestamp
from identity_timeline import IdentityResolver, TimelineEvent
from lineage_graph import (
    LineageEdge,
    LineageGraph,
    ResourceEvidence,
    analyze_resurrection_paths,
    build_lineage_graph,
    resource_evidence_from_facts,
    simulate_edge_removals,
)


USER = "subject_alpha"
EMAIL = "alpha@example.test"
CUTOFF = "2026-01-02T00:00:00Z"


def resolver(*identities: dict[str, str]) -> IdentityResolver:
    return IdentityResolver(list(identities), [])


def identity(email: str = EMAIL, user_id: str = USER) -> dict[str, str]:
    return {
        "user_id": user_id,
        "email": email,
        "updated_at": "2026-01-01T00:00:00Z",
    }


def flow_fact(
    file_id: str,
    *,
    source: str | None = "source_service",
    destination: str | None = "target_service",
    enabled: str = "true",
    selector: str = EMAIL,
    captured_at: str | None = "2026-01-01T00:00:00Z",
    mode: str = "continuous_sync",
) -> EvidenceFact:
    values = {
        "record_type": "DATA_FLOW",
        "subject_selector": selector,
        "enabled": enabled,
        "mode": mode,
    }
    if source is not None:
        values["source_system"] = source
    if destination is not None:
        values["destination"] = destination
    return EvidenceFact(
        file_id=file_id,
        source_path="evidence/connector_config.json",
        system_id="integration_service",
        resource_id=f"flow-{file_id}",
        candidate_identifiers=(IdentifierCandidate("email", selector),),
        data_categories=("DATA_FLOW",),
        personal_fields=(),
        record_state=enabled,
        event_timestamp=None,
        captured_at=parse_timestamp(captured_at),
        source_location="/records/0",
        extraction_method="synthetic",
        confidence=1.0,
        observed_fields=tuple(
            ObservedField(f"/records/0/{name}", name, value)
            for name, value in sorted(values.items())
        ),
    )


def resource(
    resource_id: str,
    system_id: str,
    *,
    user_id: str = USER,
    prohibited: bool | None = True,
    personal: bool = True,
    evidence_id: str | None = None,
    identity_status: str = "confirmed",
    temporal_status: str = "in_scope",
) -> ResourceEvidence:
    return ResourceEvidence(
        resource_id=resource_id,
        system_id=system_id,
        user_id=user_id,
        contains_personal_data=personal,
        contains_prohibited_data=prohibited,
        evidence_id=evidence_id or f"evidence-{resource_id}",
        source_file="synthetic_records.json",
        source_location=f"/records/{resource_id}",
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        captured_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        identity_status=identity_status,
        temporal_status=temporal_status,
    )


def active_edge(
    edge_id: str,
    source: str,
    destination: str,
    *,
    user_id: str = USER,
    confidence: str = "confirmed",
    propagation_supported: bool = True,
) -> LineageEdge:
    observed_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return LineageEdge(
        edge_id=edge_id,
        source_node=source,
        destination_node=destination,
        activity_id=edge_id,
        resource_id=f"resource-{edge_id}",
        process_type="DATA_FLOW_CONFIG",
        activity_state="ACTIVE",
        reported_result="enabled",
        valid_from=observed_at,
        valid_to=None,
        observed_at=observed_at,
        captured_at=None,
        source_evidence_id=f"evidence-{edge_id}",
        source_file="synthetic_flow.json",
        source_location=f"/flows/{edge_id}",
        confidence=confidence,
        identity_status="confirmed" if confidence == "confirmed" else "ambiguous",
        applicable_user_ids=(user_id,),
        propagation_supported=propagation_supported,
        ambiguity_reason="identity candidate is ambiguous" if confidence != "confirmed" else "",
    )


def process_event(
    activity_id: str,
    event_time: str | None,
    *,
    result: str = "SUCCESS",
    source: str = "source_service",
    destination: str = "target_service",
) -> dict[str, str]:
    return {
        "activity_id": activity_id,
        "event_time": event_time or "",
        "event_type": "SYNC_RECORD",
        "source_system": source,
        "target_system": destination,
        "resource_id": "resource-alpha",
        "reported_result": result,
        "_source_file": "system_activity.csv",
        "_source_location": "row:7",
    }


def process_timeline_event(
    activity_id: str,
    event_time: str | None,
    *,
    identity_status: str = "confirmed",
    user_ids: tuple[str, ...] = (USER,),
) -> TimelineEvent:
    return TimelineEvent(
        case_id="synthetic_case",
        event_type="process_activity",
        source_id=activity_id,
        event_time=parse_timestamp(event_time),
        captured_at=None,
        ingestion_time=None,
        source_file="system_activity.csv",
        source_location="row:7",
        user_ids=user_ids,
        identity_status=identity_status,
        cutoff_status="unknown_time" if event_time is None else "in_scope",
        details=(),
    )


class LineageGraphTests(unittest.TestCase):
    def test_explicit_current_configuration_supports_a_confirmed_flow(self) -> None:
        flow = flow_fact("current", captured_at=CUTOFF)
        graph = build_lineage_graph(
            (), (flow,), (), resolver(identity()), as_of=CUTOFF
        )
        analysis = analyze_resurrection_paths(
            graph, USER, (resource("source-record", "source_service"),)
        )

        self.assertEqual(graph.edges[0].activity_state, "ACTIVE")
        self.assertEqual(graph.edges[0].confidence, "confirmed")
        self.assertEqual(graph.edges[0].captured_at, parse_timestamp(CUTOFF))
        self.assertEqual(
            graph.edges[0].identity_links[0].source_file,
            "user_identities.csv",
        )
        self.assertEqual(len(analysis.confirmed_paths), 1)

    def test_flow_identity_link_keeps_audit_provenance(self) -> None:
        historical_resolver = IdentityResolver(
            [
                {
                    "user_id": USER,
                    "email": "new@example.test",
                    "updated_at": "2026-02-01T00:00:00Z",
                }
            ],
            [
                {
                    "audit_id": "audit-email",
                    "user_id": USER,
                    "event_time": "2026-01-01T00:00:00Z",
                    "field_name": "email",
                    "old_value": EMAIL,
                    "new_value": "new@example.test",
                    "_source_file": "synthetic_audit.csv",
                    "_source_location": "row:4",
                }
            ],
        )
        flow = flow_fact(
            "historical",
            selector=EMAIL,
            captured_at="2025-12-31T12:00:00Z",
        )
        graph = build_lineage_graph(
            (), (flow,), (), historical_resolver, as_of="2026-01-03T00:00:00Z"
        )

        old_email_links = [
            link for link in graph.edges[0].identity_links
            if link.audit_id == "audit-email"
        ]
        self.assertEqual(len(old_email_links), 1)
        self.assertEqual(old_email_links[0].source_file, "synthetic_audit.csv")
        self.assertEqual(old_email_links[0].source_location, "row:4")

    def test_stale_active_snapshot_is_only_a_possible_path(self) -> None:
        flow = flow_fact("older", captured_at="2026-01-01T00:00:00Z")
        graph = build_lineage_graph(
            (), (flow,), (), resolver(identity()), as_of=CUTOFF
        )
        analysis = analyze_resurrection_paths(
            graph, USER, (resource("source-record", "source_service"),)
        )

        self.assertEqual(graph.edges[0].activity_state, "ACTIVE")
        self.assertEqual(graph.edges[0].confidence, "ambiguous")
        self.assertFalse(analysis.confirmed_paths)
        self.assertEqual(len(analysis.possible_paths), 1)

    def test_active_flow_from_surviving_source_to_clean_destination(self) -> None:
        graph = LineageGraph(
            parse_timestamp(CUTOFF),
            (active_edge("flow-1", "primary", "warehouse"),),
        )
        analysis = analyze_resurrection_paths(
            graph,
            USER,
            (
                resource("record-1", "primary"),
                resource("clean-target-record", "warehouse", prohibited=False),
            ),
        )

        self.assertEqual(len(analysis.confirmed_paths), 1)
        path = analysis.confirmed_paths[0]
        self.assertEqual(path.nodes, ("primary", "warehouse"))
        self.assertEqual(
            tuple(item.resource_id for item in path.destination_resources),
            ("clean-target-record",),
        )
        self.assertEqual(
            path.supporting_evidence_ids,
            (
                "evidence-clean-target-record",
                "evidence-flow-1",
                "evidence-record-1",
            ),
        )

    def test_multi_hop_path_requires_evidence_at_intermediate_source(self) -> None:
        graph = LineageGraph(
            parse_timestamp(CUTOFF),
            (
                active_edge("flow-a", "primary", "replica"),
                active_edge("flow-b", "replica", "warehouse"),
            ),
        )
        resources = (
            resource("record-a", "primary"),
            resource("record-b", "replica"),
        )

        analysis = analyze_resurrection_paths(graph, USER, resources)
        paths = [path.nodes for path in analysis.confirmed_paths]

        self.assertIn(("primary", "replica"), paths)
        self.assertIn(("primary", "replica", "warehouse"), paths)

        without_intermediate_evidence = analyze_resurrection_paths(
            graph, USER, (resource("record-a", "primary"),)
        )
        self.assertNotIn(
            ("primary", "replica", "warehouse"),
            [path.nodes for path in without_intermediate_evidence.confirmed_paths],
        )

    def test_inactive_flow_is_not_traversed(self) -> None:
        flow = flow_fact(
            "inactive", enabled="false", captured_at=CUTOFF
        )
        graph = build_lineage_graph((), (flow,), (), resolver(identity()), as_of=CUTOFF)

        self.assertEqual(len(graph.edges), 1)
        self.assertEqual(graph.edges[0].activity_state, "INACTIVE")
        self.assertFalse(
            analyze_resurrection_paths(
                graph, USER, (resource("source-record", "source_service"),)
            ).confirmed_paths
        )

    def test_stale_inactive_configuration_is_unresolved_not_current_state(self) -> None:
        flow = flow_fact("stale-inactive", enabled="false")
        graph = build_lineage_graph((), (flow,), (), resolver(identity()), as_of=CUTOFF)
        analysis = analyze_resurrection_paths(
            graph, USER, (resource("source-record", "source_service"),)
        )

        self.assertEqual(graph.edges[0].activity_state, "UNKNOWN")
        self.assertFalse(analysis.confirmed_paths)
        self.assertEqual(len(analysis.unresolved_lineage), 1)

    def test_flow_without_timestamp_is_unresolved(self) -> None:
        flow = flow_fact("undated", captured_at=None)
        graph = build_lineage_graph((), (flow,), (), resolver(identity()), as_of=CUTOFF)
        analysis = analyze_resurrection_paths(
            graph, USER, (resource("source-record", "source_service"),)
        )

        self.assertEqual(graph.edges[0].activity_state, "UNKNOWN")
        self.assertFalse(analysis.confirmed_paths)
        self.assertEqual(len(analysis.unresolved_lineage), 1)

    def test_evidence_captured_after_cutoff_is_excluded(self) -> None:
        flow = flow_fact("future", captured_at="2026-01-03T00:00:00Z")
        graph = build_lineage_graph((), (flow,), (), resolver(identity()), as_of=CUTOFF)

        self.assertEqual(graph.edges, ())

    def test_cycle_terminates_without_repeating_nodes(self) -> None:
        graph = LineageGraph(
            parse_timestamp(CUTOFF),
            (
                active_edge("a-b", "system-a", "system-b"),
                active_edge("b-a", "system-b", "system-a"),
            ),
        )
        analysis = analyze_resurrection_paths(
            graph,
            USER,
            (resource("record-a", "system-a"), resource("record-b", "system-b")),
        )

        self.assertEqual(
            [path.nodes for path in analysis.confirmed_paths],
            [("system-a", "system-b"), ("system-b", "system-a")],
        )

    def test_missing_source_or_destination_is_unresolved(self) -> None:
        for missing_endpoint, source, destination in (
            ("source", None, "target_service"),
            ("destination", "source_service", None),
        ):
            with self.subTest(missing_endpoint=missing_endpoint):
                graph = build_lineage_graph(
                    (),
                    (
                        flow_fact(
                            f"partial-{missing_endpoint}",
                            source=source,
                            destination=destination,
                        ),
                    ),
                    (),
                    resolver(identity()),
                    as_of=CUTOFF,
                )
                analysis = analyze_resurrection_paths(
                    graph, USER, (resource("record-a", "source_service"),)
                )

                self.assertFalse(analysis.confirmed_paths)
                self.assertEqual(len(analysis.unresolved_lineage), 1)
                self.assertIsNone(
                    getattr(analysis.unresolved_lineage[0].edge, f"{missing_endpoint}_node")
                )
                self.assertIn(
                    f"{missing_endpoint} system",
                    analysis.unresolved_lineage[0].reason,
                )

    def test_ambiguous_flow_is_possible_not_confirmed(self) -> None:
        conflicted_resolver = resolver(
            identity(),
            identity(email="alpha@example.test", user_id="subject_beta"),
        )
        graph = build_lineage_graph(
            (), (flow_fact("ambiguous"),), (), conflicted_resolver, as_of=CUTOFF
        )
        analysis = analyze_resurrection_paths(
            graph, USER, (resource("record-a", "source_service"),)
        )

        self.assertFalse(analysis.confirmed_paths)
        self.assertEqual(len(analysis.possible_paths), 1)
        self.assertEqual(analysis.possible_paths[0].confidence, "ambiguous")

    def test_ambiguous_source_identity_yields_only_a_possible_path(self) -> None:
        conflicted_resolver = resolver(
            identity(),
            identity(email=EMAIL, user_id="subject_beta"),
        )
        source_fact = EvidenceFact(
            file_id="ambiguous-source",
            source_path="evidence/shared_identifier.json",
            system_id="source_service",
            resource_id="shared-record",
            candidate_identifiers=(IdentifierCandidate("email", EMAIL),),
            data_categories=("CUSTOMER_PROFILE",),
            personal_fields=("email",),
            record_state="ACTIVE",
            event_timestamp=parse_timestamp("2026-01-01T00:00:00Z"),
            captured_at=parse_timestamp("2026-01-01T00:00:00Z"),
            source_location="/records/0",
            extraction_method="synthetic",
            confidence=1.0,
            observed_fields=(
                ObservedField("/records/0/email", "email", EMAIL),
            ),
        )
        resources = resource_evidence_from_facts(
            (source_fact,),
            conflicted_resolver,
            USER,
            as_of=CUTOFF,
            prohibited_by_resource={"shared-record": True},
        )
        graph = build_lineage_graph(
            (),
            (flow_fact("stable-subject", selector=USER, captured_at=CUTOFF),),
            (),
            conflicted_resolver,
            as_of=CUTOFF,
        )
        analysis = analyze_resurrection_paths(graph, USER, resources)

        self.assertEqual(resources[0].identity_status, "ambiguous")
        self.assertEqual(resources[0].candidate_user_ids, (USER, "subject_beta"))
        self.assertFalse(analysis.confirmed_paths)
        self.assertEqual(len(analysis.possible_paths), 1)

    def test_system_edge_without_user_specific_propagation_is_not_a_finding(self) -> None:
        graph = LineageGraph(
            parse_timestamp(CUTOFF),
            (
                replace_edge(
                    active_edge("unlinked", "primary", "warehouse"),
                    applicable_user_ids=(),
                ),
            ),
        )
        analysis = analyze_resurrection_paths(
            graph, USER, (resource("record-a", "primary"),)
        )

        self.assertFalse(analysis.confirmed_paths)
        self.assertFalse(analysis.possible_paths)

    def test_hypothetical_edge_removal_breaks_path_without_mutating_graph(self) -> None:
        edge = active_edge("flow-remove", "primary", "warehouse")
        graph = LineageGraph(parse_timestamp(CUTOFF), (edge,))
        resources = (resource("record-a", "primary"),)
        simulation = simulate_edge_removals(
            graph, USER, resources, edge_ids=(edge.edge_id,)
        )

        self.assertTrue(simulation.hypothetical)
        self.assertEqual(len(simulation.broken_confirmed_paths), 1)
        self.assertFalse(simulation.remaining_confirmed_paths)
        self.assertEqual(graph.edges, (edge,))

    def test_activity_edges_are_observations_and_obey_timezone_cutoff(self) -> None:
        activities = (
            process_event("before", "2026-01-02T00:00:00Z"),
            process_event("after", "2026-01-02T00:00:01Z"),
        )
        timelines = (
            process_timeline_event("before", "2026-01-02T00:00:00Z"),
            process_timeline_event("after", "2026-01-02T00:00:01Z"),
        )
        graph = build_lineage_graph(
            activities,
            (),
            timelines,
            resolver(identity()),
            as_of="2026-01-02T02:00:00+02:00",
        )

        self.assertEqual(tuple(edge.activity_id for edge in graph.edges), ("before",))
        self.assertEqual(graph.edges[0].activity_state, "OBSERVED")
        self.assertFalse(graph.edges[0].propagation_supported)
        self.assertEqual(graph.edges[0].source_file, "system_activity.csv")
        self.assertEqual(graph.edges[0].source_location, "row:7")
        self.assertEqual(graph.edges[0].resource_id, "resource-alpha")

    def test_matching_disable_activity_makes_active_state_ambiguous(self) -> None:
        flow = flow_fact("disable-candidate", captured_at=CUTOFF)
        disable = process_event("disable-1", CUTOFF)
        disable["event_type"] = "DISABLE_DATA_FLOW"
        disable["resource_id"] = flow.resource_id
        graph = build_lineage_graph(
            (disable,),
            (flow,),
            (process_timeline_event("disable-1", CUTOFF),),
            resolver(identity()),
            as_of=CUTOFF,
        )

        self.assertEqual(graph.edges[0].activity_state, "ACTIVE")
        self.assertEqual(graph.edges[0].confidence, "ambiguous")
        self.assertEqual(
            graph.activity_observations[0].source_id,
            "disable-1",
        )
        self.assertIn("final state", graph.edges[0].ambiguity_reason)

    def test_post_cutoff_disable_does_not_change_historical_flow_state(self) -> None:
        flow = flow_fact("future-disable", captured_at=CUTOFF)
        disable = process_event("disable-after-cutoff", "2026-01-03T00:00:00Z")
        disable["event_type"] = "DISABLE_DATA_FLOW"
        disable["resource_id"] = flow.resource_id
        graph = build_lineage_graph(
            (disable,),
            (flow,),
            (
                process_timeline_event(
                    "disable-after-cutoff", "2026-01-03T00:00:00Z"
                ),
            ),
            resolver(identity()),
            as_of=CUTOFF,
        )

        self.assertEqual(graph.edges[0].confidence, "confirmed")
        self.assertEqual(graph.activity_observations, ())

    def test_missing_activity_timestamp_is_retained_as_unconfirmed(self) -> None:
        activity = process_event("no-time", None)
        timeline = process_timeline_event("no-time", None)
        graph = build_lineage_graph(
            (activity,), (), (timeline,), resolver(identity()), as_of=CUTOFF
        )

        self.assertEqual(len(graph.edges), 1)
        self.assertEqual(graph.edges[0].confidence, "unsupported")
        self.assertIn("timestamp", graph.edges[0].ambiguity_reason)

    def test_flow_provenance_and_path_order_are_deterministic(self) -> None:
        first = flow_fact(
            "flow-z", source="source", destination="target", captured_at=CUTOFF
        )
        second = flow_fact(
            "flow-a", source="source", destination="target", captured_at=CUTOFF
        )
        graph_one = build_lineage_graph(
            (), (first, second), (), resolver(identity()), as_of=CUTOFF
        )
        graph_two = build_lineage_graph(
            (), (second, first), (), resolver(identity()), as_of=CUTOFF
        )
        analysis_one = analyze_resurrection_paths(
            graph_one, USER, (resource("record", "source"),)
        )
        analysis_two = analyze_resurrection_paths(
            graph_two, USER, (resource("record", "source"),)
        )

        self.assertEqual(graph_one, graph_two)
        self.assertEqual(analysis_one.confirmed_paths, analysis_two.confirmed_paths)
        self.assertEqual(
            [path.edges[0].source_evidence_id for path in analysis_one.confirmed_paths],
            ["flow-a", "flow-z"],
        )
        self.assertEqual(
            analysis_one.confirmed_paths[0].edges[0].source_location, "/records/0"
        )

    def test_resources_missing_historical_time_are_not_confirmed_sources(self) -> None:
        unknown_time = resource("undated-record", "source")
        unknown_time = ResourceEvidence(
            **{
                **unknown_time.__dict__,
                "observed_at": None,
                "captured_at": None,
                "temporal_status": "unknown_time",
            }
        )
        graph = LineageGraph(
            parse_timestamp(CUTOFF),
            (active_edge("flow", "source", "target"),),
        )

        analysis = analyze_resurrection_paths(graph, USER, (unknown_time,))

        self.assertFalse(analysis.confirmed_paths)

    def test_resource_facts_preserve_provenance_and_policy_separation(self) -> None:
        fact = EvidenceFact(
            file_id="resource-fact",
            source_path="evidence/customer_records.json",
            system_id="source_service",
            resource_id="record-a",
            candidate_identifiers=(IdentifierCandidate("email", EMAIL),),
            data_categories=("CUSTOMER_PROFILE",),
            personal_fields=("email",),
            record_state="ACTIVE",
            event_timestamp=parse_timestamp("2026-01-01T00:00:00Z"),
            captured_at=parse_timestamp("2026-01-01T00:00:00Z"),
            source_location="/records/0",
            extraction_method="synthetic",
            confidence=1.0,
            observed_fields=(
                ObservedField("/records/0/email", "email", EMAIL),
            ),
        )
        rows = resource_evidence_from_facts(
            (fact,), resolver(identity()), USER, as_of=CUTOFF
        )
        labeled_rows = resource_evidence_from_facts(
            (fact,),
            resolver(identity()),
            USER,
            as_of=CUTOFF,
            prohibited_by_resource={"record-a": True},
        )

        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].contains_personal_data)
        self.assertIsNone(rows[0].contains_prohibited_data)
        self.assertEqual(rows[0].evidence_id, "resource-fact")
        self.assertEqual(rows[0].source_location, "/records/0")
        self.assertEqual(rows[0].record_state, "ACTIVE")
        self.assertEqual(rows[0].data_categories, ("CUSTOMER_PROFILE",))
        self.assertIs(labeled_rows[0].contains_prohibited_data, True)


def replace_edge(edge: LineageEdge, **changes: object) -> LineageEdge:
    values = {**edge.__dict__, **changes}
    return LineageEdge(**values)


if __name__ == "__main__":
    unittest.main()
