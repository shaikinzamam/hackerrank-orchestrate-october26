import sys
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

from contract_validator import OPERATION_STATES, _step_sort_key
from evidence_model import EvidenceFact, IdentifierCandidate, ObservedField
from lineage_graph import (
    LineageEdge,
    ResurrectionAnalysis,
    ResurrectionPath,
    UnresolvedLineage,
)
from identity_timeline import IdentityResolver, TimelineEvent
from main import (
    _activity_resource_targets,
    _activity_resource_links,
    _policy_records,
    _has_confirmed_stable_user_reference,
    _is_non_resource_read_attempt,
    _normalize_evidence_fact,
)
from policy_engine import (
    DeletionStatus,
    EvidenceDisposition,
    PolicyAction,
    PolicyRecord,
    evaluate_policy_record,
    evaluate_request,
    is_deletion_request,
    load_policy_rules,
)
from remediation_planner import PlanningError, plan_remediation


EMPTY_LINEAGE = ResurrectionAnalysis("user_1", (), (), ())
REQUEST = {
    "case_id": "synthetic_case",
    "request_text": "Please delete my account and personal data.",
}


def make_fact(
    category,
    fields=(),
    *,
    state="present",
    system_id="test_service",
    resource_id="resource_1",
    file_id="evidence_1",
):
    observed = tuple(
        ObservedField(f"/records/0/{name}", name, str(value))
        for name, value in fields
    )
    identifiers = tuple(
        IdentifierCandidate(name, str(value))
        for name, value in fields
        if name.casefold()
        in {
            "email", "email_hash", "phone", "user_id", "customer_id",
            "customer_reference", "owner_email", "requester_email",
        "subject_reference",
        }
    )
    personal_names = {
        "address", "display_name", "email", "email_hash", "full_name",
        "given_name", "name", "owner_email", "owner_phone", "phone",
        "requester_email", "requester_name", "requester_phone", "surname",
    }
    personal_fields = tuple(
        sorted({name for name, _ in fields if name.casefold() in personal_names})
    )
    return EvidenceFact(
        file_id=file_id,
        source_path="evidence/synthetic.json",
        system_id=system_id,
        resource_id=resource_id,
        candidate_identifiers=identifiers,
        data_categories=(category,),
        personal_fields=personal_fields,
        record_state=state,
        event_timestamp=datetime(2026, 10, 1, tzinfo=timezone.utc),
        captured_at=datetime(2026, 10, 2, tzinfo=timezone.utc),
        source_location="/records/0",
        extraction_method="synthetic_json",
        confidence=1.0,
        observed_fields=observed,
    )


class PolicyEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_policy_rules()
        cls.by_category = {rule.data_category: rule for rule in cls.rules}

    def assess(self, category, fields=(), *, state="present", overrides=None):
        fact = make_fact(category, fields, state=state)
        return evaluate_policy_record(
            PolicyRecord(fact, condition_values=overrides or {}),
            self.by_category[category],
            as_of="2026-10-10T00:00:00Z",
        )

    def test_policy_is_loaded_from_dataset_and_covers_all_fifteen_rules(self):
        self.assertEqual(len(self.rules), 15)
        self.assertEqual(
            {rule.required_action for rule in self.rules},
            {
                PolicyAction.DELETE,
                PolicyAction.REDACT,
                PolicyAction.ANONYMIZE,
                PolicyAction.RETAIN,
            },
        )

    def test_connector_configuration_alias_accepts_supported_subject_fields(self):
        fact = make_fact(
            "connector_configurations",
            [
                ("subject_reference", "user_1"),
                ("destination", "analytics_platform"),
                ("is_active", "true"),
                ("mode", "continuous_sync"),
            ],
        )

        normalized = _normalize_evidence_fact(fact)

        self.assertEqual(normalized.data_categories, ("DATA_FLOW",))

    def test_missing_system_target_uses_confirmed_direct_activity_provenance(self):
        fact = make_fact(
            "USER_PROFILE",
            [("user_id", "user_1"), ("email", "person@example.test")],
            system_id=None,
            resource_id="account_1",
            file_id="evidence_profile",
        )
        resolver = IdentityResolver(
            [
                {
                    "user_id": "user_1",
                    "email": "person@example.test",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ]
        )
        timeline = (
            TimelineEvent(
                "synthetic_case",
                "evidence_observation",
                fact.file_id,
                fact.event_timestamp,
                fact.captured_at,
                None,
                fact.source_path,
                fact.source_location,
                ("user_1",),
                "confirmed",
                "in_scope",
                (),
            ),
            TimelineEvent(
                "synthetic_case",
                "process_activity",
                "activity_profile",
                datetime(2026, 10, 3, tzinfo=timezone.utc),
                None,
                None,
                "system_activity.csv",
                "row:2",
                ("user_1",),
                "confirmed",
                "in_scope",
                (
                    ("event_type", "DELETE_RECORD"),
                    ("resource_id", "account_1"),
                    ("source_system", "deletion_worker"),
                    ("target_system", "account_service"),
                ),
            ),
            TimelineEvent(
                "synthetic_case",
                "process_activity",
                "activity_sync",
                datetime(2026, 10, 4, tzinfo=timezone.utc),
                None,
                None,
                "system_activity.csv",
                "row:3",
                ("user_1",),
                "confirmed",
                "in_scope",
                (
                    ("event_type", "SYNC_RECORD"),
                    ("resource_id", "account_1"),
                    ("source_system", "account_service"),
                    ("target_system", "account_replication_cluster"),
                ),
            ),
        )

        records = _policy_records(
            (fact,),
            timeline,
            "user_1",
            self.rules,
            _activity_resource_links(timeline, "user_1"),
            resolver,
            datetime(2026, 10, 10, tzinfo=timezone.utc),
        )
        evaluation = evaluate_request(
            REQUEST,
            records,
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            as_of="2026-10-10T00:00:00Z",
            evidence_complete=True,
        )
        plan = plan_remediation(evaluation)

        self.assertEqual(len(records), 1)
        self.assertIsNone(records[0].fact.system_id)
        self.assertEqual(records[0].target_system_id, "account_service")
        self.assertEqual(records[0].target_system_source_id, "activity_profile")
        self.assertEqual(
            records[0].target_system_source_file,
            "system_activity.csv",
        )
        self.assertTrue(
            all(step["system_id"] == "account_service" for step in plan.steps)
        )
        self.assertEqual(
            next(step for step in plan.steps if step["phase"] == "FINDING")[
                "evidence_id"
            ],
            "evidence_profile",
        )

    def test_ambiguous_activity_targets_are_not_selected(self):
        timeline = tuple(
            TimelineEvent(
                "synthetic_case",
                "process_activity",
                f"activity_{system_id}",
                datetime(2026, 10, 3, tzinfo=timezone.utc),
                None,
                None,
                "system_activity.csv",
                f"row:{index}",
                ("user_1",),
                "confirmed",
                "in_scope",
                (
                    ("event_type", "DELETE_RECORD"),
                    ("resource_id", "account_1"),
                    ("target_system", system_id),
                ),
            )
            for index, system_id in enumerate(
                ("account_service", "replica_service"),
                start=2,
            )
        )

        self.assertEqual(_activity_resource_targets(timeline, "user_1"), {})

    def test_security_readback_category_does_not_imply_retention(self):
        fact = make_fact(
            "",
            [
                ("service", "security_service"),
                ("event", "audit_record_read_completed"),
                ("subject_reference", "user_1"),
            ],
        )
        fact = replace(fact, data_categories=())

        normalized = _normalize_evidence_fact(fact)

        self.assertEqual(normalized.data_categories, ("SECURITY_AUDIT_LOG",))
        decision = evaluate_policy_record(
            PolicyRecord(normalized),
            self.by_category["SECURITY_AUDIT_LOG"],
            as_of="2026-10-10T00:00:00Z",
        )
        self.assertIsNone(decision.condition_met)
        self.assertEqual(decision.disposition, EvidenceDisposition.UNRESOLVED)

        retained_fact = replace(
            normalized,
            observed_fields=(
                *normalized.observed_fields,
                ObservedField(
                    "/records/0/retention_until",
                    "retention_until",
                    "2027-01-01T00:00:00Z",
                ),
            ),
        )
        retained_decision = evaluate_policy_record(
            PolicyRecord(retained_fact),
            self.by_category["SECURITY_AUDIT_LOG"],
            as_of="2026-10-10T00:00:00Z",
        )
        self.assertTrue(retained_decision.condition_met)
        self.assertEqual(
            retained_decision.disposition,
            EvidenceDisposition.COMPLIANT,
        )

    def test_support_order_text_establishes_shared_context_without_invented_flag(self):
        decision = self.assess(
            "SUPPORT_MESSAGE",
            [
                (
                    "message_text",
                    "The affected order includes: Cotton bedsheet set.",
                ),
                ("subject_reference", "user_1"),
            ],
        )

        self.assertIs(decision.condition_met, True)
        self.assertEqual(decision.action, PolicyAction.REDACT)
        self.assertEqual(decision.disposition, EvidenceDisposition.VIOLATION)

        unresolved = self.assess(
            "SUPPORT_MESSAGE",
            [("message_text", "[REDACTED]")],
        )
        self.assertIsNone(unresolved.condition_met)
        self.assertEqual(
            unresolved.disposition,
            EvidenceDisposition.UNRESOLVED,
        )

    def test_read_started_event_is_not_a_resource_observation(self):
        fact = make_fact(
            "",
            [("event", "profile_lookup_started"), ("lookup_key", "user_1")],
        )
        fact = replace(fact, data_categories=())

        normalized = _normalize_evidence_fact(fact)

        self.assertEqual(normalized.data_categories, ())
        self.assertTrue(_is_non_resource_read_attempt(normalized))

    def test_delete_and_redact_treatments(self):
        delete = self.assess("USER_PROFILE", [("email", "person@example.test")])
        self.assertEqual(delete.action, PolicyAction.DELETE)
        self.assertEqual(delete.disposition, EvidenceDisposition.VIOLATION)

        absent = self.assess(
            "USER_PROFILE", [("email", "person@example.test")], state="absent"
        )
        self.assertEqual(absent.disposition, EvidenceDisposition.COMPLIANT)
        claimed_deleted = self.assess(
            "USER_PROFILE", [("email", "person@example.test")], state="deleted"
        )
        self.assertEqual(claimed_deleted.disposition, EvidenceDisposition.VIOLATION)

        redaction = self.assess(
            "SUPPORT_MESSAGE",
            [("shared_context", "true"), ("email", "person@example.test")],
        )
        self.assertEqual(redaction.action, PolicyAction.REDACT)
        self.assertEqual(redaction.disposition, EvidenceDisposition.VIOLATION)

        redacted = self.assess(
            "SUPPORT_MESSAGE",
            [("shared_context", "true"), ("order_id", "order_3")],
        )
        self.assertEqual(redacted.disposition, EvidenceDisposition.COMPLIANT)

    def test_anonymization_and_retention_treatments(self):
        attributable = self.assess(
            "ANALYTICS_PROFILE", [("user_id", "user_1"), ("email", "person@example.test")]
        )
        self.assertEqual(attributable.action, PolicyAction.ANONYMIZE)
        self.assertEqual(attributable.disposition, EvidenceDisposition.VIOLATION)

        anonymized = self.assess(
            "PRODUCT_TELEMETRY",
            [("still_attributable", "false"), ("event_count", "12")],
        )
        self.assertEqual(anonymized.disposition, EvidenceDisposition.COMPLIANT)

        retained = self.assess(
            "LEGAL_HOLD_RECORD",
            [("legal_hold_active", "true"), ("user_id", "user_1")],
        )
        self.assertEqual(retained.action, PolicyAction.RETAIN)
        self.assertEqual(retained.disposition, EvidenceDisposition.COMPLIANT)

    def test_deleted_account_status_supplies_only_the_deleted_condition(self):
        complete_condition = self.assess(
            "ACCOUNT_TOMBSTONE",
            [
                ("account_status", "DELETED"),
                ("stable_reference_required", "true"),
                ("subject_reference", "user_1"),
            ],
        )
        self.assertTrue(complete_condition.condition_met)
        self.assertEqual(
            complete_condition.disposition,
            EvidenceDisposition.VIOLATION,
        )

        missing_reference_condition = self.assess(
            "ACCOUNT_TOMBSTONE",
            [
                ("account_status", "DELETED"),
                ("subject_reference", "user_1"),
            ],
        )
        self.assertIsNone(missing_reference_condition.condition_met)
        self.assertEqual(
            missing_reference_condition.disposition,
            EvidenceDisposition.UNRESOLVED,
        )

    def test_all_conditional_rules_require_evidence_for_their_conditions(self):
        conditions = {
            "SUPPORT_MESSAGE": [("shared_context", "true")],
            "SUPPORT_ATTACHMENT": [("belongs_only_to_subject", "true")],
            "ANALYTICS_PROFILE": [("still_attributable", "true")],
            "PRODUCT_TELEMETRY": [("still_attributable", "true")],
            "EMAIL_DELIVERY_LOG": [("email", "person@example.test")],
            "SECURITY_AUDIT_LOG": [("retention_until", "2027-01-01T00:00:00Z")],
            "LEGAL_HOLD_RECORD": [("legal_hold_active", "true")],
            "BACKUP_ARCHIVE": [("restore_access_blockable", "true")],
            "ACCOUNT_TOMBSTONE": [
                ("account_deleted", "true"),
                ("stable_reference_required", "true"),
                ("user_id", "user_1"),
            ],
        }
        for category, fields in conditions.items():
            with self.subTest(category=category):
                result = self.assess(category, fields)
                self.assertIsNotNone(result.action)
                self.assertNotEqual(result.disposition, EvidenceDisposition.UNRESOLVED)

        unresolved = self.assess("SUPPORT_MESSAGE", [("email", "person@example.test")])
        self.assertEqual(unresolved.disposition, EvidenceDisposition.UNRESOLVED)

    def test_each_of_the_fifteen_dataset_rules_is_evaluated(self):
        examples = {
            "USER_PROFILE": ([("email", "person@example.test")], EvidenceDisposition.VIOLATION),
            "SECONDARY_IDENTIFIER": ([("phone", "+12025550123")], EvidenceDisposition.VIOLATION),
            "SEARCH_INDEX_ENTRY": ([("email", "person@example.test")], EvidenceDisposition.VIOLATION),
            "CACHE_ENTRY": ([("email", "person@example.test")], EvidenceDisposition.VIOLATION),
            "SUPPORT_MESSAGE": (
                [("shared_context", "true"), ("email", "person@example.test")],
                EvidenceDisposition.VIOLATION,
            ),
            "SUPPORT_ATTACHMENT": (
                [("belongs_only_to_subject", "true"), ("user_id", "user_1")],
                EvidenceDisposition.VIOLATION,
            ),
            "ANALYTICS_PROFILE": ([("user_id", "user_1")], EvidenceDisposition.VIOLATION),
            "PRODUCT_TELEMETRY": ([("user_id", "user_1")], EvidenceDisposition.VIOLATION),
            "USER_EXPORT": ([("email", "person@example.test")], EvidenceDisposition.VIOLATION),
            "MARKETING_PROFILE": ([("email", "person@example.test")], EvidenceDisposition.VIOLATION),
            "EMAIL_DELIVERY_LOG": ([("email", "person@example.test")], EvidenceDisposition.VIOLATION),
            "SECURITY_AUDIT_LOG": (
                [("retention_until", "2027-01-01T00:00:00Z")],
                EvidenceDisposition.COMPLIANT,
            ),
            "LEGAL_HOLD_RECORD": (
                [("legal_hold_active", "true")],
                EvidenceDisposition.COMPLIANT,
            ),
            "BACKUP_ARCHIVE": (
                [("restore_access_blockable", "true"), ("restore_allowed", "false")],
                EvidenceDisposition.COMPLIANT,
            ),
            "ACCOUNT_TOMBSTONE": (
                [
                    ("account_deleted", "true"),
                    ("stable_reference_required", "true"),
                    ("user_id", "user_1"),
                ],
                EvidenceDisposition.COMPLIANT,
            ),
        }
        self.assertEqual(set(examples), set(self.by_category))
        for category, (fields, expected) in examples.items():
            with self.subTest(category=category):
                result = self.assess(category, fields)
                self.assertEqual(result.disposition, expected)
                self.assertEqual(result.action, self.by_category[category].required_action)

    def test_tombstone_permits_stable_user_id_but_not_direct_identifiers(self):
        fields = [
            ("account_deleted", "true"),
            ("stable_reference_required", "true"),
            ("user_id", "user_1"),
            ("email", "person@example.test"),
        ]
        decision = self.assess("ACCOUNT_TOMBSTONE", fields)
        self.assertEqual(decision.action, PolicyAction.REDACT)
        self.assertEqual(decision.disposition, EvidenceDisposition.VIOLATION)
        self.assertEqual(decision.prohibited_identifiers, ("email",))

        permitted = self.assess(
            "ACCOUNT_TOMBSTONE",
            [
                ("account_deleted", "true"),
                ("stable_reference_required", "true"),
                ("user_id", "user_1"),
            ],
        )
        self.assertEqual(permitted.disposition, EvidenceDisposition.COMPLIANT)

    def test_confirmed_subject_reference_is_stable_tombstone_reference(self):
        decision = self.assess(
            "ACCOUNT_TOMBSTONE",
            [
                ("account_deleted", "true"),
                ("stable_reference_required", "true"),
                ("subject_reference", "user_1"),
            ],
            overrides={"stable_user_id_reference_present": True},
        )
        self.assertEqual(decision.disposition, EvidenceDisposition.COMPLIANT)

    def test_tombstone_reference_requires_identity_resolver_confirmation(self):
        resolver = IdentityResolver(
            [
                {
                    "user_id": "user_1",
                    "email": "person@example.test",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ]
        )
        matching_fact = make_fact(
            "ACCOUNT_TOMBSTONE",
            [("subject_reference", "user_1")],
        )
        unrelated_fact = make_fact(
            "ACCOUNT_TOMBSTONE",
            [("subject_reference", "user_2")],
        )
        cutoff = datetime(2026, 10, 10, tzinfo=timezone.utc)

        self.assertTrue(
            _has_confirmed_stable_user_reference(
                matching_fact,
                resolver,
                "user_1",
                as_of=cutoff,
            )
        )
        self.assertFalse(
            _has_confirmed_stable_user_reference(
                unrelated_fact,
                resolver,
                "user_1",
                as_of=cutoff,
            )
        )

    def test_required_retention_failure_is_a_violation(self):
        decision = self.assess(
            "SECURITY_AUDIT_LOG",
            [("retention_until", "2027-01-01T00:00:00Z")],
            state="absent",
        )
        self.assertEqual(decision.action, PolicyAction.RETAIN)
        self.assertEqual(decision.disposition, EvidenceDisposition.VIOLATION)

    def test_retention_windows_and_holds_require_evidence(self):
        active_retention = self.assess(
            "SECURITY_AUDIT_LOG",
            [("retention_until", "2026-10-10T00:00:00Z")],
        )
        self.assertEqual(active_retention.condition_met, True)
        self.assertEqual(active_retention.disposition, EvidenceDisposition.COMPLIANT)

        expired_retention = self.assess(
            "SECURITY_AUDIT_LOG",
            [("retention_until", "2026-10-09T23:59:59Z")],
        )
        self.assertEqual(expired_retention.condition_met, False)
        self.assertEqual(expired_retention.disposition, EvidenceDisposition.UNRESOLVED)

        inactive_hold = self.assess(
            "LEGAL_HOLD_RECORD", [("legal_hold_active", "false")]
        )
        self.assertEqual(inactive_hold.condition_met, False)
        self.assertEqual(inactive_hold.disposition, EvidenceDisposition.UNRESOLVED)

        unblocked_archive = self.assess(
            "BACKUP_ARCHIVE", [("restore_access_blockable", "false")]
        )
        self.assertEqual(unblocked_archive.condition_met, False)
        self.assertEqual(
            unblocked_archive.disposition, EvidenceDisposition.UNRESOLVED
        )

    def test_active_legal_hold_is_verified_as_retained(self):
        evaluation = evaluate_request(
            REQUEST,
            [
                PolicyRecord(
                    make_fact(
                        "LEGAL_HOLD_RECORD",
                        [("legal_hold_active", "true"), ("user_id", "user_1")],
                        file_id="evidence_legal_hold",
                    )
                )
            ],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        self.assertEqual(evaluation.status, DeletionStatus.COMPLETE)
        plan = plan_remediation(evaluation)
        self.assertEqual(plan.steps[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(plan.steps[0]["evidence_id"], "evidence_legal_hold")

    def test_request_text_controls_not_applicable_and_empty_steps(self):
        self.assertFalse(is_deletion_request("Please keep my account active."))
        self.assertFalse(is_deletion_request("Please do not delete my account."))
        self.assertFalse(is_deletion_request("I do not want a deletion; export my data."))
        self.assertFalse(is_deletion_request("Remove me from marketing emails."))
        self.assertFalse(is_deletion_request("Please unsubscribe me from marketing."))
        result = evaluate_request(
            {**REQUEST, "request_text": "Please keep my account active."},
            (),
            lineage_analysis=None,
            evidence_complete=False,
        )
        plan = plan_remediation(result)
        self.assertEqual(result.status, DeletionStatus.NOT_APPLICABLE)
        self.assertEqual(plan.steps, ())

    def test_reported_complete_claim_does_not_override_remaining_record(self):
        evaluation = evaluate_request(
            {**REQUEST, "reported_status": "COMPLETE"},
            [
                PolicyRecord(
                    make_fact("USER_PROFILE", [("email", "person@example.test")])
                )
            ],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        self.assertEqual(evaluation.status, DeletionStatus.INCOMPLETE)
        self.assertEqual(
            plan_remediation(evaluation).steps[0]["operation"],
            "REPORT_REMAINING_RECORD",
        )

    def test_confirmed_remaining_personal_data_has_exact_plan_contract(self):
        record = PolicyRecord(
            make_fact("USER_PROFILE", [("email", "person@example.test")])
        )
        evaluation = evaluate_request(
            REQUEST,
            [record],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        plan = plan_remediation(evaluation)
        self.assertEqual(plan.status, DeletionStatus.INCOMPLETE)
        self.assertEqual(
            [(step["phase"], step["operation"], step["state"]) for step in plan.steps],
            [
                ("FINDING", "REPORT_REMAINING_RECORD", "PRESENT"),
                ("REMEDIATION", "DELETE_RECORD", "ABSENT"),
                ("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT"),
            ],
        )
        self.assertEqual(plan.steps[0]["evidence_id"], "evidence_1")
        self.assertEqual(
            [step["evidence_id"] for step in plan.steps[1:]], ["", ""]
        )
        self.assertEqual(
            [_step_sort_key(step) for step in plan.steps],
            sorted(_step_sort_key(step) for step in plan.steps),
        )
        for step in plan.steps:
            self.assertEqual(
                set(step),
                {
                    "step_no",
                    "phase",
                    "system_id",
                    "resource_id",
                    "operation",
                    "state",
                    "evidence_id",
                },
            )
            self.assertEqual(
                OPERATION_STATES[(step["phase"], step["operation"])],
                step["state"],
            )

    def test_complete_is_verification_only_and_requires_complete_evidence(self):
        record = PolicyRecord(
            make_fact("USER_PROFILE", [("email", "person@example.test")], state="absent")
        )
        evaluation = evaluate_request(
            REQUEST,
            [record],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        plan = plan_remediation(evaluation)
        self.assertEqual(plan.status, DeletionStatus.COMPLETE)
        self.assertEqual(len(plan.steps), 1)
        self.assertEqual(plan.steps[0]["phase"], "VERIFICATION")
        self.assertEqual(plan.steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(plan.steps[0]["evidence_id"], "evidence_1")

        incomplete_evidence = evaluate_request(
            REQUEST,
            [record],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
        )
        self.assertEqual(incomplete_evidence.status, DeletionStatus.INCOMPLETE)
        with self.assertRaises(PlanningError):
            plan_remediation(incomplete_evidence)

    def test_missing_or_post_cutoff_evidence_cannot_establish_completeness(self):
        empty = evaluate_request(
            REQUEST,
            (),
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            as_of="2026-10-10T00:00:00Z",
            evidence_complete=True,
        )
        self.assertEqual(empty.status, DeletionStatus.INCOMPLETE)
        self.assertTrue(empty.unresolved_evidence)

        future = replace(
            make_fact(
                "USER_PROFILE",
                [("email", "person@example.test")],
                state="absent",
                file_id="evidence_future",
            ),
            captured_at=datetime(2026, 10, 11, tzinfo=timezone.utc),
        )
        evaluation = evaluate_request(
            REQUEST,
            [PolicyRecord(future)],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            as_of="2026-10-10T00:00:00Z",
            evidence_complete=True,
        )
        self.assertEqual(evaluation.status, DeletionStatus.INCOMPLETE)
        self.assertIn("after the audit cutoff", evaluation.unresolved_evidence[0])

        request_cutoff = {**REQUEST, "audit_at": "2026-10-10T00:00:00Z"}
        future_event = replace(
            make_fact(
                "USER_PROFILE",
                [("email", "person@example.test")],
                state="absent",
                file_id="evidence_future_event",
            ),
            event_timestamp=datetime(2026, 10, 11, tzinfo=timezone.utc),
        )
        implicit_cutoff = evaluate_request(
            request_cutoff,
            [PolicyRecord(future_event)],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        self.assertEqual(implicit_cutoff.status, DeletionStatus.INCOMPLETE)
        self.assertIn(
            "after the audit cutoff", implicit_cutoff.unresolved_evidence[0]
        )

    def test_redact_and_anonymize_plans_use_exact_operation_state_pairs(self):
        redaction = evaluate_request(
            REQUEST,
            [
                PolicyRecord(
                    make_fact(
                        "SUPPORT_MESSAGE",
                        [
                            ("shared_context", "true"),
                            ("email", "person@example.test"),
                        ],
                        file_id="evidence_support",
                    )
                )
            ],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        redaction_plan = plan_remediation(redaction)
        self.assertEqual(
            [(step["operation"], step["state"]) for step in redaction_plan.steps],
            [
                ("REPORT_EXPOSED_PII", "PRESENT"),
                ("REDACT_RECORD", "REDACTED"),
                ("VERIFY_RECORD_REDACTED", "REDACTED"),
            ],
        )
        self.assertEqual(redaction_plan.steps[0]["evidence_id"], "evidence_support")
        self.assertEqual(
            [step["evidence_id"] for step in redaction_plan.steps[1:]], ["", ""]
        )

        anonymization = evaluate_request(
            REQUEST,
            [
                PolicyRecord(
                    make_fact(
                        "ANALYTICS_PROFILE",
                        [("user_id", "user_1"), ("event_count", "12")],
                        file_id="evidence_analytics",
                    )
                )
            ],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        anonymization_plan = plan_remediation(anonymization)
        self.assertEqual(
            [(step["operation"], step["state"]) for step in anonymization_plan.steps],
            [
                ("REPORT_EXPOSED_PII", "PRESENT"),
                ("ANONYMIZE_RECORD", "ANONYMIZED"),
                ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            ],
        )

    def test_confirmed_active_flow_is_found_stopped_then_verified(self):
        flow_fact = make_fact(
            "DATA_FLOW",
            [("user_id", "user_1")],
            system_id="integration_service",
            resource_id="flow_1",
            file_id="evidence_flow",
        )
        edge = LineageEdge(
            "edge_1", "account_service", "search_service", "activity_1",
            "flow_1", "DATA_FLOW_CONFIG", "ACTIVE", "enabled",
            datetime(2026, 10, 1, tzinfo=timezone.utc), None,
            datetime(2026, 10, 1, tzinfo=timezone.utc), None,
            "evidence_flow", "evidence/flow.json", "/flows/0",
            "confirmed", "confirmed", ("user_1",), True, "",
        )
        path = ResurrectionPath(
            "user_1", "confirmed", ("account_service", "search_service"),
            (edge,), (), (), ("evidence_flow",), "confirmed active process",
        )
        analysis = ResurrectionAnalysis("user_1", (path,), (), ())
        evaluation = evaluate_request(
            REQUEST,
            [PolicyRecord(flow_fact)],
            rules=self.rules,
            lineage_analysis=analysis,
            evidence_complete=True,
        )
        plan = plan_remediation(evaluation)
        self.assertEqual(
            [(step["phase"], step["operation"], step["state"]) for step in plan.steps],
            [
                ("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
                ("REMEDIATION", "DISABLE_DATA_FLOW", "DISABLED"),
                ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
            ],
        )
        self.assertEqual(plan.steps[0]["evidence_id"], "evidence_flow")
        self.assertEqual(
            [step["evidence_id"] for step in plan.steps[1:]], ["", ""]
        )

    def test_confirmed_restore_risk_is_blocked_without_deleting_backup(self):
        archive = PolicyRecord(
            make_fact(
                "BACKUP_ARCHIVE",
                [
                    ("restore_access_blockable", "true"),
                    ("restore_allowed", "true"),
                ],
                resource_id="backup_1",
                file_id="evidence_backup",
            )
        )
        evaluation = evaluate_request(
            REQUEST,
            [archive],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        plan = plan_remediation(evaluation)
        self.assertEqual(
            [step["operation"] for step in plan.steps],
            ["REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"],
        )

    def test_retained_backup_verifies_record_and_blocked_restore(self):
        evaluation = evaluate_request(
            REQUEST,
            [
                PolicyRecord(
                    make_fact(
                        "BACKUP_ARCHIVE",
                        [
                            ("restore_access_blockable", "true"),
                            ("restore_allowed", "false"),
                        ],
                        resource_id="backup_safe",
                        file_id="evidence_backup_safe",
                    )
                )
            ],
            rules=self.rules,
            lineage_analysis=EMPTY_LINEAGE,
            evidence_complete=True,
        )
        self.assertEqual(evaluation.status, DeletionStatus.COMPLETE)
        plan = plan_remediation(evaluation)
        self.assertEqual(
            [(step["operation"], step["state"]) for step in plan.steps],
            [
                ("VERIFY_RECORD_PRESENT", "PRESENT"),
                ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
            ],
        )
        self.assertTrue(
            all(step["evidence_id"] == "evidence_backup_safe" for step in plan.steps)
        )

    def test_possible_flow_remains_uncertain_and_is_not_reported_as_active(self):
        edge = LineageEdge(
            "edge_possible", "account_service", "search_service", "activity_possible",
            "flow_possible", "DATA_FLOW_CONFIG", "ACTIVE", "enabled",
            datetime(2026, 10, 1, tzinfo=timezone.utc), None,
            datetime(2026, 10, 1, tzinfo=timezone.utc), None,
            "evidence_possible", "evidence/flow.json", "/flows/0",
            "possible", "confirmed", ("user_1",), True,
            "configuration validity is not established",
        )
        possible = ResurrectionPath(
            "user_1", "possible", ("account_service", "search_service"),
            (edge,), (), (), ("evidence_possible",), "possible active process",
        )
        analysis = ResurrectionAnalysis("user_1", (), (possible,), ())
        evaluation = evaluate_request(
            REQUEST,
            [
                PolicyRecord(
                    make_fact("USER_PROFILE", [("email", "person@example.test")])
                )
            ],
            rules=self.rules,
            lineage_analysis=analysis,
            evidence_complete=True,
        )
        self.assertEqual(evaluation.status, DeletionStatus.INCOMPLETE)
        self.assertFalse(evaluation.confirmed_paths)
        self.assertFalse(
            any(
                decision.fact.data_categories == ("DATA_FLOW",)
                for decision in evaluation.decisions
            )
        )
        self.assertTrue(
            all(
                step["operation"] != "REPORT_ACTIVE_DATA_FLOW"
                for step in plan_remediation(evaluation).steps
            )
        )

    def test_unresolved_identity_and_lineage_never_become_complete_or_invent_steps(self):
        unresolved_fact = make_fact(
            "USER_PROFILE", [("email", "person@example.test")], file_id="evidence_ambiguous"
        )
        edge = LineageEdge(
            "edge_unknown", None, "search_service", "activity_unknown", None,
            "DATA_FLOW_CONFIG", "UNKNOWN", None, None, None, None, None,
            "evidence_ambiguous", "evidence/flow.json", "/flows/0",
            "unsupported", "ambiguous", ("user_1",), False,
            "source system is missing",
        )
        unresolved = UnresolvedLineage("user_1", edge, "source system is missing")
        analysis = ResurrectionAnalysis("user_1", (), (), (unresolved,))
        evaluation = evaluate_request(
            REQUEST,
            [PolicyRecord(unresolved_fact, identity_status="ambiguous")],
            rules=self.rules,
            lineage_analysis=analysis,
            evidence_complete=True,
        )
        self.assertEqual(evaluation.status, DeletionStatus.INCOMPLETE)
        self.assertTrue(evaluation.unresolved_evidence)
        with self.assertRaises(PlanningError):
            plan_remediation(evaluation)

    def test_repeated_planning_is_deterministic(self):
        records = [
            PolicyRecord(
                make_fact(
                    "USER_PROFILE",
                    [("email", "person@example.test")],
                    resource_id="z_resource",
                    file_id="evidence_z",
                    system_id="z_service",
                )
            ),
            PolicyRecord(
                make_fact(
                    "SEARCH_INDEX_ENTRY",
                    [("email", "person@example.test")],
                    resource_id="a_resource",
                    file_id="evidence_a",
                    system_id="a_service",
                )
            ),
        ]
        evaluations = [
            evaluate_request(
                REQUEST,
                records,
                rules=self.rules,
                lineage_analysis=EMPTY_LINEAGE,
                evidence_complete=True,
            )
            for _ in range(2)
        ]
        plans = [plan_remediation(item) for item in evaluations]
        self.assertEqual(plans[0].steps, plans[1].steps)
        self.assertEqual(
            [_step_sort_key(step) for step in plans[0].steps],
            sorted(_step_sort_key(step) for step in plans[0].steps),
        )
        evidence_ids = {"evidence_z", "evidence_a"}
        for step in plans[0].steps:
            self.assertEqual(
                set(step),
                {
                    "step_no",
                    "phase",
                    "system_id",
                    "resource_id",
                    "operation",
                    "state",
                    "evidence_id",
                },
            )
            self.assertIn(step["evidence_id"], evidence_ids | {""})
        self.assertEqual(
            [step["step_no"] for step in plans[0].steps],
            list(range(1, len(plans[0].steps) + 1)),
        )


if __name__ == "__main__":
    unittest.main()
