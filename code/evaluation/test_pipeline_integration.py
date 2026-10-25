import csv
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from contract_validator import validate_output
from evidence_model import EvidenceFact, ObservedField
from main import _normalize_evidence_fact, run_pipeline


class PipelineIntegrationTests(unittest.TestCase):
    def test_inventory_targets_are_preserved_from_explicit_table_or_collection(self) -> None:
        def fact(location: str, fields: tuple[ObservedField, ...]) -> EvidenceFact:
            return EvidenceFact(
                file_id="evidence_inventory",
                source_path="evidence/records/inventory.json",
                source_location=location,
                extraction_method="fixture",
                system_id=None,
                resource_id="resource_1",
                candidate_identifiers=(),
                data_categories=(),
                personal_fields=(),
                record_state="PRESENT",
                event_timestamp=None,
                captured_at=None,
                confidence=None,
                observed_fields=fields,
            )

        table_fact = _normalize_evidence_fact(
            fact(
                "table:search_documents_primary/row:1",
                (ObservedField("resource_id", "resource_id", "search_1"),),
            )
        )
        collection_fact = _normalize_evidence_fact(
            fact(
                "/records/0",
                (
                    ObservedField("resource_id", "resource_id", "export_1"),
                    ObservedField(
                        "collection", "collection", "customer_export_jobs"
                    ),
                ),
            )
        )

        self.assertEqual(table_fact.system_id, "search_service")
        self.assertEqual(table_fact.data_categories, ("SEARCH_INDEX_ENTRY",))
        self.assertEqual(collection_fact.system_id, "export_service")

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.dataset = self.root / "dataset"
        self.evidence = self.dataset / "evidence" / "records"
        self.evidence.mkdir(parents=True)
        self.requests_path = self.dataset / "deletion_requests.csv"
        self.manifest_path = self.dataset / "evidence_files.csv"
        self.captured_at_by_id: dict[str, str] = {}

        shutil.copyfile(
            REPO_ROOT / "dataset" / "deletion_rules.csv",
            self.dataset / "deletion_rules.csv",
        )
        self.write_csv(
            self.dataset / "user_identities.csv",
            ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
            [
                {
                    "user_id": "user_complete",
                    "name": "Synthetic Complete",
                    "email": "complete@example.test",
                    "phone": "",
                    "email_hash": "",
                    "updated_at": "2026-01-01T00:00:00Z",
                },
                {
                    "user_id": "user_incomplete",
                    "name": "Synthetic Incomplete",
                    "email": "incomplete@example.test",
                    "phone": "",
                    "email_hash": "",
                    "updated_at": "2026-01-01T00:00:00Z",
                },
            ],
        )
        self.write_csv(
            self.dataset / "user_audit_log.csv",
            [
                "audit_id",
                "user_id",
                "event_time",
                "field_name",
                "old_value",
                "new_value",
            ],
            [],
        )
        self.write_csv(
            self.dataset / "system_activity.csv",
            [
                "activity_id",
                "event_time",
                "event_type",
                "source_system",
                "target_system",
                "resource_id",
                "reported_result",
                "details",
            ],
            [
                {
                    "activity_id": "activity_complete",
                    "event_time": "2026-02-28T00:00:00Z",
                    "event_type": "DELETE_RECORD",
                    "source_system": "account_service",
                    "target_system": "",
                    "resource_id": "account_complete",
                    "reported_result": "SUCCESS",
                    "details": "email=complete@example.test",
                }
            ],
        )
        self.write_csv(
            self.requests_path,
            [
                "case_id",
                "email",
                "requested_at",
                "reported_status",
                "reported_at",
                "audit_at",
                "request_text",
            ],
            [
                {
                    "case_id": "case_001",
                    "email": "complete@example.test",
                    "requested_at": "2026-02-01T00:00:00Z",
                    "reported_status": "NOT_STARTED",
                    "reported_at": "",
                    "audit_at": "2026-06-30T00:00:00Z",
                    "request_text": "Please delete my account and personal data.",
                },
                {
                    "case_id": "case_002",
                    "email": "incomplete@example.test",
                    "requested_at": "2026-02-01T00:00:00Z",
                    "reported_status": "COMPLETE",
                    "reported_at": "2026-02-02T00:00:00Z",
                    "audit_at": "2026-06-30T00:00:00Z",
                    "request_text": "Please erase my account and personal data.",
                },
                {
                    "case_id": "case_003",
                    "email": "unmatched@example.test",
                    "requested_at": "2026-02-01T00:00:00Z",
                    "reported_status": "COMPLETE",
                    "reported_at": "2026-02-02T00:00:00Z",
                    "audit_at": "2026-06-30T00:00:00Z",
                    "request_text": "Please do not delete my account.",
                },
            ],
        )

        self.add_evidence(
            "evidence_absent",
            "2026-03-01T00:00:00Z",
            {
                "system_id": "account_service",
                "resource_id": "account_complete",
                "data_category": "USER_PROFILE",
                "status": "absent",
                "event_time": "2026-02-28T00:00:00Z",
            },
        )
        self.add_evidence(
            "evidence_present",
            "2026-03-01T00:00:00Z",
            {
                "data_store": "profile_service",
                "resource_id": "profile_incomplete",
                "user_id": "user_incomplete",
                "email": "incomplete@example.test",
                "collection": "customer_profiles",
                "status": "present",
                "event_time": "2026-02-28T00:00:00Z",
            },
        )
        self.add_evidence(
            "evidence_future",
            "2026-07-01T00:00:00Z",
            {
                "system_id": "account_service",
                "resource_id": "account_complete",
                "user_id": "user_complete",
                "email": "complete@example.test",
                "data_category": "USER_PROFILE",
                "status": "present",
                "event_time": "2026-07-01T00:00:00Z",
            },
        )
        self.write_manifest()

    @staticmethod
    def write_csv(
        path: Path,
        fieldnames: list[str],
        rows: list[dict[str, str]],
    ) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

    def add_evidence(
        self,
        evidence_id: str,
        captured_at: str,
        record: dict[str, str],
    ) -> None:
        path = self.evidence / f"{evidence_id}.json"
        path.write_text(
            json.dumps({"records": [record]}),
            encoding="utf-8",
        )
        self.captured_at_by_id[evidence_id] = captured_at

    def write_manifest(self) -> None:
        rows = []
        for path in sorted(self.evidence.glob("*.json")):
            evidence_id = path.stem
            rows.append(
                {
                    "file_id": evidence_id,
                    "file_path": f"evidence/records/{path.name}",
                    "origin": "synthetic_fixture",
                    "captured_at": self.captured_at_by_id.get(
                        evidence_id,
                        "2026-03-01T00:00:00Z",
                    ),
                }
            )
        self.write_csv(
            self.manifest_path,
            ["file_id", "file_path", "origin", "captured_at"],
            rows,
        )

    def run_fixture(self, output_path: Path):
        return run_pipeline(
            self.dataset,
            output_path=output_path,
            expected_case_count=3,
        )

    def test_end_to_end_status_contract_cutoff_and_deterministic_order(self) -> None:
        first_output = self.root / "first.csv"
        first = self.run_fixture(first_output)
        second_output = self.root / "second.csv"
        second = self.run_fixture(second_output)

        self.assertFalse(first.failures)
        self.assertTrue(first.output_written)
        self.assertEqual(first.rows, second.rows)
        self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
        self.assertEqual(
            [row["case_id"] for row in first.rows],
            ["case_001", "case_002", "case_003"],
        )
        statuses = {row["case_id"]: row["deletion_status"] for row in first.rows}
        self.assertEqual(
            statuses,
            {
                "case_001": "COMPLETE",
                "case_002": "INCOMPLETE",
                "case_003": "NOT_APPLICABLE",
            },
        )
        complete_steps = json.loads(first.rows[0]["steps_json"])
        self.assertEqual(
            [(step["phase"], step["operation"]) for step in complete_steps],
            [("VERIFICATION", "VERIFY_RECORD_ABSENT")],
        )
        self.assertEqual(complete_steps[0]["evidence_id"], "evidence_absent")
        self.assertNotIn("evidence_future", first.rows[0]["steps_json"])
        incomplete_steps = json.loads(first.rows[1]["steps_json"])
        remediation = next(
            step for step in incomplete_steps if step["phase"] == "REMEDIATION"
        )
        self.assertEqual(remediation["system_id"], "profile_service")
        self.assertEqual(remediation["resource_id"], "profile_incomplete")
        self.assertEqual(json.loads(first.rows[2]["steps_json"]), [])

        validate_output(
            first_output,
            self.requests_path,
            self.manifest_path,
            self.dataset / "system_activity.csv",
            self.dataset / "user_audit_log.csv",
            expected_case_count=3,
        )

    def test_malformed_evidence_is_isolated_and_prevents_partial_output(self) -> None:
        malformed = self.evidence / "evidence_broken.json"
        malformed.write_text('{"records":[}', encoding="utf-8")
        self.write_manifest()
        output_path = self.root / "must_not_exist.csv"

        result = self.run_fixture(output_path)

        self.assertEqual(result.evidence_failure_count, 1)
        self.assertTrue(result.failures)
        failure = next(item for item in result.failures if item.case_id == "case_001")
        self.assertEqual(failure.error_type, "CaseProcessingError")
        self.assertEqual(failure.cause_type, "PlanningError")
        self.assertTrue(failure.error_message)
        self.assertTrue(failure.cause_message)
        self.assertFalse(result.output_written)
        self.assertFalse(output_path.exists())
        successful_ids = {row["case_id"] for row in result.rows}
        self.assertIn("case_002", successful_ids)
        self.assertIn("case_003", successful_ids)
        self.assertNotIn("case_001", successful_ids)
        self.assertEqual(
            result.status_counts,
            (("INCOMPLETE", 1), ("NOT_APPLICABLE", 1)),
        )

    def test_failure_diagnostics_are_case_level_and_do_not_enable_output(self) -> None:
        malformed = self.evidence / "evidence_broken.json"
        malformed.write_text('{"records":[}', encoding="utf-8")
        self.write_manifest()
        diagnostics_path = self.root / "diagnostics.csv"

        result = run_pipeline(
            self.dataset,
            output_path=self.root / "must_not_exist.csv",
            diagnostics_path=diagnostics_path,
            expected_case_count=3,
        )

        self.assertTrue(result.failures)
        with diagnostics_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual([row["case_id"] for row in rows], ["case_001"])
        self.assertEqual(rows[0]["failure_stage"], "planning")
        self.assertEqual(rows[0]["classification"], "unsupported evidence format")


if __name__ == "__main__":
    unittest.main()
