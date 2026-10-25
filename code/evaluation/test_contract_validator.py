import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

from contract_validator import ContractValidationError, validate_output


class ContractValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.requests = self.root / "requests.csv"
        self.output = self.root / "output.csv"
        self.manifest = self.root / "manifest.csv"
        self.activity = self.root / "activity.csv"
        self.audit = self.root / "audit.csv"
        self.write_csv(self.requests, ["case_id"], [{"case_id": "case_1"}])
        self.write_csv(self.manifest, ["file_id"], [{"file_id": "file_1"}])
        self.write_csv(self.activity, ["activity_id"], [{"activity_id": "activity_1"}])
        self.write_csv(self.audit, ["audit_id"], [{"audit_id": "audit_1"}])

    @staticmethod
    def write_csv(path: Path, header: list[str], rows: list[dict[str, str]]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=header)
            writer.writeheader()
            writer.writerows(rows)

    @staticmethod
    def step(
        step_no: int,
        phase: str,
        operation: str,
        state: str,
        evidence_id: str,
        system_id: str = "account_service",
        resource_id: str = "resource_1",
    ) -> dict[str, object]:
        return {
            "step_no": step_no,
            "phase": phase,
            "system_id": system_id,
            "resource_id": resource_id,
            "operation": operation,
            "state": state,
            "evidence_id": evidence_id,
        }

    def write_output(
        self,
        rows: list[tuple[str, str, list[dict[str, object]]]],
        header: list[str] | None = None,
    ) -> None:
        self.write_csv(
            self.output,
            header or ["case_id", "deletion_status", "steps_json"],
            [
                {
                    "case_id": case_id,
                    "deletion_status": status,
                    "steps_json": json.dumps(steps),
                }
                for case_id, status, steps in rows
            ],
        )

    def validate(self) -> None:
        validate_output(
            self.output,
            self.requests,
            self.manifest,
            self.activity,
            self.audit,
            expected_case_count=None,
        )

    def test_supplied_sample_answers_satisfy_contract(self) -> None:
        requests = REPO_ROOT / "dataset" / "sample_deletion_requests.csv"
        output = REPO_ROOT / "dataset" / "sample_output.csv"
        validate_output(
            output,
            requests,
            REPO_ROOT / "dataset" / "evidence_files.csv",
            REPO_ROOT / "dataset" / "system_activity.csv",
            REPO_ROOT / "dataset" / "user_audit_log.csv",
            expected_case_count=32,
        )
        with requests.open(encoding="utf-8-sig", newline="") as handle:
            request_ids = {row["case_id"] for row in csv.DictReader(handle)}
        with output.open(encoding="utf-8-sig", newline="") as handle:
            output_rows = list(csv.DictReader(handle))
        self.assertEqual(len(output_rows), 32)
        self.assertEqual({row["case_id"] for row in output_rows}, request_ids)

    def test_not_applicable_requires_empty_steps(self) -> None:
        self.write_output([("case_1", "NOT_APPLICABLE", [])])
        self.validate()

    def test_not_applicable_rejects_steps(self) -> None:
        step = self.step(
            1, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "file_1"
        )
        self.write_output([("case_1", "NOT_APPLICABLE", [step])])
        with self.assertRaisesRegex(ContractValidationError, "NOT_APPLICABLE"):
            self.validate()

    def test_rejects_operation_with_wrong_state(self) -> None:
        step = self.step(
            1, "FINDING", "REPORT_REMAINING_RECORD", "ACTIVE", "file_1"
        )
        self.write_output([("case_1", "COMPLETE", [step])])
        with self.assertRaisesRegex(ContractValidationError, "requires state"):
            self.validate()

    def test_rejects_duplicate_case_ids(self) -> None:
        self.write_output(
            [
                ("case_1", "NOT_APPLICABLE", []),
                ("case_1", "NOT_APPLICABLE", []),
            ]
        )
        with self.assertRaisesRegex(ContractValidationError, "duplicate case_id"):
            self.validate()

    def test_rejects_invalid_evidence_reference(self) -> None:
        step = self.step(
            1, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "unknown_file"
        )
        self.write_output([("case_1", "INCOMPLETE", [step])])
        with self.assertRaisesRegex(ContractValidationError, "unknown evidence_id"):
            self.validate()

    def test_rejects_incorrect_phase_order(self) -> None:
        steps = [
            self.step(1, "REMEDIATION", "DELETE_RECORD", "ABSENT", ""),
            self.step(2, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "file_1"),
            self.step(3, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
        ]
        self.write_output([("case_1", "INCOMPLETE", steps)])
        with self.assertRaisesRegex(ContractValidationError, "canonical"):
            self.validate()

    def test_rejects_noncanonical_operation_order(self) -> None:
        steps = [
            self.step(1, "FINDING", "REPORT_EXPOSED_PII", "PRESENT", "file_1"),
            self.step(2, "FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "file_1"),
            self.step(3, "REMEDIATION", "DELETE_RECORD", "ABSENT", ""),
            self.step(4, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", ""),
        ]
        self.write_output([("case_1", "INCOMPLETE", steps)])
        with self.assertRaisesRegex(ContractValidationError, "canonical"):
            self.validate()

    def test_rejects_wrong_output_header_order(self) -> None:
        self.write_output(
            [("case_1", "NOT_APPLICABLE", [])],
            ["deletion_status", "case_id", "steps_json"],
        )
        with self.assertRaisesRegex(ContractValidationError, "columns must be exactly"):
            self.validate()

    def test_rejects_missing_requested_case(self) -> None:
        self.write_output([])
        with self.assertRaisesRegex(ContractValidationError, "missing request case_ids"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
