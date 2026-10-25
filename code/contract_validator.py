"""Validation for the Ghost Data Still Exists output CSV contract."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


OUTPUT_COLUMNS = ("case_id", "deletion_status", "steps_json")
STEP_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}

PHASE_OPERATIONS = {
    "FINDING": (
        ("REPORT_REMAINING_RECORD", "PRESENT"),
        ("REPORT_EXPOSED_PII", "PRESENT"),
        ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"),
        ("REPORT_RESTORE_RISK", "ACTIVE"),
    ),
    "REMEDIATION": (
        ("DISABLE_DATA_FLOW", "DISABLED"),
        ("BLOCK_RESTORE", "BLOCKED"),
        ("DELETE_RECORD", "ABSENT"),
        ("REDACT_RECORD", "REDACTED"),
        ("ANONYMIZE_RECORD", "ANONYMIZED"),
    ),
    "VERIFICATION": (
        ("VERIFY_RECORD_ABSENT", "ABSENT"),
        ("VERIFY_RECORD_PRESENT", "PRESENT"),
        ("VERIFY_RECORD_REDACTED", "REDACTED"),
        ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
        ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
    ),
}

PHASE_ORDER = {phase: rank for rank, phase in enumerate(PHASE_OPERATIONS)}
OPERATION_ORDER = {
    (phase, operation): rank
    for phase, operations in PHASE_OPERATIONS.items()
    for rank, (operation, _) in enumerate(operations)
}
OPERATION_STATES = {
    (phase, operation): state
    for phase, operations in PHASE_OPERATIONS.items()
    for operation, state in operations
}


class ContractValidationError(ValueError):
    """Raised when one or more output rows violate the submission contract."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("\n".join(errors))


def _read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            return [], []
        rows: list[dict[str, str]] = []
        for line_no, values in enumerate(reader, start=2):
            if len(values) != len(header):
                raise ContractValidationError(
                    [f"{path}: row {line_no} has {len(values)} columns; "
                     f"expected {len(header)}"]
                )
            rows.append(dict(zip(header, values)))
    return header, rows


def _required_column(
    path: Path,
    header: list[str],
    column: str,
    errors: list[str],
) -> bool:
    if header.count(column) != 1:
        errors.append(f"{path}: expected exactly one {column!r} column")
        return False
    return True


def _load_ids(
    path: Path,
    column: str,
    errors: list[str],
) -> set[str]:
    try:
        header, rows = _read_csv(path)
    except (OSError, UnicodeError, ContractValidationError) as exc:
        errors.append(str(exc))
        return set()
    if not _required_column(path, header, column, errors):
        return set()
    values = [row[column] for row in rows]
    if any(not value for value in values):
        errors.append(f"{path}: {column!r} contains an empty value")
    if len(values) != len(set(values)):
        errors.append(f"{path}: duplicate {column!r} values")
    return {value for value in values if value}


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant {value}")


def _step_sort_key(step: dict[str, Any]) -> tuple[int, int, str, str]:
    return (
        PHASE_ORDER[step["phase"]],
        OPERATION_ORDER[(step["phase"], step["operation"])],
        step["system_id"],
        step["resource_id"],
    )


def _validate_steps(
    case_id: str,
    status: str,
    raw_steps: str,
    evidence_ids: set[str],
    errors: list[str],
) -> None:
    try:
        steps = json.loads(
            raw_steps,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        errors.append(f"{case_id}: steps_json is invalid JSON ({exc})")
        return

    if not isinstance(steps, list):
        errors.append(f"{case_id}: steps_json must be a JSON array")
        return

    if status == "NOT_APPLICABLE":
        if steps:
            errors.append(f"{case_id}: NOT_APPLICABLE must have no steps")
        return

    if status == "COMPLETE":
        if not steps:
            errors.append(f"{case_id}: COMPLETE must contain verification steps")
    elif status == "INCOMPLETE":
        present_phases = {
            step.get("phase")
            for step in steps
            if isinstance(step, dict)
        }
        expected_phases = {"FINDING", "REMEDIATION", "VERIFICATION"}
        if present_phases != expected_phases:
            errors.append(
                f"{case_id}: INCOMPLETE must contain FINDING, REMEDIATION, "
                "and VERIFICATION steps"
            )

    validated_steps: list[dict[str, Any]] = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            errors.append(f"{case_id}: step {index} must be a JSON object")
            continue
        if set(step) != STEP_FIELDS:
            missing = sorted(STEP_FIELDS - set(step))
            extra = sorted(set(step) - STEP_FIELDS)
            errors.append(
                f"{case_id}: step {index} fields mismatch "
                f"(missing={missing}, extra={extra})"
            )
            continue

        step_no = step["step_no"]
        if type(step_no) is not int or step_no != index:
            errors.append(
                f"{case_id}: step {index} must have consecutive integer "
                f"step_no {index}"
            )

        phase = step["phase"]
        operation = step["operation"]
        if not isinstance(phase, str) or phase not in PHASE_OPERATIONS:
            errors.append(f"{case_id}: step {index} has invalid phase {phase!r}")
            continue
        if not isinstance(operation, str) or (phase, operation) not in OPERATION_STATES:
            errors.append(
                f"{case_id}: step {index} has invalid operation {operation!r} "
                f"for phase {phase!r}"
            )
            continue

        expected_state = OPERATION_STATES[(phase, operation)]
        if step["state"] != expected_state:
            errors.append(
                f"{case_id}: step {index} operation {operation!r} requires "
                f"state {expected_state!r}"
            )

        for field in ("system_id", "resource_id", "evidence_id"):
            if not isinstance(step[field], str):
                errors.append(
                    f"{case_id}: step {index} field {field!r} must be a string"
                )
        if not isinstance(step["system_id"], str) or not step["system_id"]:
            errors.append(f"{case_id}: step {index} system_id must be non-empty")
        if not isinstance(step["resource_id"], str) or not step["resource_id"]:
            errors.append(f"{case_id}: step {index} resource_id must be non-empty")
        evidence_id = step["evidence_id"]
        if isinstance(evidence_id, str) and evidence_id and evidence_id not in evidence_ids:
            errors.append(
                f"{case_id}: step {index} references unknown evidence_id "
                f"{evidence_id!r}"
            )

        if status == "COMPLETE":
            if phase != "VERIFICATION":
                errors.append(f"{case_id}: COMPLETE may contain verification steps only")
            if not evidence_id:
                errors.append(
                    f"{case_id}: COMPLETE verification steps require evidence_id"
                )
        elif status == "INCOMPLETE":
            if phase == "FINDING" and not evidence_id:
                errors.append(
                    f"{case_id}: INCOMPLETE finding steps require evidence_id"
                )
            if phase in {"REMEDIATION", "VERIFICATION"} and evidence_id:
                errors.append(
                    f"{case_id}: INCOMPLETE remediation and future verification "
                    "steps must have empty evidence_id"
                )

        validated_steps.append(step)

    sortable = all(
        isinstance(step.get("phase"), str)
        and step["phase"] in PHASE_OPERATIONS
        and isinstance(step.get("operation"), str)
        and (step["phase"], step["operation"]) in OPERATION_ORDER
        and isinstance(step.get("system_id"), str)
        and isinstance(step.get("resource_id"), str)
        for step in validated_steps
    )
    if len(validated_steps) == len(steps) and sortable:
        keys = [_step_sort_key(step) for step in validated_steps]
        if keys != sorted(keys):
            errors.append(
                f"{case_id}: steps are not in canonical phase/operation/system/"
                "resource order"
            )


def validate_output(
    output_path: str | Path,
    requests_path: str | Path,
    evidence_manifest_path: str | Path,
    activity_path: str | Path,
    audit_path: str | Path,
    *,
    expected_case_count: int | None = 518,
) -> None:
    """Validate an output CSV against requests, evidence IDs, and the contract.

    Set ``expected_case_count=None`` for small synthetic test fixtures. The
    request/output ID coverage check remains exact in either mode.
    """
    output_path = Path(output_path)
    requests_path = Path(requests_path)
    errors: list[str] = []

    try:
        request_header, request_rows = _read_csv(requests_path)
    except (OSError, UnicodeError, ContractValidationError) as exc:
        raise ContractValidationError([str(exc)]) from exc

    _required_column(requests_path, request_header, "case_id", errors)
    requested_ids = [row.get("case_id", "") for row in request_rows]
    if any(not case_id for case_id in requested_ids):
        errors.append(f"{requests_path}: case_id contains an empty value")
    if len(requested_ids) != len(set(requested_ids)):
        errors.append(f"{requests_path}: duplicate case_id values")
    if expected_case_count is not None and len(requested_ids) != expected_case_count:
        errors.append(
            f"{requests_path}: expected {expected_case_count} request rows, "
            f"found {len(requested_ids)}"
        )

    try:
        output_header, output_rows = _read_csv(output_path)
    except (OSError, UnicodeError, ContractValidationError) as exc:
        errors.append(str(exc))
        output_header, output_rows = [], []

    if output_header != list(OUTPUT_COLUMNS):
        errors.append(
            f"{output_path}: columns must be exactly "
            f"{','.join(OUTPUT_COLUMNS)} in that order"
        )

    evidence_ids: set[str] = set()
    evidence_ids.update(_load_ids(evidence_manifest_path, "file_id", errors))
    evidence_ids.update(_load_ids(activity_path, "activity_id", errors))
    evidence_ids.update(_load_ids(audit_path, "audit_id", errors))

    output_ids = [row.get("case_id", "") for row in output_rows]
    if any(not case_id for case_id in output_ids):
        errors.append(f"{output_path}: case_id contains an empty value")
    if len(output_ids) != len(set(output_ids)):
        errors.append(f"{output_path}: duplicate case_id values")
    if output_ids != sorted(output_ids):
        errors.append(f"{output_path}: rows are not sorted by case_id")

    requested_set = set(requested_ids)
    output_set = set(output_ids)
    missing_ids = sorted(requested_set - output_set)
    extra_ids = sorted(output_set - requested_set)
    if missing_ids:
        errors.append(f"{output_path}: missing request case_ids: {missing_ids}")
    if extra_ids:
        errors.append(f"{output_path}: contains unknown case_ids: {extra_ids}")
    if len(output_rows) != len(requested_ids):
        errors.append(
            f"{output_path}: expected {len(requested_ids)} output rows, "
            f"found {len(output_rows)}"
        )

    for row in output_rows:
        case_id = row.get("case_id", "")
        status = row.get("deletion_status", "")
        if status not in ALLOWED_STATUSES:
            errors.append(f"{case_id}: invalid deletion_status {status!r}")
            continue
        _validate_steps(
            case_id,
            status,
            row.get("steps_json", ""),
            evidence_ids,
            errors,
        )

    if errors:
        raise ContractValidationError(errors)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "output.csv",
        help="output CSV to validate (default: repository-root output.csv)",
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=repo_root / "dataset",
        help="directory containing challenge CSV inputs",
    )
    args = parser.parse_args()

    try:
        validate_output(
            args.output,
            args.dataset / "deletion_requests.csv",
            args.dataset / "evidence_files.csv",
            args.dataset / "system_activity.csv",
            args.dataset / "user_audit_log.csv",
        )
    except ContractValidationError as exc:
        print(f"Output validation failed:\n{exc}", file=sys.stderr)
        return 1

    print(f"Output validation passed: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
