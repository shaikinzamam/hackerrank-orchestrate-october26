"""Normalized, provenance-preserving evidence facts."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import date, datetime
from typing import Any


@dataclass(frozen=True, order=True)
class ObservedField:
    """A scalar value observed at a source-specific field path."""

    path: str
    name: str
    value: str


@dataclass(frozen=True, order=True)
class IdentifierCandidate:
    """An identifier-like value to be resolved by a later identity stage."""

    field_name: str
    value: str


@dataclass(frozen=True)
class EvidenceFact:
    """A source-backed observation, not a deletion-status conclusion."""

    file_id: str
    source_path: str
    system_id: str | None
    resource_id: str | None
    candidate_identifiers: tuple[IdentifierCandidate, ...]
    data_categories: tuple[str, ...]
    personal_fields: tuple[str, ...]
    record_state: str | None
    event_timestamp: datetime | None
    captured_at: datetime | None
    source_location: str
    extraction_method: str
    confidence: float | None
    observed_fields: tuple[ObservedField, ...]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation with ISO timestamps."""
        result = asdict(self)
        result["event_timestamp"] = (
            self.event_timestamp.isoformat() if self.event_timestamp else None
        )
        result["captured_at"] = (
            self.captured_at.isoformat() if self.captured_at else None
        )
        return result


@dataclass(frozen=True)
class ExtractionWarning:
    """A non-fatal limitation encountered while inspecting an evidence file."""

    file_id: str
    source_path: str
    code: str
    message: str


@dataclass(frozen=True)
class ExtractionResult:
    """Facts and explicit non-fatal warnings from evidence ingestion."""

    facts: tuple[EvidenceFact, ...]
    warnings: tuple[ExtractionWarning, ...]


def parse_timestamp(value: Any) -> datetime | None:
    """Parse ISO or unambiguous day-month-name dates without guessing."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time())
    if not isinstance(value, str):
        return None

    candidate = value.strip()
    if not candidate:
        return None
    malformed_iso_date = re.fullmatch(
        r"(\d{4}):(\d{2})-\s*(\d{2}T.*)",
        candidate,
    )
    if malformed_iso_date is not None:
        candidate = (
            f"{malformed_iso_date.group(1)}-{malformed_iso_date.group(2)}-"
            f"{malformed_iso_date.group(3)}"
        )
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        for format_string in (
            "%d %b %Y %H:%M:%S",
            "%d %b %Y %H:%M",
            "%d %B %Y %H:%M:%S",
            "%d %B %Y %H:%M",
            "%d %b %Y",
            "%d %B %Y",
        ):
            try:
                return datetime.strptime(candidate, format_string)
            except ValueError:
                continue
        return None


_IDENTIFIER_FIELDS = {
    "account_id",
    "customer_email",
    "customer_id",
    "customer_reference",
    "email",
    "email_hash",
    "lookup_key",
    "lookup_value",
    "owner_email",
    "phone",
    "requester_email",
    "requester_phone",
    "subject_id",
    "subject_reference",
    "user_id",
}
_PERSONAL_FIELD_NAMES = {
    "address",
    "customer_email",
    "display_name",
    "email",
    "email_hash",
    "full_name",
    "given_name",
    "name",
    "owner_email",
    "owner_phone",
    "phone",
    "requester_email",
    "requester_name",
    "requester_phone",
    "surname",
}
_TIMESTAMP_FIELDS = (
    "event_time",
    "recorded_at",
    "observed_at",
    "updated_at",
    "indexed_at",
    "created_at",
    "modified_at",
    "timestamp",
    "date_observed",
)
_SYSTEM_FIELDS = (
    "system_id",
    "system",
    "source_system",
    "origin_system",
    "function",
    "service",
    "data_store",
)
_STATE_FIELDS = (
    "record_state",
    "state",
    "status",
    "account_status",
    "enabled",
    "restore_allowed",
    "last_delivery_status",
)
_CATEGORY_FIELDS = (
    "data_category",
    "category",
    "record_type",
    "collection",
    "collection_name",
)
_NULL_PLACEHOLDERS = {"null"}


def json_pointer_part(value: str) -> str:
    """Escape a path segment according to JSON Pointer."""
    return value.replace("~", "~0").replace("/", "~1")


def scalar_text(value: Any) -> str | None:
    """Return a stable textual form for JSON/SQLite scalar values."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return None


def collect_observed_fields(
    value: Any,
    path: str,
) -> tuple[ObservedField, ...]:
    """Flatten scalar values while preserving their exact structured paths."""
    fields: list[ObservedField] = []

    def visit(current: Any, current_path: str) -> None:
        if isinstance(current, dict):
            for key, child in current.items():
                child_path = f"{current_path}/{json_pointer_part(str(key))}"
                visit(child, child_path)
            return
        if isinstance(current, (list, tuple)):
            for index, child in enumerate(current):
                visit(child, f"{current_path}/{index}")
            return

        text = scalar_text(current)
        if text is None:
            return
        name = current_path.rsplit("/", 1)[-1] if "/" in current_path else current_path
        fields.append(ObservedField(current_path, name, text))

    visit(value, path)
    return tuple(fields)


def collect_direct_fields(
    value: dict[str, Any],
    path: str,
) -> tuple[ObservedField, ...]:
    """Collect only this object's scalar fields, not nested child records."""
    direct_values = {
        key: child
        for key, child in value.items()
        if not isinstance(child, (dict, list, tuple))
    }
    return collect_observed_fields(direct_values, path)


def build_fact(
    *,
    file_id: str,
    source_path: str,
    source_location: str,
    extraction_method: str,
    fields: tuple[ObservedField, ...],
    captured_at: datetime | None,
    inherited_timestamp: datetime | None = None,
    confidence: float | None = None,
) -> EvidenceFact | None:
    """Normalize a source record if it contains useful, explicitly observed data."""
    if not fields:
        return None

    field_values: dict[str, list[str]] = {}
    for field in fields:
        field_values.setdefault(field.name.lower(), []).append(field.value)

    def first_value(names: tuple[str, ...]) -> str | None:
        for name in names:
            for value in field_values.get(name, ()):
                if value.strip().casefold() not in _NULL_PLACEHOLDERS:
                    return value
        return None

    identifiers = tuple(
        sorted(
            {
                IdentifierCandidate(field.name, field.value)
                for field in fields
                if field.name.lower() in _IDENTIFIER_FIELDS
                and field.value.strip().casefold() not in _NULL_PLACEHOLDERS
            }
        )
    )
    personal_fields = tuple(
        sorted(
            {
                field.name
                for field in fields
                if field.name.lower() in _PERSONAL_FIELD_NAMES
                and field.value.strip().casefold() not in _NULL_PLACEHOLDERS
            },
            key=str.lower,
        )
    )
    categories = tuple(
        sorted(
            {
                field.value
                for field in fields
                if field.name.lower() in _CATEGORY_FIELDS
                and field.value.strip().casefold() not in _NULL_PLACEHOLDERS
            },
            key=str.lower,
        )
    )
    timestamp: datetime | None = None
    for name in _TIMESTAMP_FIELDS:
        for value in field_values.get(name, ()):
            timestamp = parse_timestamp(value)
            if timestamp is not None:
                break
        if timestamp is not None:
            break

    resource_id = first_value(("resource_id",))
    system_id = first_value(_SYSTEM_FIELDS)
    record_state = first_value(_STATE_FIELDS)
    event_timestamp = timestamp or inherited_timestamp

    return EvidenceFact(
        file_id=file_id,
        source_path=source_path,
        system_id=system_id,
        resource_id=resource_id,
        candidate_identifiers=identifiers,
        data_categories=categories,
        personal_fields=personal_fields,
        record_state=record_state,
        event_timestamp=event_timestamp,
        captured_at=captured_at,
        source_location=source_location,
        extraction_method=extraction_method,
        confidence=confidence,
        observed_fields=fields,
    )
