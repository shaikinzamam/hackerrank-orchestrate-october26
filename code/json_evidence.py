"""Deterministic extraction of provenance-backed facts from JSON evidence."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from evidence_model import (
    EvidenceFact,
    ObservedField,
    build_fact,
    collect_direct_fields,
    parse_timestamp,
)
from evidence_manifest import EvidenceIngestionError, ManifestEntry


class MalformedJsonEvidenceError(EvidenceIngestionError):
    """Raised when a manifest-listed JSON evidence file cannot be parsed."""


_CONTEXT_FIELD_GROUPS = (
    {
        "system_id",
        "system",
        "source_system",
        "origin_system",
        "function",
        "service",
        "data_store",
    },
    {"resource_id"},
    {
        "data_category",
        "category",
        "record_type",
        "collection",
        "collection_name",
    },
    {
        "event_time",
        "recorded_at",
        "observed_at",
        "updated_at",
        "indexed_at",
        "created_at",
        "modified_at",
        "captured_at",
        "timestamp",
        "date_observed",
    },
    {
        "record_state",
        "state",
        "status",
        "account_status",
        "enabled",
        "restore_allowed",
        "last_delivery_status",
    },
)
_CONTEXT_FIELD_NAMES = frozenset().union(*_CONTEXT_FIELD_GROUPS)


def _records(
    value: Any,
    location: str,
    *,
    file_id: str,
    source_path: str,
    captured_at: datetime | None,
    inherited_timestamp: datetime | None,
    inherited_fields: tuple[ObservedField, ...] = (),
) -> list[EvidenceFact]:
    facts: list[EvidenceFact] = []
    if isinstance(value, dict):
        local_timestamp = inherited_timestamp
        for key in (
            "event_time",
            "recorded_at",
            "observed_at",
            "updated_at",
            "indexed_at",
            "created_at",
            "modified_at",
            "captured_at",
            "timestamp",
            "date_observed",
        ):
            parsed = parse_timestamp(value.get(key))
            if parsed is not None:
                local_timestamp = parsed
                break

        fields = collect_direct_fields(value, location)
        present_names = {field.name.casefold() for field in fields}
        present_groups = tuple(
            group for group in _CONTEXT_FIELD_GROUPS if present_names & group
        )
        fields += tuple(
            field
            for field in inherited_fields
            if field.name.casefold() not in present_names
            and not any(
                field.name.casefold() in group for group in present_groups
            )
        )
        fact = build_fact(
            file_id=file_id,
            source_path=source_path,
            source_location=location or "/",
            extraction_method="json",
            fields=fields,
            captured_at=captured_at,
            inherited_timestamp=local_timestamp,
        )
        if fact is not None:
            facts.append(fact)

        context_fields = tuple(
            field
            for field in fields
            if field.name.casefold() in _CONTEXT_FIELD_NAMES
        )
        for key, child in value.items():
            child_location = f"{location}/{_pointer_part(str(key))}"
            facts.extend(
                _records(
                    child,
                    child_location,
                    file_id=file_id,
                    source_path=source_path,
                    captured_at=captured_at,
                    inherited_timestamp=local_timestamp,
                    inherited_fields=context_fields,
                )
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            facts.extend(
                _records(
                    child,
                    f"{location}/{index}",
                    file_id=file_id,
                    source_path=source_path,
                    captured_at=captured_at,
                    inherited_timestamp=inherited_timestamp,
                    inherited_fields=inherited_fields,
                )
            )
    return facts


def _pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def extract_json(entry: ManifestEntry, content: bytes) -> tuple[EvidenceFact, ...]:
    """Parse JSON and return facts for objects containing scalar observations."""
    try:
        text = content.decode("utf-8-sig")
        document = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedJsonEvidenceError(
            f"{entry.file_path}: malformed UTF-8 JSON: {exc}"
        ) from exc

    return tuple(
        _records(
            document,
            "",
            file_id=entry.file_id,
            source_path=entry.file_path,
            captured_at=entry.captured_at,
            inherited_timestamp=None,
        )
    )
