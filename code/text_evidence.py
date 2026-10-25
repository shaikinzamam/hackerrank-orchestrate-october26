"""Labeled-field extraction from operational logs and plain-text records."""

from __future__ import annotations

import re

from evidence_model import (
    EvidenceFact,
    ObservedField,
    build_fact,
    collect_observed_fields,
)
from evidence_manifest import EvidenceIngestionError, ManifestEntry


_KEY_VALUE = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*
        (?:"(?P<quoted>(?:\\.|[^"\\])*)"|(?P<bare>[^\s,;]+))""",
    re.VERBOSE,
)
_LABELED_VALUE = re.compile(
    r"""(?P<key>user_id|customer_reference|customer_id|subject_reference|
        resource_id|email_hash|customer_email|requester_email|owner_email|
        requester_phone|owner_phone|phone|email|record_type|data_category|
        category|collection|collection_name|system_id|source_system|
        origin_system|function|service|system|account_status|
        status|state|enabled|restore_allowed|event_time|recorded_at|
        observed_at|updated_at|indexed_at|created_at|captured_at|timestamp)
        \s*:\s*(?:"(?P<quoted>(?:\\.|[^"\\])*)"|(?P<bare>[^\s,;]+))""",
    re.IGNORECASE | re.VERBOSE,
)
_SYSTEM_TAG = re.compile(r"\[([A-Za-z][A-Za-z0-9_-]*)\]")
_LEVELS = {
    "TRACE",
    "DEBUG",
    "INFO",
    "NOTICE",
    "WARNING",
    "WARN",
    "ERROR",
    "CRITICAL",
}


def _unescape(value: str) -> str:
    return value.replace(r"\"", '"').replace(r"\\", "\\")


def _line_fields(line: str, line_number: int) -> tuple[tuple[str, str], ...]:
    matches: list[tuple[str, str]] = []
    for pattern in (_KEY_VALUE, _LABELED_VALUE):
        for match in pattern.finditer(line):
            value = match.group("quoted")
            if value is None:
                value = match.group("bare") or ""
            matches.append((match.group("key"), _unescape(value)))

    if not any(
        key.lower()
        in {
            "system_id",
            "system",
            "source_system",
            "origin_system",
            "function",
            "service",
        }
        for key, _ in matches
    ):
        for tag in _SYSTEM_TAG.findall(line):
            if tag.upper() not in _LEVELS:
                matches.append(("system_id", tag))
                break

    timestamp_match = re.match(
        r"^\s*(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?"
        r"(?:Z|[+-]\d{2}:?\d{2})?)",
        line,
    )
    if timestamp_match and not any(
        key.lower() in {"event_time", "recorded_at", "observed_at", "timestamp"}
        for key, _ in matches
    ):
        matches.append(("event_time", timestamp_match.group(1)))

    return tuple(matches)


def extract_text(
    entry: ManifestEntry,
    content: bytes,
    *,
    extraction_method: str = "text_regex",
) -> tuple[EvidenceFact, ...]:
    """Extract only labeled scalar observations, retaining one-based line refs."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise EvidenceIngestionError(
            f"{entry.file_path}: text is not valid UTF-8: {exc}"
        ) from exc

    facts: list[EvidenceFact] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        pairs = _line_fields(line, line_number)
        if not pairs:
            fields = ()
        else:
            row = {key: value for key, value in pairs}
            fields = collect_observed_fields(row, f"line:{line_number}")
        fields += (
            ObservedField(
                f"line:{line_number}/text",
                "text",
                line,
            ),
        )
        fact = build_fact(
            file_id=entry.file_id,
            source_path=entry.file_path,
            source_location=f"line:{line_number}",
            extraction_method=extraction_method,
            fields=fields,
            captured_at=entry.captured_at,
        )
        if fact is not None:
            facts.append(fact)
    return tuple(facts)
