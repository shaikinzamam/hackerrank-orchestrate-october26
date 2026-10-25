"""Schema-driven extraction from SQLite-compatible SQL snapshot exports."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from evidence_model import EvidenceFact, build_fact, collect_direct_fields
from evidence_manifest import EvidenceIngestionError, ManifestEntry
from json_evidence import _records


class MalformedSqlEvidenceError(EvidenceIngestionError):
    """Raised when a SQL snapshot cannot be loaded by SQLite."""


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _row_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped or stripped[0] not in "[{":
        return value
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return value
    return parsed


def extract_sql(entry: ManifestEntry, content: bytes) -> tuple[EvidenceFact, ...]:
    """Execute the participant-provided SQL dump in memory and inspect tables."""
    try:
        script = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise MalformedSqlEvidenceError(
            f"{entry.file_path}: SQL dump is not valid UTF-8: {exc}"
        ) from exc

    facts: list[EvidenceFact] = []
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(script)
        table_names = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                "ORDER BY name"
            )
        ]
        for table_name in table_names:
            schema = connection.execute(
                f"PRAGMA table_info({_quote_identifier(table_name)})"
            ).fetchall()
            columns = [row[1] for row in schema]
            if not columns:
                continue
            selected_columns = ", ".join(
                _quote_identifier(column) for column in columns
            )
            base_query = (
                f"SELECT {selected_columns} "
                f"FROM {_quote_identifier(table_name)}"
            )
            try:
                cursor = connection.execute(f"{base_query} ORDER BY rowid")
            except sqlite3.OperationalError:
                primary_key_columns = [
                    row[1]
                    for row in sorted(schema, key=lambda item: item[5])
                    if row[5]
                ]
                order_columns = primary_key_columns or columns
                order_by = ", ".join(
                    _quote_identifier(column) for column in order_columns
                )
                cursor = connection.execute(f"{base_query} ORDER BY {order_by}")
            for ordinal, row in enumerate(cursor, start=1):
                record = {
                    column: _row_value(value)
                    for column, value in zip(columns, row)
                }
                location = f"table:{table_name}/row:{ordinal}"
                fields = collect_direct_fields(record, location)
                fact = build_fact(
                    file_id=entry.file_id,
                    source_path=entry.file_path,
                    source_location=location,
                    extraction_method="sqlite3",
                    fields=fields,
                    captured_at=entry.captured_at,
                )
                if fact is not None:
                    facts.append(fact)

                for column, value in record.items():
                    if isinstance(value, (dict, list)):
                        nested = _records(
                            value,
                            f"{location}/{column}",
                            file_id=entry.file_id,
                            source_path=entry.file_path,
                            captured_at=entry.captured_at,
                            inherited_timestamp=None,
                            inherited_fields=fields,
                        )
                        facts.extend(nested)
    except sqlite3.Error as exc:
        raise MalformedSqlEvidenceError(
            f"{entry.file_path}: cannot inspect SQL snapshot: {exc}"
        ) from exc
    finally:
        connection.close()

    return tuple(facts)
