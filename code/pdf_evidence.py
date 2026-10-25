"""Embedded-text extraction from PDF evidence using installed local parsers."""

from __future__ import annotations

import re
from datetime import datetime
from io import BytesIO

from evidence_model import (
    EvidenceFact,
    ObservedField,
    build_fact,
    collect_observed_fields,
    parse_timestamp,
)
from evidence_manifest import EvidenceIngestionError, ManifestEntry
from text_evidence import _line_fields


_JOURNAL_EVENT_REFERENCE = re.compile(
    r"^\s*Record Event reference\s+([A-Za-z0-9_-]+)\s*$",
    re.IGNORECASE,
)
_JOURNAL_SUBJECT_REFERENCE = re.compile(
    r"^\s*Detail subject reference\s+(.+?)\s*$",
    re.IGNORECASE,
)
_JOURNAL_RETAIN_UNTIL = re.compile(
    r"^\s*retain until\s+(.+?)\s*$",
    re.IGNORECASE,
)
_JOURNAL_RECORDED_AT = re.compile(
    r"^\s*recorded\s+(.+?)\s*$",
    re.IGNORECASE,
)


class PdfParserUnavailableError(EvidenceIngestionError):
    """Raised when no supported local PDF text parser is installed."""


def _extract_pages(content: bytes) -> tuple[list[str], str]:
    try:
        import pdfplumber

        with pdfplumber.open(BytesIO(content)) as pdf:
            return ([page.extract_text() or "" for page in pdf.pages], "pdfplumber")
    except ImportError:
        pass

    try:
        from PyPDF2 import PdfReader

        reader = PdfReader(BytesIO(content))
        return ([page.extract_text() or "" for page in reader.pages], "PyPDF2")
    except ImportError as exc:
        raise PdfParserUnavailableError(
            "PDF evidence requires installed pdfplumber or PyPDF2"
        ) from exc


def _journal_timestamp(value: str) -> str | None:
    normalized = value.strip()
    match = re.fullmatch(
        r"(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})\s+(\d{1,2})\s+(\d{2})\s+UTC",
        normalized,
        re.IGNORECASE,
    )
    if match:
        try:
            parsed = datetime.strptime(
                f"{match.group(1)} {int(match.group(2)):02d}:{match.group(3)}",
                "%d %b %Y %H:%M",
            )
        except ValueError:
            try:
                parsed = datetime.strptime(
                    f"{match.group(1)} {int(match.group(2)):02d}:{match.group(3)}",
                    "%d %B %Y %H:%M",
                )
            except ValueError:
                return None
        return parsed.replace(microsecond=0).isoformat() + "Z"
    parsed = parse_timestamp(normalized)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.isoformat() + "Z"
    return parsed.isoformat()


def _security_journal_facts(
    entry: ManifestEntry,
    pages: list[str],
) -> tuple[EvidenceFact, ...]:
    if entry.origin.casefold() != "security_service" or not any(
        "compliance journal" in page.casefold() for page in pages
    ):
        return ()

    facts: list[EvidenceFact] = []
    for page_number, text in enumerate(pages, start=1):
        lines = text.splitlines()
        markers = [
            (line_number, match.group(1))
            for line_number, line in enumerate(lines)
            if (match := _JOURNAL_EVENT_REFERENCE.fullmatch(line))
        ]
        for marker_index, (line_number, resource_id) in enumerate(markers):
            end = (
                markers[marker_index + 1][0]
                if marker_index + 1 < len(markers)
                else len(lines)
            )
            section = lines[line_number + 1 : end]
            subject_reference = next(
                (
                    match.group(1)
                    for line in section
                    if (match := _JOURNAL_SUBJECT_REFERENCE.fullmatch(line))
                ),
                None,
            )
            retention_until = next(
                (
                    match.group(1)
                    for line in section
                    if (match := _JOURNAL_RETAIN_UNTIL.fullmatch(line))
                ),
                None,
            )
            if not subject_reference or not retention_until:
                continue

            fields = [
                ObservedField(
                    f"page:{page_number}/line:{line_number + 1}/resource_id",
                    "resource_id",
                    resource_id,
                ),
                ObservedField(
                    f"page:{page_number}/line:{line_number + 1}/record_type",
                    "record_type",
                    "SECURITY_AUDIT_LOG",
                ),
                ObservedField(
                    f"page:{page_number}/line:{line_number + 1}/system_id",
                    "system_id",
                    entry.origin,
                ),
                ObservedField(
                    f"page:{page_number}/line:{line_number + 1}/record_state",
                    "record_state",
                    "present",
                ),
            ]
            subject_line = next(
                index
                for index, line in enumerate(section, start=line_number + 2)
                if _JOURNAL_SUBJECT_REFERENCE.fullmatch(line)
            )
            retention_line = next(
                index
                for index, line in enumerate(section, start=line_number + 2)
                if _JOURNAL_RETAIN_UNTIL.fullmatch(line)
            )
            fields.extend(
                (
                    ObservedField(
                        f"page:{page_number}/line:{subject_line}/subject_reference",
                        "subject_reference",
                        subject_reference.strip(),
                    ),
                    ObservedField(
                        f"page:{page_number}/line:{retention_line}/retention_until",
                        "retention_until",
                        _journal_timestamp(retention_until) or retention_until.strip(),
                    ),
                )
            )
            recorded_at = next(
                (
                    (index, match.group(1))
                    for index, line in enumerate(section, start=line_number + 2)
                    if (match := _JOURNAL_RECORDED_AT.fullmatch(line))
                ),
                None,
            )
            if recorded_at is not None:
                recorded_value = _journal_timestamp(recorded_at[1])
                if recorded_value is not None:
                    fields.append(
                        ObservedField(
                            f"page:{page_number}/line:{recorded_at[0]}/event_time",
                            "event_time",
                            recorded_value,
                        )
                    )

            fact = build_fact(
                file_id=entry.file_id,
                source_path=entry.file_path,
                source_location=f"page:{page_number}/record:{resource_id}",
                extraction_method="pdf_labeled_record",
                fields=tuple(fields),
                captured_at=entry.captured_at,
            )
            if fact is not None:
                facts.append(fact)
    return tuple(fact for fact in facts if fact is not None)


def extract_pdf(entry: ManifestEntry, content: bytes) -> tuple[EvidenceFact, ...]:
    """Extract labeled text facts with page and line provenance."""
    pages, parser_name = _extract_pages(content)
    facts: list[EvidenceFact] = []
    for page_number, text in enumerate(pages, start=1):
        for line_number, line in enumerate(text.splitlines(), start=1):
            pairs = _line_fields(line, line_number)
            row = {key: value for key, value in pairs}
            location = f"page:{page_number}/line:{line_number}"
            fields = collect_observed_fields(row, location)
            fields += (
                ObservedField(
                    f"{location}/text",
                    "text",
                    line,
                ),
            )
            fact = build_fact(
                file_id=entry.file_id,
                source_path=entry.file_path,
                source_location=location,
                extraction_method=parser_name,
                fields=fields,
                captured_at=entry.captured_at,
            )
            if fact is not None:
                facts.append(fact)
    facts.extend(_security_journal_facts(entry, pages))
    return tuple(facts)
