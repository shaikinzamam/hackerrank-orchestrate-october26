"""Manifest-backed dispatch for structured and unstructured evidence files."""

from __future__ import annotations

from pathlib import Path

from evidence_manifest import (
    EmptyEvidenceFileError,
    EvidenceIngestionError,
    EvidenceManifest,
    ManifestEntry,
    UnsupportedEvidenceFormatError,
    load_manifest,
)
from evidence_model import EvidenceFact, ExtractionResult, ExtractionWarning
from image_evidence import OCRBackend, extract_image
from json_evidence import extract_json
from pdf_evidence import extract_pdf
from sql_evidence import extract_sql
from text_evidence import extract_text


_IMAGE_SUFFIXES = {".bmp", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
_SUPPORTED_SUFFIXES = {".json", ".log", ".pdf", ".sql", ".txt"} | _IMAGE_SUFFIXES


def _extract_entry(
    entry: ManifestEntry,
    *,
    ocr_backend: OCRBackend | None,
) -> tuple[tuple[EvidenceFact, ...], tuple[ExtractionWarning, ...]]:
    try:
        content = entry.resolved_path.read_bytes()
    except OSError as exc:
        raise EvidenceIngestionError(
            f"{entry.file_path}: cannot read evidence file: {exc}"
        ) from exc
    if not content:
        raise EmptyEvidenceFileError(f"{entry.file_path}: evidence file is empty")

    suffix = entry.resolved_path.suffix.lower()
    if suffix not in _SUPPORTED_SUFFIXES:
        raise UnsupportedEvidenceFormatError(
            f"{entry.file_path}: unsupported evidence format {suffix or '<none>'!r}"
        )

    warnings: list[ExtractionWarning] = []
    if suffix == ".json":
        facts = extract_json(entry, content)
    elif suffix == ".sql":
        facts = extract_sql(entry, content)
    elif suffix in {".log", ".txt"}:
        facts = extract_text(
            entry,
            content,
            extraction_method="log_regex" if suffix == ".log" else "text_regex",
        )
    elif suffix == ".pdf":
        facts = extract_pdf(entry, content)
    else:
        facts, limitation = extract_image(
            entry,
            content,
            ocr_backend=ocr_backend,
        )
        if limitation:
            warnings.append(
                ExtractionWarning(
                    entry.file_id,
                    entry.file_path,
                    "OCR_UNAVAILABLE",
                    limitation,
                )
            )

    if not facts and not warnings:
        warnings.append(
            ExtractionWarning(
                entry.file_id,
                entry.file_path,
                "NO_STRUCTURED_FACTS",
                "No labeled or structured scalar facts were extracted.",
            )
        )
    return tuple(facts), tuple(warnings)


def ingest_evidence(
    manifest_path: str | Path,
    *,
    ocr_backend: OCRBackend | None = None,
) -> ExtractionResult:
    """Extract deterministic facts from every manifest-listed evidence file.

    This function does not resolve candidate identifiers, infer deletion state,
    or apply ``audit_at`` cutoffs. Those remain responsibilities of later stages.
    """
    manifest: EvidenceManifest = load_manifest(manifest_path)
    facts: list[EvidenceFact] = []
    warnings: list[ExtractionWarning] = []
    for entry in manifest.entries:
        result = ingest_manifest_entry(entry, ocr_backend=ocr_backend)
        facts.extend(result.facts)
        warnings.extend(result.warnings)
    return ExtractionResult(tuple(facts), tuple(warnings))


def ingest_manifest_entry(
    entry: ManifestEntry,
    *,
    ocr_backend: OCRBackend | None = None,
) -> ExtractionResult:
    """Extract one manifest entry so callers can isolate per-file failures."""
    facts, warnings = _extract_entry(entry, ocr_backend=ocr_backend)
    return ExtractionResult(facts, warnings)


__all__ = [
    "EmptyEvidenceFileError",
    "EvidenceIngestionError",
    "ExtractionResult",
    "ExtractionWarning",
    "UnsupportedEvidenceFormatError",
    "ingest_evidence",
    "ingest_manifest_entry",
    "load_manifest",
]
