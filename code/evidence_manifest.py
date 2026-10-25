"""Manifest-backed evidence file discovery and path validation."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath

from evidence_model import parse_timestamp


class EvidenceIngestionError(ValueError):
    """Base class for manifest and evidence ingestion failures."""


class InvalidEvidenceManifestError(EvidenceIngestionError):
    """Raised when a manifest is malformed or does not match disk contents."""


class MissingEvidenceFileError(EvidenceIngestionError):
    """Raised when a manifest-listed evidence file is missing."""


class UnlistedEvidenceFileError(EvidenceIngestionError):
    """Raised when an evidence file is not registered in the manifest."""


class EmptyEvidenceFileError(EvidenceIngestionError):
    """Raised when a manifest-listed evidence file has no bytes."""


class UnsupportedEvidenceFormatError(EvidenceIngestionError):
    """Raised when the evidence file extension has no registered parser."""


@dataclass(frozen=True)
class ManifestEntry:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime | None
    resolved_path: Path


@dataclass(frozen=True)
class EvidenceManifest:
    dataset_root: Path
    entries: tuple[ManifestEntry, ...]

    def by_id(self) -> dict[str, ManifestEntry]:
        return {entry.file_id: entry for entry in self.entries}


def load_manifest(manifest_path: str | Path) -> EvidenceManifest:
    """Load and validate all manifest paths against dataset/evidence on disk."""
    manifest_path = Path(manifest_path).resolve()
    dataset_root = manifest_path.parent
    evidence_root = (dataset_root / "evidence").resolve()
    if not evidence_root.is_dir():
        raise InvalidEvidenceManifestError(
            f"Evidence directory does not exist: {evidence_root}"
        )

    entries: list[ManifestEntry] = []
    ids: set[str] = set()
    paths: set[str] = set()
    try:
        with manifest_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames != [
                "file_id",
                "file_path",
                "origin",
                "captured_at",
            ]:
                raise InvalidEvidenceManifestError(
                    f"{manifest_path}: expected columns "
                    "file_id,file_path,origin,captured_at"
                )
            for line_no, row in enumerate(reader, start=2):
                file_id = (row.get("file_id") or "").strip()
                raw_path = (row.get("file_path") or "").strip()
                origin = (row.get("origin") or "").strip()
                if not file_id or not raw_path or not origin:
                    raise InvalidEvidenceManifestError(
                        f"{manifest_path}: empty required value on line {line_no}"
                    )
                if file_id in ids:
                    raise InvalidEvidenceManifestError(
                        f"{manifest_path}: duplicate file_id {file_id!r}"
                    )

                normalized_path = raw_path.replace("\\", "/")
                relative_path = PurePosixPath(normalized_path)
                if relative_path.is_absolute() or ".." in relative_path.parts:
                    raise InvalidEvidenceManifestError(
                        f"{manifest_path}: unsafe evidence path {raw_path!r}"
                    )
                if not relative_path.parts or relative_path.parts[0] != "evidence":
                    raise InvalidEvidenceManifestError(
                        f"{manifest_path}: evidence path must start with 'evidence/': "
                        f"{raw_path!r}"
                    )
                if normalized_path in paths:
                    raise InvalidEvidenceManifestError(
                        f"{manifest_path}: duplicate file_path {raw_path!r}"
                    )

                resolved_path = (dataset_root / Path(*relative_path.parts)).resolve()
                try:
                    resolved_path.relative_to(evidence_root)
                except ValueError as exc:
                    raise InvalidEvidenceManifestError(
                        f"{manifest_path}: path escapes evidence directory: "
                        f"{raw_path!r}"
                    ) from exc
                if not resolved_path.is_file():
                    raise MissingEvidenceFileError(
                        f"{manifest_path}: listed evidence file does not exist: "
                        f"{raw_path!r}"
                    )

                captured_at_value = row.get("captured_at") or ""
                captured_at = parse_timestamp(captured_at_value)
                if not captured_at:
                    raise InvalidEvidenceManifestError(
                        f"{manifest_path}: invalid captured_at on line {line_no}"
                    )
                ids.add(file_id)
                paths.add(normalized_path)
                entries.append(
                    ManifestEntry(
                        file_id=file_id,
                        file_path=normalized_path,
                        origin=origin,
                        captured_at=captured_at,
                        resolved_path=resolved_path,
                    )
                )
    except OSError as exc:
        raise InvalidEvidenceManifestError(
            f"Cannot read evidence manifest {manifest_path}: {exc}"
        ) from exc

    listed_paths = {entry.resolved_path for entry in entries}
    actual_paths = {
        path.resolve()
        for path in evidence_root.rglob("*")
        if path.is_file()
    }
    unlisted_paths = sorted(actual_paths - listed_paths)
    if unlisted_paths:
        first = unlisted_paths[0]
        raise UnlistedEvidenceFileError(
            f"Evidence file is absent from manifest: "
            f"{first.relative_to(dataset_root).as_posix()}"
        )

    return EvidenceManifest(dataset_root, tuple(entries))
