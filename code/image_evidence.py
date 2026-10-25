"""Image validation and injectable OCR extraction."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import subprocess
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Sequence

from evidence_model import (
    EvidenceFact,
    ObservedField,
    build_fact,
    collect_observed_fields,
)
from evidence_manifest import EvidenceIngestionError, ManifestEntry
from text_evidence import _line_fields


_WINDOWS_OCR_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType=WindowsRuntime]
$null = [Windows.Storage.Streams.IRandomAccessStream, Windows.Storage.Streams, ContentType=WindowsRuntime]
$null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics.Imaging, ContentType=WindowsRuntime]
$null = [Windows.Graphics.Imaging.SoftwareBitmap, Windows.Graphics.Imaging, ContentType=WindowsRuntime]
$null = [Windows.Media.Ocr.OcrEngine, Windows.Media.Ocr, ContentType=WindowsRuntime]
$null = [Windows.Media.Ocr.OcrResult, Windows.Media.Ocr, ContentType=WindowsRuntime]
function AwaitWinRt($operation, [Type]$resultType) {
    $method = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethodDefinition -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 } |
        Select-Object -First 1
    $task = $method.MakeGenericMethod($resultType).Invoke($null, @($operation))
    return $task.GetAwaiter().GetResult()
}
$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($null -eq $engine) { throw 'Windows OCR has no user-profile language engine.' }
$file = AwaitWinRt ([Windows.Storage.StorageFile]::GetFileFromPathAsync($env:GHOST_OCR_IMAGE_PATH)) ([Windows.Storage.StorageFile])
$stream = AwaitWinRt ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = AwaitWinRt ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$bitmap = AwaitWinRt ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
$result = AwaitWinRt ($engine.RecognizeAsync($bitmap)) ([Windows.Media.Ocr.OcrResult])
@($result.Lines | ForEach-Object {
    [PSCustomObject]@{
        text = $_.Text
        left = [int]$_.BoundingRect.X
        top = [int]$_.BoundingRect.Y
        right = [int]($_.BoundingRect.X + $_.BoundingRect.Width)
        bottom = [int]($_.BoundingRect.Y + $_.BoundingRect.Height)
    }
}) | ConvertTo-Json -Compress
"""


@dataclass(frozen=True)
class OCRTextBlock:
    text: str
    region: tuple[int, int, int, int] | None = None
    confidence: float | None = None


class OCRBackend(Protocol):
    """Testable interface for a local OCR engine."""

    name: str

    def recognize(self, image_path: Path) -> Sequence[OCRTextBlock]:
        """Return text blocks with optional pixel regions and confidence."""
        ...


def local_ocr_backend() -> OCRBackend | None:
    """Return an installed local OCR backend without network access."""
    if importlib.util.find_spec("pytesseract") is not None:
        try:
            import pytesseract
        except ImportError:
            pytesseract = None
        if (
            pytesseract is not None
            and pytesseract.pytesseract.tesseract_cmd
            and shutil.which(pytesseract.pytesseract.tesseract_cmd) is not None
        ):
            class TesseractBackend:
                name = "pytesseract"

                def recognize(self, image_path: Path) -> Sequence[OCRTextBlock]:
                    from PIL import Image

                    with Image.open(image_path) as image:
                        data = pytesseract.image_to_data(
                            image,
                            output_type=pytesseract.Output.DICT,
                        )
                    grouped: dict[tuple[int, int, int, int], list[int]] = defaultdict(list)
                    for index, raw_text in enumerate(data["text"]):
                        if raw_text.strip():
                            key = tuple(int(data[name][index]) for name in ("page_num", "block_num", "par_num", "line_num"))
                            grouped[key].append(index)
                    blocks: list[OCRTextBlock] = []
                    for indexes in grouped.values():
                        text = " ".join(data["text"][index].strip() for index in indexes)
                        left = min(int(data["left"][index]) for index in indexes)
                        top = min(int(data["top"][index]) for index in indexes)
                        right = max(int(data["left"][index]) + int(data["width"][index]) for index in indexes)
                        bottom = max(int(data["top"][index]) + int(data["height"][index]) for index in indexes)
                        scores = [float(data["conf"][index]) / 100.0 for index in indexes if str(data["conf"][index]).replace(".", "", 1).lstrip("-").isdigit() and float(data["conf"][index]) >= 0]
                        blocks.append(OCRTextBlock(text, (left, top, right, bottom), sum(scores) / len(scores) if scores else None))
                    return blocks

            return TesseractBackend()

    if platform.system() != "Windows" or shutil.which("powershell") is None:
        return None

    class WindowsMediaOcrBackend:
        name = "windows_media_ocr"

        def recognize(self, image_path: Path) -> Sequence[OCRTextBlock]:
            environment = os.environ.copy()
            environment["GHOST_OCR_IMAGE_PATH"] = str(image_path)
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", _WINDOWS_OCR_SCRIPT],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
                check=False,
                timeout=30,
            )
            if completed.returncode:
                raise EvidenceIngestionError(
                    f"Windows OCR failed for {image_path.name}: {completed.stderr.strip()}"
                )
            # Windows PowerShell may prefix redirected Unicode output with a
            # BOM.  It is transport framing, not evidence content.
            raw_blocks = json.loads((completed.stdout or "[]").lstrip("\ufeff \t\r\n"))
            if isinstance(raw_blocks, dict):
                raw_blocks = [raw_blocks]
            return tuple(
                OCRTextBlock(
                    str(block["text"]),
                    (
                        int(block["left"]),
                        int(block["top"]),
                        int(block["right"]),
                        int(block["bottom"]),
                    ),
                )
                for block in raw_blocks
                if str(block.get("text", "")).strip()
            )

    return WindowsMediaOcrBackend()


def validate_image(entry: ManifestEntry, content: bytes) -> tuple[int, int]:
    """Verify the image payload with Pillow and return its dimensions."""
    try:
        from io import BytesIO
        from PIL import Image

        with Image.open(BytesIO(content)) as image:
            image.verify()
        with Image.open(BytesIO(content)) as image:
            return image.size
    except ImportError as exc:
        raise EvidenceIngestionError(
            "Image verification requires the installed Pillow package"
        ) from exc
    except (OSError, ValueError, SyntaxError) as exc:
        raise EvidenceIngestionError(
            f"{entry.file_path}: invalid image data: {exc}"
        ) from exc


def extract_image(
    entry: ManifestEntry,
    content: bytes,
    *,
    ocr_backend: OCRBackend | None = None,
) -> tuple[tuple[EvidenceFact, ...], str | None]:
    """Validate an image and optionally extract OCR candidates."""
    validate_image(entry, content)
    backend = ocr_backend if ocr_backend is not None else local_ocr_backend()
    if backend is None:
        return (), "No local OCR backend is available; image content was not transcribed."

    facts: list[EvidenceFact] = []
    for block_number, block in enumerate(backend.recognize(entry.resolved_path), start=1):
        for line_number, line in enumerate(block.text.splitlines(), start=1):
            pairs = _line_fields(line, line_number)
            row = {key: value for key, value in pairs}
            fields = collect_observed_fields(row, f"ocr:{block_number}")
            fields += (
                ObservedField(
                    f"ocr:{block_number}/line:{line_number}/text",
                    "text",
                    line,
                ),
            )
            region = (
                ",".join(str(value) for value in block.region)
                if block.region is not None
                else "unknown"
            )
            fact = build_fact(
                file_id=entry.file_id,
                source_path=entry.file_path,
                source_location=f"region:{region}/block:{block_number}/line:{line_number}",
                extraction_method=f"ocr:{backend.name}",
                fields=fields,
                captured_at=entry.captured_at,
                confidence=block.confidence,
            )
            if fact is not None:
                facts.append(fact)
    return tuple(facts), None
