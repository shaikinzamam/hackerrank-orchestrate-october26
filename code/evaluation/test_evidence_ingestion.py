import csv
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

from evidence_ingestion import (
    EmptyEvidenceFileError,
    UnsupportedEvidenceFormatError,
    ingest_evidence,
    load_manifest,
)
from evidence_manifest import (
    InvalidEvidenceManifestError,
    MissingEvidenceFileError,
    UnlistedEvidenceFileError,
)
from evidence_model import parse_timestamp
from identity_timeline import IdentityResolver
from image_evidence import OCRTextBlock
from json_evidence import MalformedJsonEvidenceError, extract_json
from main import _is_non_resource_read_attempt, _normalize_evidence_fact
from pdf_evidence import extract_pdf
from sql_evidence import MalformedSqlEvidenceError, extract_sql


class FakeOCR:
    name = "test-ocr"

    def recognize(self, image_path: Path) -> list[OCRTextBlock]:
        return [
            OCRTextBlock(
                "resource_id=resource_test email=person@example.test",
                (10, 20, 110, 50),
                0.92,
            )
        ]


class EvidenceIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.dataset = self.root / "dataset"
        self.evidence = self.dataset / "evidence"
        self.evidence.mkdir(parents=True)
        self.manifest_path = self.dataset / "evidence_files.csv"

    def write_manifest(self, entries: list[tuple[str, str, str]]) -> None:
        with self.manifest_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle)
            writer.writerow(["file_id", "file_path", "origin", "captured_at"])
            for file_id, relative_path, captured_at in entries:
                writer.writerow([file_id, relative_path, "synthetic_source", captured_at])

    def add_file(self, relative_path: str, content: bytes) -> Path:
        path = self.dataset / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def entry(self, file_id: str, relative_path: str):
        self.write_manifest(
            [(file_id, relative_path, "2026-06-01T12:00:00Z")]
        )
        return load_manifest(self.manifest_path).entries[0]

    def test_valid_json_extracts_fact_with_json_pointer_provenance(self) -> None:
        relative_path = "evidence/records/snapshot.json"
        self.add_file(
            relative_path,
            json.dumps(
                {
                    "captured_at": "2026-06-01T12:00:00Z",
                    "records": [
                        {
                            "system": "profile_service",
                            "resource_id": "resource_test",
                            "user_id": "user_test",
                            "email": "person@example.test",
                            "data_category": "USER_PROFILE",
                            "status": "present",
                            "updated_at": "2026-05-31T09:30:00Z",
                        }
                    ],
                }
            ).encode(),
        )
        entry = self.entry("file_test", relative_path)
        facts = extract_json(entry, entry.resolved_path.read_bytes())

        record_fact = next(fact for fact in facts if fact.resource_id == "resource_test")
        self.assertEqual(record_fact.file_id, "file_test")
        self.assertEqual(record_fact.source_path, relative_path)
        self.assertEqual(record_fact.source_location, "/records/0")
        self.assertEqual(record_fact.system_id, "profile_service")
        self.assertEqual(record_fact.data_categories, ("USER_PROFILE",))
        self.assertIn("email", record_fact.personal_fields)
        self.assertEqual(record_fact.record_state, "present")
        self.assertEqual(
            record_fact.event_timestamp,
            datetime(2026, 5, 31, 9, 30, tzinfo=timezone.utc),
        )
        self.assertIn(
            ("user_id", "user_test"),
            {(item.field_name, item.value) for item in record_fact.candidate_identifiers},
        )
        self.assertIn(
            "/records/0/resource_id",
            {field.path for field in record_fact.observed_fields},
        )

    def test_null_text_placeholders_do_not_become_fact_targets_or_identifiers(self) -> None:
        relative_path = "evidence/records/null_placeholders.json"
        self.add_file(
            relative_path,
            json.dumps(
                {
                    "records": [
                        {
                            "system": "null",
                            "resource_id": "null",
                            "data_category": "SUPPORT_MESSAGE",
                            "customer_reference": "null",
                            "requester_email": "null",
                            "requester_phone": "null",
                        }
                    ]
                }
            ).encode(),
        )
        entry = self.entry("file_nulls", relative_path)
        facts = extract_json(entry, entry.resolved_path.read_bytes())
        fact = next(item for item in facts if item.source_location == "/records/0")

        self.assertIsNone(fact.system_id)
        self.assertIsNone(fact.resource_id)
        self.assertEqual(fact.data_categories, ("SUPPORT_MESSAGE",))
        self.assertEqual(fact.candidate_identifiers, ())
        self.assertEqual(fact.personal_fields, ())
        self.assertIn(
            ("requester_phone", "null"),
            {(item.name, item.value) for item in fact.observed_fields},
        )

    def test_manifest_capture_time_is_not_misreported_as_event_time(self) -> None:
        relative_path = "evidence/records/captured.json"
        self.add_file(
            relative_path,
            b'{"exported_at":"2026-06-01T11:00:00Z","records":[{"resource_id":"resource_captured",'
            b'"user_id":"user_captured"}]}',
        )
        entry = self.entry("file_capture", relative_path)
        facts = extract_json(entry, entry.resolved_path.read_bytes())
        record_fact = next(
            fact for fact in facts if fact.resource_id == "resource_captured"
        )
        self.assertIsNone(record_fact.event_timestamp)
        self.assertEqual(
            record_fact.captured_at,
            datetime(2026, 6, 1, 12, 0, tzinfo=timezone.utc),
        )

    def test_nested_json_snapshot_inherits_system_category_and_capture_time(self) -> None:
        relative_path = "evidence/records/snapshot_bundle.json"
        self.add_file(
            relative_path,
            json.dumps(
                {
                    "snapshots": [
                        {
                            "captured_at": "2026-06-01T11:00:00Z",
                            "data_store": "analytics_platform",
                            "collection": "customer_analytics_reports",
                            "records": [
                                {
                                    "resource_id": "analytics_nested",
                                    "user_id": "user_nested",
                                    "email": "person@example.test",
                                }
                            ],
                        }
                    ]
                }
            ).encode(),
        )
        entry = self.entry("file_snapshot_bundle", relative_path)
        facts = extract_json(entry, entry.resolved_path.read_bytes())
        record = next(
            fact for fact in facts if fact.resource_id == "analytics_nested"
        )

        normalized = _normalize_evidence_fact(record)

        self.assertEqual(normalized.system_id, "analytics_platform")
        self.assertEqual(normalized.data_categories, ("ANALYTICS_PROFILE",))
        self.assertEqual(
            normalized.event_timestamp,
            datetime(2026, 6, 1, 11, 0, tzinfo=timezone.utc),
        )
        self.assertEqual(
            {(item.field_name, item.value) for item in record.candidate_identifiers},
            {("user_id", "user_nested"), ("email", "person@example.test")},
        )

    def test_nested_search_document_inherits_its_explicit_resource_id(self) -> None:
        relative_path = "evidence/records/search_snapshot.json"
        self.add_file(
            relative_path,
            json.dumps(
                {
                    "snapshots": [
                        {
                            "data_store": "search_service",
                            "collection": "customer_search_documents",
                            "records": [
                                {
                                    "resource_id": "search_entry_1",
                                    "document": {
                                        "customer_reference": "user_nested",
                                        "email": "person@example.test",
                                    },
                                }
                            ],
                        }
                    ]
                }
            ).encode(),
        )
        entry = self.entry("file_search_snapshot", relative_path)
        facts = extract_json(entry, entry.resolved_path.read_bytes())
        document = next(
            fact
            for fact in facts
            if fact.source_location.endswith("/document")
        )

        self.assertEqual(document.resource_id, "search_entry_1")
        self.assertEqual(document.system_id, "search_service")
        self.assertEqual(document.data_categories, ("customer_search_documents",))
        self.assertEqual(
            {(item.field_name, item.value) for item in document.candidate_identifiers},
            {
                ("customer_reference", "user_nested"),
                ("email", "person@example.test"),
            },
        )

    def test_malformed_json_is_reported(self) -> None:
        relative_path = "evidence/records/broken.json"
        self.add_file(relative_path, b'{"records": [}')
        entry = self.entry("file_test", relative_path)
        with self.assertRaises(MalformedJsonEvidenceError):
            extract_json(entry, entry.resolved_path.read_bytes())

    def test_sql_extraction_uses_discovered_schema_and_row_location(self) -> None:
        relative_path = "evidence/databases/snapshot.sql"
        sql = b"""
        CREATE TABLE custom_snapshot (
            source_system TEXT,
            resource_id TEXT,
            customer_reference TEXT,
            email TEXT,
            updated_at TEXT,
            record_json TEXT
        );
        INSERT INTO custom_snapshot VALUES (
            'analytics_service',
            'resource_sql',
            'user_sql',
            'person@example.test',
            '2026-05-30T08:45:00Z',
            '{"record_type":"ANALYTICS_PROFILE","phone":"+10000000000"}'
        );
        """
        self.add_file(relative_path, sql)
        entry = self.entry("file_sql", relative_path)
        facts = extract_sql(entry, entry.resolved_path.read_bytes())
        row_fact = next(fact for fact in facts if fact.resource_id == "resource_sql")

        self.assertEqual(row_fact.source_location, "table:custom_snapshot/row:1")
        self.assertEqual(row_fact.system_id, "analytics_service")
        self.assertEqual(row_fact.event_timestamp.isoformat(), "2026-05-30T08:45:00+00:00")
        self.assertIn("email", row_fact.personal_fields)
        self.assertTrue(any(fact.source_location.endswith("/record_json") for fact in facts))

    def test_sql_json_payload_inherits_parent_record_provenance(self) -> None:
        relative_path = "evidence/databases/inventory.sql"
        sql = b"""
        CREATE TABLE customer_data_primary (
            resource_id TEXT,
            system_id TEXT,
            record_type TEXT,
            record_json TEXT,
            event_time TEXT
        );
        INSERT INTO customer_data_primary VALUES (
            'analytics_sql',
            'analytics_platform',
            'customer_analytics_reports',
            '{"user_id":"user_sql","email":"person@example.test","still_attributable":true}',
            '2026-05-30T08:45:00Z'
        );
        CREATE TABLE customer_profiles (
            resource_id TEXT,
            system_id TEXT,
            email TEXT,
            updated_at TEXT
        );
        INSERT INTO customer_profiles VALUES (
            'profile_sql',
            'profile_service',
            'person@example.test',
            '2026-05-30T08:45:00Z'
        );
        CREATE TABLE security_audit_records (
            resource_id TEXT,
            subject_reference TEXT,
            event_code TEXT,
            retention_until TEXT,
            updated_at TEXT
        );
        INSERT INTO security_audit_records VALUES (
            'audit_sql',
            'user_sql',
            'ACCOUNT_DELETION_RECORDED',
            '2031:12- 31T23:59:59Z',
            '2026-05-30T08:45:00Z'
        );
        CREATE TABLE customer_profiles_failover_replica (
            resource_id TEXT,
            user_id TEXT,
            email TEXT
        );
        INSERT INTO customer_profiles_failover_replica VALUES (
            'profile_failover_sql',
            'user_sql',
            'person@example.test'
        );
        CREATE TABLE customer_analytics_profiles (
            resource_id TEXT,
            email TEXT
        );
        INSERT INTO customer_analytics_profiles VALUES (
            'analytics_profile_sql',
            'person@example.test'
        );
        CREATE TABLE backup_restore_entries (
            resource_id TEXT,
            email TEXT
        );
        INSERT INTO backup_restore_entries VALUES (
            'backup_sql',
            'person@example.test'
        );
        CREATE TABLE customer_exports (
            resource_id TEXT,
            email TEXT
        );
        INSERT INTO customer_exports VALUES (
            'export_sql',
            'person@example.test'
        );
        CREATE TABLE support_records (
            resource_id TEXT,
            email TEXT,
            message TEXT
        );
        INSERT INTO support_records VALUES (
            'support_sql',
            'person@example.test',
            'Customer contacted support'
        );
        CREATE TABLE search_documents_primary (
            resource_id TEXT,
            email TEXT
        );
        INSERT INTO search_documents_primary VALUES (
            'search_sql',
            'person@example.test'
        );
        CREATE TABLE connector_subscriptions (
            resource_id TEXT,
            customer_email TEXT,
            connector_name TEXT,
            enabled INTEGER,
            last_delivery_status TEXT
        );
        INSERT INTO connector_subscriptions VALUES (
            'flow_sql',
            'person@example.test',
            'profile_connector',
            1,
            'delivered'
        );
        """
        self.add_file(relative_path, sql)
        entry = self.entry("file_sql_context", relative_path)
        facts = extract_sql(entry, entry.resolved_path.read_bytes())

        payload = next(
            fact
            for fact in facts
            if fact.source_location.endswith("/record_json")
        )
        normalized_payload = _normalize_evidence_fact(payload)
        self.assertEqual(normalized_payload.data_categories, ("ANALYTICS_PROFILE",))
        self.assertEqual(normalized_payload.system_id, "analytics_platform")
        self.assertEqual(normalized_payload.resource_id, "analytics_sql")
        self.assertEqual(
            {(item.field_name, item.value) for item in payload.candidate_identifiers},
            {("user_id", "user_sql"), ("email", "person@example.test")},
        )
        parent_row = next(
            fact
            for fact in facts
            if fact.source_location == "table:customer_data_primary/row:1"
        )
        self.assertEqual(
            _normalize_evidence_fact(
                parent_row,
                policy_categories={"ANALYTICS_PROFILE"},
            ).data_categories,
            ("ANALYTICS_PROFILE",),
        )

        profile = next(fact for fact in facts if fact.resource_id == "profile_sql")
        self.assertEqual(
            _normalize_evidence_fact(profile).data_categories,
            ("USER_PROFILE",),
        )

        security_record = next(
            fact for fact in facts if fact.resource_id == "audit_sql"
        )
        normalized_security_record = _normalize_evidence_fact(security_record)
        self.assertEqual(
            normalized_security_record.data_categories,
            ("SECURITY_AUDIT_LOG",),
        )
        self.assertEqual(
            parse_timestamp(
                next(
                    field.value
                    for field in security_record.observed_fields
                    if field.name == "retention_until"
                )
            ),
            datetime(2031, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        )
        expected_categories = {
            "profile_failover_sql": "USER_PROFILE",
            "analytics_profile_sql": "ANALYTICS_PROFILE",
            "backup_sql": "BACKUP_ARCHIVE",
            "export_sql": "USER_EXPORT",
            "support_sql": "SUPPORT_MESSAGE",
            "search_sql": "SEARCH_INDEX_ENTRY",
            "flow_sql": "DATA_FLOW",
        }
        for resource_id, expected_category in expected_categories.items():
            with self.subTest(resource_id=resource_id):
                fact = next(item for item in facts if item.resource_id == resource_id)
                self.assertEqual(
                    _normalize_evidence_fact(fact).data_categories,
                    (expected_category,),
                )
        flow = next(item for item in facts if item.resource_id == "flow_sql")
        normalized_flow = _normalize_evidence_fact(flow)
        flow_fields = {field.name.casefold() for field in normalized_flow.observed_fields}
        self.assertNotIn("mode", flow_fields)
        self.assertNotIn("destination", flow_fields)

    def test_service_export_paths_preserve_categories_and_system_targets(self) -> None:
        relative_path = "evidence/records/service_resource_export_fixture.json"
        payload = {
            "service_exports": {
                "analytics_platform": {
                    "profiles": [
                        {
                            "email": "person@example.test",
                            "resource_id": "analytics_fixture",
                        }
                    ]
                },
                "account_service": {
                    "profile_lookups": [
                        {
                            "observed_at": "2026-05-30T08:45:00Z",
                            "profile": None,
                            "resource_id": "account_missing",
                            "status_code": 404,
                        }
                    ]
                },
                "security_service": {
                    "audit_records": [
                        {
                            "event_code": "SUBJECT_REQUEST_AUDITED",
                            "resource_id": "audit_fixture",
                            "retention_until": "2033-12-31T23:59:59Z",
                            "subject_reference": "user_sql",
                        }
                    ]
                },
                "integration_service": {
                    "connectors": [
                        {
                            "enabled": True,
                            "resource_id": "flow_fixture",
                        }
                    ]
                },
                "search_service": {
                    "index_queries": [
                        {
                            "hits": {
                                "documents": [
                                    {
                                        "email": "person@example.test",
                                        "resource_id": "search_fixture",
                                    }
                                ],
                                "total": 1,
                            },
                            "query": "person@example.test",
                            "resource_id": "search_fixture",
                        }
                    ]
                },
            }
        }
        self.add_file(relative_path, json.dumps(payload).encode())
        entry = self.entry("file_service_export", relative_path)
        facts = extract_json(entry, entry.resolved_path.read_bytes())

        expected = {
            "analytics_fixture": ("ANALYTICS_PROFILE", "analytics_platform"),
            "account_missing": ("USER_PROFILE", "account_service"),
            "audit_fixture": ("SECURITY_AUDIT_LOG", "security_service"),
            "flow_fixture": ("DATA_FLOW", "integration_service"),
            "search_fixture": ("SEARCH_INDEX_ENTRY", "search_service"),
        }
        for resource_id, (category, system_id) in expected.items():
            with self.subTest(resource_id=resource_id):
                fact = next(
                    item
                    for item in facts
                    if item.resource_id == resource_id
                    and (
                        resource_id != "search_fixture"
                        or "/hits/documents/" in item.source_location
                    )
                )
                normalized = _normalize_evidence_fact(fact)
                self.assertEqual(normalized.data_categories, (category,))
                self.assertEqual(normalized.system_id, system_id)

        missing_profile = next(
            fact for fact in facts if fact.resource_id == "account_missing"
        )
        self.assertEqual(
            _normalize_evidence_fact(missing_profile).record_state,
            "ABSENT",
        )
        search_query = next(
            fact
            for fact in facts
            if fact.source_location == "/service_exports/search_service/index_queries/0"
        )
        self.assertTrue(_is_non_resource_read_attempt(search_query))

    def test_customer_export_job_collection_identifies_user_exports(self) -> None:
        relative_path = "evidence/records/customer_export_jobs_fixture.json"
        self.add_file(
            relative_path,
            b'{"records":[{"resource_id":"export_fixture",'
            b'"owner_email":"person@example.test","created_at":"2026-05-30T08:45:00Z"}]}',
        )
        entry = self.entry("file_export_job", relative_path)
        fact = next(
            item
            for item in extract_json(entry, entry.resolved_path.read_bytes())
            if item.resource_id == "export_fixture"
        )
        self.assertEqual(
            _normalize_evidence_fact(fact).data_categories,
            ("USER_EXPORT",),
        )

    def test_security_journal_pdf_extracts_subject_and_retention_record(self) -> None:
        relative_path = "evidence/documents/security_journal.pdf"
        self.add_file(relative_path, b"placeholder")
        entry = replace(
            self.entry("file_security_journal", relative_path),
            origin="security_service",
        )
        pages = [
            "\n".join(
                (
                    "COMPLIANCE JOURNAL - SIGNED RECORD EXTRACT",
                    "Journal entry",
                    "Record Event reference audit_record_003",
                    "Detail subject reference user_03",
                    "recorded 25 Aug 2026 04 03 UTC",
                    "retain until 25 Aug 2027 04 03 UTC",
                )
            )
        ]
        with patch("pdf_evidence._extract_pages", return_value=(pages, "fixture")):
            facts = extract_pdf(entry, b"placeholder")

        record = next(
            fact for fact in facts if fact.extraction_method == "pdf_labeled_record"
        )
        self.assertEqual(record.system_id, "security_service")
        self.assertEqual(record.resource_id, "audit_record_003")
        self.assertEqual(record.data_categories, ("SECURITY_AUDIT_LOG",))
        self.assertEqual(
            record.event_timestamp,
            datetime(2026, 8, 25, 4, 3, tzinfo=timezone.utc),
        )
        fields = {field.name: field.value for field in record.observed_fields}
        self.assertEqual(fields["retention_until"], "2027-08-25T04:03:00Z")
        resolution = IdentityResolver(
            [
                {
                    "user_id": "user_03",
                    "email": "person@example.test",
                    "updated_at": "2026-01-01T00:00:00Z",
                }
            ]
        ).resolve_fact(record, as_of="2026-10-01T00:00:00Z")
        self.assertEqual(resolution.user_id, "user_03")

    def test_malformed_sql_is_reported(self) -> None:
        relative_path = "evidence/databases/broken.sql"
        self.add_file(relative_path, b"CREATE TABLE broken (")
        entry = self.entry("file_sql", relative_path)
        with self.assertRaises(MalformedSqlEvidenceError):
            extract_sql(entry, entry.resolved_path.read_bytes())

    def test_timestamp_parser_handles_iso_and_invalid_values(self) -> None:
        parsed = parse_timestamp("2026-06-01T12:34:56Z")
        self.assertEqual(parsed, datetime(2026, 6, 1, 12, 34, 56, tzinfo=timezone.utc))
        self.assertEqual(
            parse_timestamp("2031:12- 31T23:59:59Z"),
            datetime(2031, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        )
        self.assertEqual(parse_timestamp("2026-06-01"), datetime(2026, 6, 1))
        self.assertEqual(parse_timestamp("08 Jul 2026"), datetime(2026, 7, 8))
        self.assertIsNone(parse_timestamp("not a timestamp"))
        self.assertIsNone(parse_timestamp(None))

    def test_missing_manifest_file_is_reported(self) -> None:
        self.write_manifest(
            [("file_missing", "evidence/logs/missing.log", "2026-06-01T12:00:00Z")]
        )
        with self.assertRaises(MissingEvidenceFileError):
            load_manifest(self.manifest_path)

    def test_invalid_manifest_capture_time_is_reported(self) -> None:
        relative_path = "evidence/logs/events.log"
        self.add_file(relative_path, b"resource_id=resource_test")
        self.write_manifest([( "file_time", relative_path, "not a timestamp")])
        with self.assertRaisesRegex(InvalidEvidenceManifestError, "captured_at"):
            load_manifest(self.manifest_path)

    def test_unlisted_evidence_file_is_reported(self) -> None:
        self.add_file("evidence/logs/unlisted.log", b"resource_id=resource_test")
        self.write_manifest([])
        with self.assertRaises(UnlistedEvidenceFileError):
            load_manifest(self.manifest_path)

    def test_empty_file_is_reported(self) -> None:
        relative_path = "evidence/logs/empty.log"
        self.add_file(relative_path, b"")
        self.write_manifest(
            [("file_empty", relative_path, "2026-06-01T12:00:00Z")]
        )
        with self.assertRaises(EmptyEvidenceFileError):
            ingest_evidence(self.manifest_path)

    def test_unsupported_format_is_reported(self) -> None:
        relative_path = "evidence/records/opaque.bin"
        self.add_file(relative_path, b"opaque")
        self.write_manifest(
            [("file_opaque", relative_path, "2026-06-01T12:00:00Z")]
        )
        with self.assertRaises(UnsupportedEvidenceFormatError):
            ingest_evidence(self.manifest_path)

    def test_manifest_reference_and_text_line_provenance_are_preserved(self) -> None:
        relative_path = "evidence/logs/events.log"
        self.add_file(
            relative_path,
            b'2026-06-01T10:15:00Z [INFO] [account_service] '
            b'resource_id="resource_log" user_id="user_log" '
            b'email="person@example.test" status="present"\n',
        )
        self.write_manifest(
            [("file_log", relative_path, "2026-06-01T12:00:00Z")]
        )
        result = ingest_evidence(self.manifest_path)
        fact = next(fact for fact in result.facts if fact.resource_id == "resource_log")

        self.assertEqual(fact.file_id, "file_log")
        self.assertEqual(fact.source_location, "line:1")
        self.assertEqual(fact.system_id, "account_service")
        self.assertEqual(fact.extraction_method, "log_regex")
        self.assertEqual(fact.event_timestamp.isoformat(), "2026-06-01T10:15:00+00:00")

    def test_image_ocr_interface_preserves_region_and_confidence(self) -> None:
        relative_path = "evidence/images/screen.png"
        try:
            from io import BytesIO
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow is not installed")
        buffer = BytesIO()
        Image.new("RGB", (4, 4), color="white").save(buffer, format="PNG")
        image_path = self.add_file(relative_path, buffer.getvalue())
        entry = self.entry("file_image", relative_path)

        result = ingest_evidence(self.manifest_path, ocr_backend=FakeOCR())
        fact = next(item for item in result.facts if item.file_id == "file_image")
        self.assertEqual(fact.resource_id, "resource_test")
        self.assertIn("region:10,20,110,50", fact.source_location)
        self.assertEqual(fact.confidence, 0.92)
        self.assertEqual(image_path, entry.resolved_path)

    def test_repeated_ingestion_produces_stable_facts(self) -> None:
        relative_path = "evidence/records/stable.json"
        self.add_file(
            relative_path,
            b'{"records":[{"resource_id":"resource_stable",'
            b'"user_id":"user_stable","email":"person@example.test"}]}',
        )
        self.write_manifest(
            [("file_stable", relative_path, "2026-06-01T12:00:00Z")]
        )
        first = ingest_evidence(self.manifest_path)
        second = ingest_evidence(self.manifest_path)
        self.assertEqual(
            [fact.to_dict() for fact in first.facts],
            [fact.to_dict() for fact in second.facts],
        )
        self.assertEqual(first.warnings, second.warnings)

    def test_repeated_sql_extraction_produces_stable_facts(self) -> None:
        relative_path = "evidence/databases/stable.sql"
        self.add_file(
            relative_path,
            b"CREATE TABLE records (resource_id TEXT, user_id TEXT);"
            b"INSERT INTO records VALUES ('resource_1', 'user_1');"
            b"INSERT INTO records VALUES ('resource_2', 'user_2');",
        )
        entry = self.entry("file_sql", relative_path)
        content = entry.resolved_path.read_bytes()
        self.assertEqual(extract_sql(entry, content), extract_sql(entry, content))


if __name__ == "__main__":
    unittest.main()
