import csv
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

from evidence_model import build_fact, collect_direct_fields, parse_timestamp
from identity_timeline import (
    IdentityResolver,
    load_activity_events,
    load_identity_resolver,
    normalize_identifier,
    reconstruct_timeline,
)


def snapshot(
    user_id: str,
    email: str,
    *,
    phone: str = "+1 202 555 0100",
    email_hash: str = "hash-old",
    updated_at: str = "2026-03-01T00:00:00Z",
) -> dict[str, str]:
    return {
        "user_id": user_id,
        "name": "Names are not identifiers",
        "email": email,
        "phone": phone,
        "email_hash": email_hash,
        "updated_at": updated_at,
    }


def audit(
    audit_id: str,
    user_id: str,
    event_time: str,
    field_name: str,
    old_value: str,
    new_value: str,
    *,
    source_file: str = "synthetic_audit.csv",
    source_location: str = "row:2",
) -> dict[str, str]:
    return {
        "audit_id": audit_id,
        "user_id": user_id,
        "event_time": event_time,
        "field_name": field_name,
        "old_value": old_value,
        "new_value": new_value,
        "_source_file": source_file,
        "_source_location": source_location,
    }


def fact(
    file_id: str,
    fields: dict[str, str],
    *,
    captured_at: str | None = "2026-02-01T00:00:00Z",
    event_time: str | None = None,
    source_path: str = "evidence/synthetic.json",
    source_location: str = "/records/0",
):
    return build_fact(
        file_id=file_id,
        source_path=source_path,
        source_location=source_location,
        extraction_method="synthetic",
        fields=collect_direct_fields(fields, "/records/0"),
        captured_at=parse_timestamp(captured_at),
        inherited_timestamp=parse_timestamp(event_time),
    )


class IdentityTimelineTests(unittest.TestCase):
    def test_historical_email_changes_preserve_audit_provenance(self) -> None:
        resolver = IdentityResolver(
            [snapshot("user_alpha", "new@example.test")],
            [
                audit(
                    "audit_email",
                    "user_alpha",
                    "2026-01-01T00:00:00Z",
                    "email",
                    "old@example.test",
                    "new@example.test",
                )
            ],
        )

        old = resolver.resolve_identifier(
            "email", "OLD@example.test", at="2025-12-31T12:00:00Z"
        )
        current = resolver.resolve_identifier(
            "email", "new@example.test", at="2026-02-01T00:00:00Z"
        )

        self.assertEqual(old.status, "confirmed")
        self.assertEqual(old.user_id, "user_alpha")
        self.assertEqual(old.matched_links[0].audit_id, "audit_email")
        self.assertEqual(old.matched_links[0].source_file, "synthetic_audit.csv")
        self.assertEqual(old.matched_links[0].source_location, "row:2")
        self.assertEqual(current.user_id, "user_alpha")

    def test_phone_and_email_hash_history_are_resolved(self) -> None:
        resolver = IdentityResolver(
            [
                snapshot(
                    "user_alpha",
                    "person@example.test",
                    phone="+1 202 555 0111",
                    email_hash="hash-new",
                )
            ],
            [
                audit(
                    "audit_phone",
                    "user_alpha",
                    "2026-01-05T00:00:00Z",
                    "phone",
                    "+1 202 555 0100",
                    "+1 202 555 0111",
                ),
                audit(
                    "audit_hash",
                    "user_alpha",
                    "2026-01-06T00:00:00Z",
                    "email_hash",
                    "hash-old",
                    "hash-new",
                ),
            ],
        )

        phone = resolver.resolve_identifier(
            "phone", "+1202 555 0100", at="2026-01-04T00:00:00Z"
        )
        email_hash = resolver.resolve_identifier(
            "email_hash", "HASH-OLD", at="2026-01-05T12:00:00Z"
        )

        self.assertEqual(phone.user_id, "user_alpha")
        self.assertEqual(phone.matched_links[0].audit_id, "audit_phone")
        self.assertEqual(email_hash.user_id, "user_alpha")
        self.assertEqual(email_hash.matched_links[0].audit_id, "audit_hash")

    def test_reused_identifier_is_disambiguated_only_by_temporal_context(self) -> None:
        resolver = IdentityResolver(
            [
                snapshot("user_first", "first@example.test"),
                snapshot("user_second", "shared@example.test"),
            ],
            [
                audit(
                    "audit_first_reuse",
                    "user_first",
                    "2026-01-01T00:00:00Z",
                    "email",
                    "shared@example.test",
                    "first@example.test",
                ),
                audit(
                    "audit_second_reuse",
                    "user_second",
                    "2026-02-01T00:00:00Z",
                    "email",
                    "second@example.test",
                    "shared@example.test",
                ),
            ],
        )

        before = resolver.resolve_identifier(
            "email", "shared@example.test", at="2025-12-31T23:00:00Z"
        )
        after = resolver.resolve_identifier(
            "email", "shared@example.test", at="2026-02-15T00:00:00Z"
        )
        without_time = resolver.resolve_identifier("email", "shared@example.test")

        self.assertEqual(before.user_id, "user_first")
        self.assertEqual(after.user_id, "user_second")
        self.assertEqual(without_time.status, "ambiguous")
        self.assertEqual(without_time.candidate_user_ids, ("user_first", "user_second"))

    def test_evidence_with_stable_identifier_adds_provenance_link(self) -> None:
        observation = fact(
            "evidence_link",
            {
                "user_id": "user_alpha",
                "email": "evidence@example.test",
                "email_hash": "hash-evidence",
                "phone": "+1 202 555 0199",
            },
        )
        resolver = IdentityResolver(
            [snapshot("user_alpha", "snapshot@example.test")],
            evidence_facts=[observation],
        )

        resolution = resolver.resolve_identifier(
            "email", "evidence@example.test", as_of="2026-02-02T00:00:00Z"
        )

        self.assertEqual(resolution.user_id, "user_alpha")
        evidence_link = next(
            link for link in resolution.matched_links if link.source == "evidence"
        )
        self.assertEqual(evidence_link.source_file, "evidence/synthetic.json")
        self.assertEqual(evidence_link.source_location, "/records/0")
        self.assertEqual(evidence_link.source_id, "evidence_link")

    def test_ambiguous_evidence_is_not_merged_with_name_match(self) -> None:
        resolver = IdentityResolver(
            [
                snapshot("user_first", "shared@example.test"),
                snapshot("user_second", "shared@example.test"),
            ]
        )
        result = resolver.resolve_identifier("email", "shared@example.test")
        name_only = resolver.resolve_identifier("name", "Names are not identifiers")
        timeline = reconstruct_timeline(
            {
                "case_id": "ambiguous_case",
                "email": "shared@example.test",
                "audit_at": "2026-03-02T00:00:00Z",
            },
            resolver,
            activity_events=[
                {
                    "activity_id": "activity_ambiguous",
                    "event_time": "2026-03-01T12:00:00Z",
                    "event_type": "SYNC",
                    "resource_id": "resource_shared",
                    "details": "Event associated with shared@example.test.",
                }
            ],
        )

        self.assertEqual(result.status, "ambiguous")
        self.assertEqual(result.candidate_user_ids, ("user_first", "user_second"))
        self.assertEqual(name_only.status, "unmatched")
        ambiguous_activity = next(
            event for event in timeline if event.source_id == "activity_ambiguous"
        )
        self.assertEqual(ambiguous_activity.identity_status, "ambiguous")
        self.assertEqual(
            ambiguous_activity.user_ids, ("user_first", "user_second")
        )

    def test_normalization_is_case_and_whitespace_conservative(self) -> None:
        resolver = IdentityResolver([snapshot("user_alpha", " Person@Example.Test ")])

        email = resolver.resolve_identifier("email", "person@example.test")
        phone = resolver.resolve_identifier("phone", "+1 202 555 0100")
        stable = resolver.resolve_identifier("user_id", " user_alpha ")
        wrong_case_stable = resolver.resolve_identifier("user_id", "USER_ALPHA")
        provider_variant = resolver.resolve_identifier(
            "email", "person+tag@example.test"
        )

        self.assertEqual(email.user_id, "user_alpha")
        self.assertEqual(phone.user_id, "user_alpha")
        self.assertEqual(stable.user_id, "user_alpha")
        self.assertEqual(wrong_case_stable.status, "unmatched")
        self.assertEqual(
            normalize_identifier("email", " Person@Example.Test "),
            "person@example.test",
        )
        self.assertIsNone(normalize_identifier("requester_phone", "null"))
        self.assertEqual(provider_variant.status, "unmatched")

    def test_as_of_timeline_excludes_future_audit_activity_and_evidence(self) -> None:
        snapshots = [snapshot("user_alpha", "new@example.test")]
        audits = [
            audit(
                "audit_before",
                "user_alpha",
                "2026-01-01T00:00:00Z",
                "email",
                "old@example.test",
                "new@example.test",
            ),
            audit(
                "audit_after",
                "user_alpha",
                "2026-03-01T00:00:00Z",
                "email",
                "new@example.test",
                "later@example.test",
            ),
        ]
        before_fact = fact(
            "file_before",
            {"user_id": "user_alpha", "email": "new@example.test", "resource_id": "r1"},
            captured_at="2026-01-10T00:00:00Z",
            event_time="2026-01-09T00:00:00Z",
        )
        after_fact = fact(
            "file_after",
            {"user_id": "user_alpha", "email": "later@example.test", "resource_id": "r2"},
            captured_at="2026-03-10T00:00:00Z",
        )
        resolver = IdentityResolver(
            snapshots, audits, [before_fact, after_fact]
        )
        request = {
            "case_id": "synthetic_case",
            "email": "new@example.test",
            "requested_at": "2026-01-02T00:00:00Z",
            "audit_at": "2026-02-01T00:00:00Z",
        }
        activities = [
            {
                "activity_id": "activity_before",
                "event_time": "2026-01-20T00:00:00Z",
                "resource_id": "r1",
                "event_type": "SYNC",
            },
            {
                "activity_id": "activity_after",
                "event_time": "2026-03-20T00:00:00Z",
                "resource_id": "r1",
                "event_type": "SYNC",
            },
        ]

        timeline = reconstruct_timeline(
            request, resolver, activity_events=activities
        )
        source_ids = {event.source_id for event in timeline}

        self.assertIn("audit_before", source_ids)
        self.assertNotIn("audit_after", source_ids)
        self.assertIn("file_before", source_ids)
        self.assertNotIn("file_after", source_ids)
        self.assertIn("activity_before", source_ids)
        self.assertNotIn("activity_after", source_ids)
        self.assertEqual(
            next(event for event in timeline if event.source_id == "file_before").captured_at,
            datetime(2026, 1, 10, tzinfo=timezone.utc),
        )

    def test_capture_time_cutoff_excludes_evidence_independent_of_event_time(self) -> None:
        before = fact(
            "file_captured_before",
            {"user_id": "user_alpha", "email": "person@example.test"},
            captured_at="2026-01-31T23:00:00Z",
            event_time="2026-01-30T00:00:00Z",
        )
        after = fact(
            "file_captured_after",
            {"user_id": "user_alpha", "email": "person@example.test"},
            captured_at="2026-02-01T00:01:00Z",
            event_time="2026-01-15T00:00:00Z",
        )
        resolver = IdentityResolver(
            [snapshot("user_alpha", "person@example.test")],
            evidence_facts=[before, after],
        )
        request = {
            "case_id": "capture_case",
            "email": "person@example.test",
            "requested_at": "2026-01-01T00:00:00Z",
            "audit_at": "2026-02-01T00:00:00Z",
        }

        timeline = reconstruct_timeline(request, resolver)

        self.assertIn("file_captured_before", {event.source_id for event in timeline})
        self.assertNotIn("file_captured_after", {event.source_id for event in timeline})

    def test_missing_timestamps_remain_explicitly_uncertain(self) -> None:
        resolver = IdentityResolver(
            [snapshot("user_alpha", "person@example.test", updated_at="")]
        )
        observation = fact(
            "file_unknown_time",
            {"user_id": "user_alpha", "email": "person@example.test"},
            captured_at=None,
        )
        request = {
            "case_id": "unknown_time_case",
            "email": "person@example.test",
            "audit_at": "2026-02-01T00:00:00Z",
        }

        timeline = reconstruct_timeline(
            request, resolver, evidence_facts=[observation]
        )

        self.assertTrue(timeline)
        self.assertTrue(
            all(event.cutoff_status == "unknown_time" for event in timeline)
        )
        self.assertTrue(
            all(event.captured_at is None for event in timeline if event.event_type == "evidence_observation")
        )

    def test_timezone_offsets_are_compared_as_instants(self) -> None:
        resolver = IdentityResolver(
            [snapshot("user_alpha", "person@example.test")],
            [
                audit(
                    "audit_offset",
                    "user_alpha",
                    "2026-01-01T00:30:00+01:00",
                    "email",
                    "old@example.test",
                    "person@example.test",
                )
            ],
        )
        request = {
            "case_id": "timezone_case",
            "email": "person@example.test",
            "requested_at": "2026-01-01T00:00:00Z",
            "audit_at": "2025-12-31T23:45:00Z",
        }

        timeline = reconstruct_timeline(request, resolver)

        offset_event = next(
            event for event in timeline if event.source_id == "audit_offset"
        )
        self.assertEqual(
            offset_event.event_time,
            datetime(2025, 12, 31, 23, 30, tzinfo=timezone.utc),
        )
        self.assertEqual(offset_event.cutoff_status, "in_scope")

    def test_naive_timestamps_are_interpreted_as_utc(self) -> None:
        observation = fact(
            "file_naive_time",
            {"user_id": "user_alpha", "email": "person@example.test"},
            captured_at="2026-01-01T00:15:00Z",
            event_time="2026-01-01T00:00:00",
        )
        resolver = IdentityResolver(
            [
                snapshot(
                    "user_alpha",
                    "person@example.test",
                    updated_at="2025-12-01T00:00:00Z",
                )
            ],
            evidence_facts=[observation],
        )
        timeline = reconstruct_timeline(
            {
                "case_id": "naive_time_case",
                "email": "person@example.test",
                "audit_at": "2026-01-01T00:30:00Z",
            },
            resolver,
        )

        evidence_event = next(
            event for event in timeline if event.source_id == "file_naive_time"
        )
        self.assertEqual(
            evidence_event.event_time,
            datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
        )

    def test_repeated_resolution_and_timeline_are_deterministic(self) -> None:
        resolver = IdentityResolver(
            [snapshot("user_alpha", "person@example.test")],
            [
                audit(
                    "audit_second",
                    "user_alpha",
                    "2026-01-02T00:00:00Z",
                    "phone",
                    "+1 202 555 0100",
                    "+1 202 555 0110",
                ),
                audit(
                    "audit_first",
                    "user_alpha",
                    "2026-01-01T00:00:00Z",
                    "email",
                    "old@example.test",
                    "person@example.test",
                ),
            ],
        )
        request = {
            "case_id": "stable_case",
            "email": "person@example.test",
            "audit_at": "2026-02-01T00:00:00Z",
        }
        first = reconstruct_timeline(request, resolver)
        reordered_resolver = IdentityResolver(
            [snapshot("user_alpha", "person@example.test")],
            list(reversed(resolver.audit_events)),
        )
        second = reconstruct_timeline(request, reordered_resolver)

        self.assertEqual(first, second)
        self.assertEqual(resolver.links, reordered_resolver.links)
        self.assertEqual(
            [event.source_id for event in first],
            [event.source_id for event in sorted(
                first,
                key=lambda event: (
                    event.event_time or datetime.min.replace(tzinfo=timezone.utc),
                    event.captured_at or datetime.min.replace(tzinfo=timezone.utc),
                    event.event_type,
                    event.source_id,
                    event.source_file or "",
                    event.source_location or "",
                ),
            )],
        )

    def test_csv_loader_preserves_row_location_and_audit_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity_path = root / "user_identities.csv"
            audit_path = root / "user_audit_log.csv"
            activity_path = root / "system_activity.csv"
            with identity_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["user_id", "name", "email", "phone", "email_hash", "updated_at"],
                )
                writer.writeheader()
                writer.writerow(snapshot("user_alpha", "new@example.test"))
            with audit_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "audit_id",
                        "user_id",
                        "event_time",
                        "field_name",
                        "old_value",
                        "new_value",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        key: value
                        for key, value in audit(
                            "audit_csv",
                            "user_alpha",
                            "2026-01-01T00:00:00Z",
                            "email",
                            "old@example.test",
                            "new@example.test",
                        ).items()
                        if not key.startswith("_")
                    }
                )
            with activity_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=[
                        "activity_id",
                        "event_time",
                        "event_type",
                        "resource_id",
                        "details",
                    ],
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "activity_id": "activity_csv",
                        "event_time": "2026-02-01T00:00:00Z",
                        "event_type": "SYNC",
                        "resource_id": "resource_csv",
                        "details": (
                            "Catalog linked resource_csv to new@example.test and "
                            "user_alpha."
                        ),
                    }
                )

            resolver = load_identity_resolver(identity_path, audit_path)
            resolution = resolver.resolve_identifier(
                "email", "old@example.test", at="2025-12-01T00:00:00Z"
            )
            timeline = reconstruct_timeline(
                {
                    "case_id": "activity_provenance",
                    "email": "new@example.test",
                    "audit_at": "2026-02-02T00:00:00Z",
                },
                resolver,
                activity_events=load_activity_events(activity_path),
            )

        self.assertEqual(resolution.user_id, "user_alpha")
        self.assertEqual(resolution.matched_links[0].audit_id, "audit_csv")
        self.assertEqual(resolution.matched_links[0].source_id, "audit_csv")
        self.assertEqual(resolution.matched_links[0].source_file, "user_audit_log.csv")
        self.assertEqual(resolution.matched_links[0].source_location, "row:2")
        activity_event = next(
            event for event in timeline if event.source_id == "activity_csv"
        )
        self.assertEqual(activity_event.source_file, "system_activity.csv")
        self.assertEqual(activity_event.source_location, "row:2")
        self.assertEqual(activity_event.identity_status, "confirmed")


if __name__ == "__main__":
    unittest.main()
