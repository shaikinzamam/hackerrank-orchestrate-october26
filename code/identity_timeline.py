"""Historical identity matching and auditable as-of timeline reconstruction."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from evidence_model import EvidenceFact, parse_timestamp


_FIELD_ALIASES = {
    "account_email": "email",
    "customer_email": "email",
    "email": "email",
    "email_hash": "email_hash",
    "hashed_email": "email_hash",
    "owner_email": "email",
    "phone": "phone",
    "requester_email": "email",
    "requester_phone": "phone",
    "subject_id": "user_id",
    "subject_reference": "user_id",
    "user_id": "user_id",
    "customer_id": "user_id",
    "customer_reference": "user_id",
}
_IDENTIFIER_FIELDS = ("email", "email_hash", "phone", "user_id")
_EMAIL_PATTERN = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^_`{|}~-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w-])"
)
_HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{32,128}\b")
_PHONE_PATTERN = re.compile(r"(?<!\w)\+?[\d().\s-]{6,}\d(?!\w)")
_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9_-]*\b")


def _as_utc(value: Any) -> datetime | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def normalize_identifier(field_name: str, value: Any) -> str | None:
    """Normalize only whitespace/case; do not apply provider-specific rules."""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.casefold() == "null":
        return None
    canonical_field = _FIELD_ALIASES.get(field_name.strip().casefold())
    if canonical_field is None:
        return None
    if canonical_field == "email":
        return text.casefold()
    if canonical_field == "phone":
        return re.sub(r"\s+", "", text)
    if canonical_field == "user_id":
        return text
    return text.casefold()


def _field_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return _FIELD_ALIASES.get(value.strip().casefold())


def _stable_user_id(value: Any, known_user_ids: set[str]) -> str | None:
    normalized = normalize_identifier("user_id", value)
    if normalized is None:
        return None
    for known_user_id in known_user_ids:
        if normalize_identifier("user_id", known_user_id) == normalized:
            return known_user_id
    return None


def _csv_records(
    path: str | Path,
    *,
    required_columns: set[str] | None = None,
) -> tuple[dict[str, str], ...]:
    source = Path(path)
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"{source}: CSV has no header")
        missing = (required_columns or set()) - set(reader.fieldnames)
        if missing:
            raise ValueError(f"{source}: missing columns {sorted(missing)}")
        return tuple(
            {
                **row,
                "_source_file": source.name,
                "_source_location": f"row:{line_no}",
            }
            for line_no, row in enumerate(reader, start=2)
        )


@dataclass(frozen=True)
class IdentityLink:
    user_id: str
    field_name: str
    value: str
    normalized_value: str
    valid_from: datetime | None
    valid_to: datetime | None
    available_at: datetime | None
    source: str
    source_file: str | None
    source_location: str | None
    audit_id: str | None = None
    captured_at: datetime | None = None
    source_id: str | None = None


@dataclass(frozen=True)
class IdentityResolution:
    status: str
    field_name: str
    value: str
    normalized_value: str | None
    user_id: str | None
    candidate_user_ids: tuple[str, ...]
    matched_links: tuple[IdentityLink, ...]
    reason: str


@dataclass(frozen=True)
class TimelineEvent:
    case_id: str
    event_type: str
    source_id: str
    event_time: datetime | None
    captured_at: datetime | None
    ingestion_time: datetime | None
    source_file: str | None
    source_location: str | None
    user_ids: tuple[str, ...]
    identity_status: str
    cutoff_status: str
    details: tuple[tuple[str, str], ...]


def _record_value(record: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = record.get(name)
        if value is not None and str(value).strip():
            return value
    return None


def _snapshot_links(
    identities: Iterable[Mapping[str, Any]],
) -> tuple[list[IdentityLink], set[str]]:
    links: list[IdentityLink] = []
    user_ids: set[str] = set()
    for row_no, row in enumerate(identities, start=2):
        user_id_value = _record_value(row, "user_id")
        if user_id_value is None:
            continue
        user_id = str(user_id_value).strip()
        if not user_id:
            continue
        user_ids.add(user_id)
        updated_at = _as_utc(_record_value(row, "updated_at"))
        source_file = _record_value(row, "_source_file") or "user_identities.csv"
        source_location = _record_value(row, "_source_location") or f"row:{row_no}"

        stable_value = normalize_identifier("user_id", user_id)
        if stable_value:
            links.append(
                IdentityLink(
                    user_id,
                    "user_id",
                    user_id,
                    stable_value,
                    None,
                    None,
                    updated_at,
                    "snapshot",
                    str(source_file),
                    str(source_location),
                    source_id=user_id,
                )
            )

        for field_name in ("email", "phone", "email_hash"):
            value = _record_value(row, field_name)
            normalized = normalize_identifier(field_name, value)
            if not normalized:
                continue
            links.append(
                IdentityLink(
                    user_id,
                    field_name,
                    str(value),
                    normalized,
                    updated_at,
                    None,
                    updated_at,
                    "snapshot",
                    str(source_file),
                    str(source_location),
                    source_id=user_id,
                )
            )
    return links, user_ids


def _reconcile_temporal_links(
    snapshot_links: list[IdentityLink],
    audit_links: list[IdentityLink],
) -> tuple[list[IdentityLink], list[IdentityLink]]:
    reconciled_snapshots: list[IdentityLink] = []
    reconciled_audits: list[IdentityLink] = []
    fields = {
        (link.user_id, link.field_name)
        for link in snapshot_links + audit_links
        if link.field_name != "user_id"
    }
    for user_id, field_name in sorted(fields):
        snapshots = [
            link
            for link in snapshot_links
            if link.user_id == user_id and link.field_name == field_name
        ]
        audits = [
            link
            for link in audit_links
            if link.user_id == user_id and link.field_name == field_name
        ]
        snapshot = snapshots[-1] if snapshots else None
        snapshot_time = snapshot.available_at if snapshot else None
        future_audit_times = sorted(
            link.available_at
            for link in audits
            if snapshot_time is not None
            and link.available_at is not None
            and link.available_at > snapshot_time
        )
        snapshot_end = future_audit_times[0] if future_audit_times else None
        for link in snapshots:
            reconciled_snapshots.append(
                IdentityLink(
                    link.user_id,
                    link.field_name,
                    link.value,
                    link.normalized_value,
                    link.valid_from,
                    snapshot_end,
                    link.available_at,
                    link.source,
                    link.source_file,
                    link.source_location,
                    link.audit_id,
                    link.captured_at,
                    link.source_id,
                )
            )
        for link in audits:
            valid_to = link.valid_to
            if (
                link.source == "audit_new"
                and valid_to is None
                and snapshot_time is not None
                and link.valid_from is not None
                and link.valid_from < snapshot_time
                and link.normalized_value
                != (snapshot.normalized_value if snapshot else None)
            ):
                valid_to = snapshot_time
            reconciled_audits.append(
                IdentityLink(
                    link.user_id,
                    link.field_name,
                    link.value,
                    link.normalized_value,
                    link.valid_from,
                    valid_to,
                    link.available_at,
                    link.source,
                    link.source_file,
                    link.source_location,
                    link.audit_id,
                    link.captured_at,
                    link.source_id,
                )
            )

    reconciled_snapshots.extend(
        link for link in snapshot_links if link.field_name == "user_id"
    )
    reconciled_audits.extend(
        link for link in audit_links if link.field_name == "user_id"
    )
    return reconciled_snapshots, reconciled_audits


def _audit_links(
    audit_events: Iterable[Mapping[str, Any]],
    known_user_ids: set[str],
) -> list[IdentityLink]:
    audit_rows = tuple(audit_events)
    grouped: dict[tuple[str, str], list[tuple[datetime | None, str, Mapping[str, Any]]]] = {}
    for row_no, row in enumerate(audit_rows, start=2):
        user_id = _stable_user_id(_record_value(row, "user_id"), known_user_ids)
        field_name = _field_name(_record_value(row, "field_name"))
        if user_id is None or field_name not in _IDENTIFIER_FIELDS:
            continue
        event_time = _as_utc(_record_value(row, "event_time"))
        audit_id = str(_record_value(row, "audit_id") or f"row:{row_no}")
        grouped.setdefault((user_id, field_name), []).append(
            (event_time, audit_id, row)
        )

    links: list[IdentityLink] = []
    for row_no, row in enumerate(audit_rows, start=2):
        user_id = _stable_user_id(_record_value(row, "user_id"), known_user_ids)
        if user_id is None:
            continue
        event_time = _as_utc(_record_value(row, "event_time"))
        audit_id = str(_record_value(row, "audit_id") or f"row:{row_no}")
        links.append(
            IdentityLink(
                user_id,
                "user_id",
                user_id,
                normalize_identifier("user_id", user_id) or user_id,
                None,
                None,
                event_time,
                "audit_user",
                str(_record_value(row, "_source_file") or "user_audit_log.csv"),
                str(_record_value(row, "_source_location") or f"row:{row_no}"),
                audit_id,
                source_id=audit_id,
            )
        )
    for (user_id, field_name), events in sorted(grouped.items()):
        events.sort(
            key=lambda item: (
                item[0] is None,
                item[0] or datetime.max.replace(tzinfo=timezone.utc),
                item[1],
            )
        )
        for index, (event_time, audit_id, row) in enumerate(events):
            source_file = _record_value(row, "_source_file") or "user_audit_log.csv"
            source_location = _record_value(row, "_source_location")
            if source_location is None:
                source_location = f"row:{index + 2}"
            next_time = events[index + 1][0] if index + 1 < len(events) else None

            old_value = _record_value(row, "old_value")
            old_normalized = normalize_identifier(field_name, old_value)
            if old_normalized:
                previous_time = events[index - 1][0] if index else None
                links.append(
                    IdentityLink(
                        user_id,
                        field_name,
                        str(old_value),
                        old_normalized,
                        previous_time,
                        event_time,
                        event_time,
                        "audit_old",
                        str(source_file),
                        str(source_location),
                        audit_id,
                        source_id=audit_id,
                    )
                )

            new_value = _record_value(row, "new_value")
            new_normalized = normalize_identifier(field_name, new_value)
            if new_normalized:
                links.append(
                    IdentityLink(
                        user_id,
                        field_name,
                        str(new_value),
                        new_normalized,
                        event_time,
                        next_time,
                        event_time,
                        "audit_new",
                        str(source_file),
                        str(source_location),
                        audit_id,
                        source_id=audit_id,
                    )
                )
    return links


def _fact_identifiers(fact: EvidenceFact) -> tuple[tuple[str, str], ...]:
    values: set[tuple[str, str]] = set()
    for candidate in fact.candidate_identifiers:
        field_name = _field_name(candidate.field_name)
        if field_name is not None:
            values.add((field_name, candidate.value))
    for field in fact.observed_fields:
        field_name = _field_name(field.name)
        if field_name is not None:
            values.add((field_name, field.value))
    return tuple(sorted(values))


class IdentityResolver:
    """Resolve exact identifiers without conflating distinct stable users."""

    def __init__(
        self,
        identities: Iterable[Mapping[str, Any]],
        audit_events: Iterable[Mapping[str, Any]] = (),
        evidence_facts: Iterable[EvidenceFact] = (),
    ) -> None:
        self._identity_rows = tuple(identities)
        self._audit_events = tuple(audit_events)
        self.evidence_facts = tuple(evidence_facts)
        self._snapshot_links, self.user_ids = _snapshot_links(self._identity_rows)
        self._audit_links = _audit_links(self._audit_events, self.user_ids)
        self._snapshot_links, self._audit_links = _reconcile_temporal_links(
            self._snapshot_links, self._audit_links
        )
        self._evidence_links = self._build_evidence_links()
        self.links = tuple(
            sorted(
                self._snapshot_links + self._audit_links + self._evidence_links,
                key=_link_sort_key,
            )
        )
        links_by_identifier: dict[tuple[str, str], list[IdentityLink]] = {}
        for link in self.links:
            links_by_identifier.setdefault(
                (link.field_name, link.normalized_value), []
            ).append(link)
        self._links_by_identifier = {
            key: tuple(sorted(links, key=_link_sort_key))
            for key, links in links_by_identifier.items()
        }
        fact_indexes_by_user: dict[str, list[int]] = {}
        for index, fact in enumerate(self.evidence_facts):
            resolution = self.resolve_fact(fact)
            for user_id in resolution.candidate_user_ids:
                fact_indexes_by_user.setdefault(user_id, []).append(index)
        self._fact_indexes_by_user = {
            user_id: tuple(indexes)
            for user_id, indexes in fact_indexes_by_user.items()
        }

    def _build_evidence_links(self) -> list[IdentityLink]:
        links: list[IdentityLink] = []
        audit_change_times: dict[tuple[str, str], list[datetime]] = {}
        for link in self._audit_links:
            if link.available_at is not None and link.field_name != "user_id":
                audit_change_times.setdefault(
                    (link.user_id, link.field_name), []
                ).append(link.available_at)
        for fact in self.evidence_facts:
            identifiers = _fact_identifiers(fact)
            stable_ids = {
                stable_id
                for field_name, value in identifiers
                if field_name == "user_id"
                for stable_id in [_stable_user_id(value, self.user_ids)]
                if stable_id is not None
            }
            if len(stable_ids) != 1:
                continue
            user_id = next(iter(stable_ids))
            observed_at = _as_utc(fact.event_timestamp) or _as_utc(fact.captured_at)
            for field_name, value in identifiers:
                if field_name == "user_id":
                    continue
                normalized = normalize_identifier(field_name, value)
                if not normalized:
                    continue
                later_changes = [
                    timestamp
                    for timestamp in audit_change_times.get((user_id, field_name), ())
                    if observed_at is not None and timestamp > observed_at
                ]
                links.append(
                    IdentityLink(
                        user_id,
                        field_name,
                        value,
                        normalized,
                        observed_at,
                        min(later_changes) if later_changes else None,
                        _as_utc(fact.captured_at),
                        "evidence",
                        fact.source_path,
                        fact.source_location,
                        captured_at=_as_utc(fact.captured_at),
                        source_id=fact.file_id,
                    )
                )
        return links

    def resolve_identifier(
        self,
        field_name: str,
        value: Any,
        *,
        at: Any = None,
        as_of: Any = None,
    ) -> IdentityResolution:
        canonical_field = _field_name(field_name)
        normalized = normalize_identifier(field_name, value)
        original_value = "" if value is None else str(value)
        if canonical_field is None or normalized is None:
            return IdentityResolution(
                "unmatched",
                canonical_field or field_name,
                original_value,
                normalized,
                None,
                (),
                (),
                "unsupported or empty identifier",
            )

        effective_at = _as_utc(at)
        cutoff = _as_utc(as_of)
        matches = [
            link
            for link in self._links_by_identifier.get(
                (canonical_field, normalized), ()
            )
            if (
                cutoff is None
                or link.available_at is None
                or link.available_at <= cutoff
            )
            and (
                effective_at is None
                or link.valid_from is None
                or link.valid_from <= effective_at
            )
            and (
                effective_at is None
                or link.valid_to is None
                or effective_at < link.valid_to
            )
        ]
        candidates = tuple(sorted({link.user_id for link in matches}))
        unknown_temporal_link = bool(
            (effective_at is not None or cutoff is not None)
            and any(
                link.available_at is None
                and link.source
                in {"snapshot", "audit_user", "audit_old", "audit_new", "evidence"}
                for link in matches
            )
        )
        if len(candidates) == 1 and unknown_temporal_link:
            status = "ambiguous"
            reason = "matching identity evidence has no usable timestamp"
            user_id = None
        elif len(candidates) == 1:
            status = "confirmed"
            reason = "exact normalized identifier maps to one stable user_id"
            user_id = candidates[0]
        elif candidates:
            status = "ambiguous"
            reason = "identifier is linked to multiple stable user_ids"
            user_id = None
        else:
            status = "unmatched"
            reason = "no exact identifier link is available at the requested time"
            user_id = None
        return IdentityResolution(
            status,
            canonical_field,
            original_value,
            normalized,
            user_id,
            candidates,
            tuple(sorted(matches, key=_link_sort_key)),
            reason,
        )

    def resolve_request(
        self,
        request: Mapping[str, Any],
        *,
        as_of: Any = None,
    ) -> IdentityResolution:
        cutoff = as_of if as_of is not None else request.get("audit_at")
        requested_at = request.get("requested_at")
        resolution = self.resolve_identifier(
            "email",
            request.get("email"),
            at=requested_at,
            as_of=cutoff,
        )
        if resolution.status != "unmatched":
            return resolution
        # A request can use an older address not active at submission time.
        # Historical ownership is safe only when it identifies one user.
        historical = self.resolve_identifier(
            "email", request.get("email"), as_of=cutoff
        )
        return historical if historical.status != "unmatched" else resolution

    def resolve_fact(
        self,
        fact: EvidenceFact,
        *,
        as_of: Any = None,
    ) -> IdentityResolution:
        cutoff = _as_utc(as_of)
        captured_at = _as_utc(fact.captured_at)
        if cutoff is not None and captured_at is not None and captured_at > cutoff:
            return IdentityResolution(
                "unmatched",
                "",
                "",
                None,
                None,
                (),
                (),
                "evidence was captured after the as-of cutoff",
            )

        matches: list[IdentityLink] = []
        candidate_user_ids: set[str] = set()
        uncertain_match = False
        event_time = _as_utc(fact.event_timestamp) or captured_at
        for field_name, value in _fact_identifiers(fact):
            resolution = self.resolve_identifier(
                field_name,
                value,
                at=event_time,
                as_of=cutoff,
            )
            candidate_user_ids.update(resolution.candidate_user_ids)
            uncertain_match = uncertain_match or resolution.status == "ambiguous"
            matches.extend(resolution.matched_links)

        candidates = tuple(sorted(candidate_user_ids))
        if len(candidates) == 1 and uncertain_match:
            status = "ambiguous"
            user_id = None
            reason = "fact has identity candidates with uncertain temporal validity"
        elif len(candidates) == 1:
            status = "confirmed"
            user_id = candidates[0]
            reason = "fact identifiers resolve to one stable user_id"
        elif candidates:
            status = "ambiguous"
            user_id = None
            reason = "fact identifiers conflict or have multiple possible owners"
        else:
            status = "unmatched"
            user_id = None
            reason = "fact has no identifier linked to a known stable user_id"
        return IdentityResolution(
            status,
            "",
            "",
            None,
            user_id,
            candidates,
            tuple(sorted(set(matches), key=_link_sort_key)),
            reason,
        )

    def links_for_user(
        self,
        user_id: str,
        *,
        at: Any = None,
        as_of: Any = None,
    ) -> tuple[IdentityLink, ...]:
        effective_at = _as_utc(at)
        cutoff = _as_utc(as_of)
        return tuple(
            link
            for link in self.links
            if link.user_id == user_id
            and (cutoff is None or link.available_at is None or link.available_at <= cutoff)
            and (
                effective_at is None
                or link.valid_from is None
                or link.valid_from <= effective_at
            )
            and (
                effective_at is None
                or link.valid_to is None
                or effective_at < link.valid_to
            )
        )

    @property
    def audit_events(self) -> tuple[Mapping[str, Any], ...]:
        return self._audit_events

    @property
    def identity_rows(self) -> tuple[Mapping[str, Any], ...]:
        return self._identity_rows


def _link_sort_key(link: IdentityLink) -> tuple[Any, ...]:
    return (
        link.user_id,
        link.field_name,
        link.normalized_value,
        link.valid_from or datetime.min.replace(tzinfo=timezone.utc),
        link.valid_to or datetime.max.replace(tzinfo=timezone.utc),
        link.source,
        link.source_file or "",
        link.source_location or "",
        link.audit_id or "",
        link.source_id or "",
    )


def load_identity_resolver(
    identities_path: str | Path,
    audit_path: str | Path,
    *,
    evidence_facts: Iterable[EvidenceFact] = (),
) -> IdentityResolver:
    """Load the challenge identity and audit schemas with row provenance."""
    required_identity_columns = {"user_id", "email", "phone", "email_hash", "updated_at"}
    required_audit_columns = {
        "audit_id",
        "user_id",
        "event_time",
        "field_name",
        "old_value",
        "new_value",
    }
    identities = _csv_records(
        identities_path, required_columns=required_identity_columns
    )
    audits = _csv_records(audit_path, required_columns=required_audit_columns)
    return IdentityResolver(identities, audits, evidence_facts)


def _activity_identifiers(
    activity: Mapping[str, Any],
) -> tuple[tuple[str, str], ...]:
    identifiers: set[tuple[str, str]] = set()
    for name, value in activity.items():
        field_name = _field_name(name)
        if field_name is not None and normalize_identifier(field_name, value):
            identifiers.add((field_name, str(value)))

    details = str(activity.get("details") or "")
    email_labels = {
        "account_email",
        "customer_email",
        "email",
        "owner_email",
        "requester_email",
    }
    for value in _EMAIL_PATTERN.findall(details):
        if "=" in value:
            label, candidate = value.rsplit("=", 1)
            if label.casefold() in email_labels:
                value = candidate
        identifiers.add(("email", value))
    identifiers.update(
        ("email_hash", value) for value in _HASH_PATTERN.findall(details)
    )
    identifiers.update(("phone", value) for value in _PHONE_PATTERN.findall(details))
    identifiers.update(
        ("user_id", value)
        for value in _TOKEN_PATTERN.findall(details)
    )
    return tuple(sorted(identifiers))


def load_activity_events(activity_path: str | Path) -> tuple[dict[str, Any], ...]:
    """Load process activity with CSV row provenance for timeline events."""
    required_columns = {"activity_id", "event_time", "event_type", "resource_id"}
    return tuple(
        {**row, "_identity_candidates": _activity_identifiers(row)}
        for row in _csv_records(activity_path, required_columns=required_columns)
    )


def _activity_matches(
    activity: Mapping[str, Any],
    user_ids: set[str],
    resolver: IdentityResolver,
    resource_users: Mapping[str, set[str]],
    ambiguous_resources: set[str],
    cutoff: datetime | None,
) -> tuple[str, tuple[str, ...]]:
    candidates: set[str] = set()
    ambiguous = False
    resource_id = str(activity.get("resource_id", "")).strip()
    if resource_id in resource_users:
        candidates.update(resource_users[resource_id] & user_ids)
        ambiguous = resource_id in ambiguous_resources or len(
            resource_users[resource_id]
        ) > 1
    identifier_pairs = activity.get("_identity_candidates")
    if identifier_pairs is None:
        identifier_pairs = _activity_identifiers(activity)
    for field_name, value in identifier_pairs:
        if field_name == "user_id" and str(value).strip() not in resolver.user_ids:
            continue
        resolution = resolver.resolve_identifier(
            field_name, value, as_of=cutoff
        )
        candidates.update(set(resolution.candidate_user_ids) & user_ids)
        ambiguous = ambiguous or resolution.status == "ambiguous"
    if ambiguous or len(candidates) > 1:
        status = "ambiguous"
    elif candidates:
        status = "confirmed"
    else:
        status = "unmatched"
    return status, tuple(sorted(candidates))


def reconstruct_timeline(
    request: Mapping[str, Any],
    resolver: IdentityResolver,
    *,
    activity_events: Iterable[Mapping[str, Any]] = (),
    evidence_facts: Iterable[EvidenceFact] | None = None,
) -> tuple[TimelineEvent, ...]:
    """Return relevant identity, evidence, and activity observations at audit_at.

    Events with unknown time are retained with ``cutoff_status="unknown_time"``
    so missing source data is not silently treated as evidence of absence.
    """
    cutoff = _as_utc(request.get("audit_at"))
    case_id = str(request.get("case_id") or "")
    resolution = resolver.resolve_request(request, as_of=cutoff)
    user_ids = set(resolution.candidate_user_ids)
    if resolution.user_id:
        user_ids.add(resolution.user_id)
    if not user_ids:
        return ()

    timeline: list[TimelineEvent] = []
    for row in resolver.audit_events:
        user_id = _stable_user_id(row.get("user_id"), resolver.user_ids)
        if user_id not in user_ids:
            continue
        event_time = _as_utc(row.get("event_time"))
        if cutoff is not None and event_time is not None and event_time > cutoff:
            continue
        timeline.append(
            TimelineEvent(
                case_id,
                "identity_change",
                str(row.get("audit_id") or ""),
                event_time,
                None,
                None,
                str(row.get("_source_file") or "user_audit_log.csv"),
                row.get("_source_location"),
                (user_id,),
                "confirmed",
                "unknown_time" if event_time is None or cutoff is None else "in_scope",
                tuple(
                    sorted(
                        (str(key), str(value))
                        for key, value in row.items()
                        if not key.startswith("_") and value is not None
                    )
                ),
            )
        )

    identity_rows_by_id = {
        str(row.get("user_id", "")).strip(): row for row in resolver.identity_rows
    }
    for user_id in sorted(user_ids):
        row = identity_rows_by_id.get(user_id)
        if row is None:
            continue
        updated_at = _as_utc(row.get("updated_at"))
        if cutoff is not None and updated_at is not None and updated_at > cutoff:
            continue
        if any(
            link.source == "snapshot"
            and link.user_id == user_id
            and link.available_at == updated_at
            for link in resolver.links
        ):
            timeline.append(
                TimelineEvent(
                    case_id,
                    "identity_snapshot",
                    user_id,
                    updated_at,
                    None,
                    None,
                    str(row.get("_source_file") or "user_identities.csv"),
                    row.get("_source_location"),
                    (user_id,),
                    "confirmed",
                    "unknown_time" if updated_at is None else "in_scope",
                    tuple(
                        sorted(
                            (key, str(row[key]))
                            for key in ("user_id", "email", "phone", "email_hash")
                            if row.get(key) is not None
                        )
                    ),
                )
            )

    if evidence_facts is None:
        fact_indexes = sorted(
            {
                index
                for user_id in user_ids
                for index in resolver._fact_indexes_by_user.get(user_id, ())
            }
        )
        facts = tuple(resolver.evidence_facts[index] for index in fact_indexes)
    else:
        facts = tuple(evidence_facts)
    relevant_resources: dict[str, set[str]] = {}
    ambiguous_resources: set[str] = set()
    for fact in facts:
        captured_at = _as_utc(fact.captured_at)
        event_time = _as_utc(fact.event_timestamp)
        if cutoff is not None and captured_at is not None and captured_at > cutoff:
            continue
        if cutoff is not None and event_time is not None and event_time > cutoff:
            continue
        fact_resolution = resolver.resolve_fact(fact, as_of=cutoff)
        fact_users = set(fact_resolution.candidate_user_ids)
        relevant_users = tuple(sorted(fact_users & user_ids))
        if not relevant_users:
            continue
        if fact.resource_id:
            relevant_resources.setdefault(fact.resource_id, set()).update(
                relevant_users
            )
            if fact_resolution.status == "ambiguous":
                ambiguous_resources.add(fact.resource_id)
        timeline.append(
            TimelineEvent(
                case_id,
                "evidence_observation",
                fact.file_id,
                event_time,
                captured_at,
                None,
                fact.source_path,
                fact.source_location,
                relevant_users,
                fact_resolution.status,
                (
                    "unknown_time"
                    if captured_at is None or cutoff is None
                    else "in_scope"
                ),
                tuple(
                    sorted(
                        {
                            ("system_id", fact.system_id or ""),
                            ("resource_id", fact.resource_id or ""),
                            ("record_state", fact.record_state or ""),
                            ("data_categories", ",".join(fact.data_categories)),
                        }
                    )
                ),
            )
        )

    for row in activity_events:
        event_time = _as_utc(row.get("event_time"))
        if cutoff is not None and event_time is not None and event_time > cutoff:
            continue
        identity_status, relevant_users = _activity_matches(
            row,
            user_ids,
            resolver,
            relevant_resources,
            ambiguous_resources,
            cutoff,
        )
        if not relevant_users:
            continue
        timeline.append(
            TimelineEvent(
                case_id,
                "process_activity",
                str(row.get("activity_id") or ""),
                event_time,
                None,
                None,
                str(row.get("_source_file") or "system_activity.csv"),
                row.get("_source_location"),
                relevant_users,
                identity_status,
                "unknown_time" if event_time is None or cutoff is None else "in_scope",
                tuple(
                    sorted(
                        (str(key), str(value))
                        for key, value in row.items()
                        if not key.startswith("_") and value is not None
                    )
                ),
            )
        )

    timeline.sort(
        key=lambda event: (
            event.event_time or datetime.min.replace(tzinfo=timezone.utc),
            event.captured_at or datetime.min.replace(tzinfo=timezone.utc),
            event.event_type,
            event.source_id,
            event.source_file or "",
            event.source_location or "",
        )
    )
    return tuple(timeline)


__all__ = [
    "IdentityLink",
    "IdentityResolution",
    "IdentityResolver",
    "TimelineEvent",
    "load_activity_events",
    "load_identity_resolver",
    "normalize_identifier",
    "reconstruct_timeline",
]
