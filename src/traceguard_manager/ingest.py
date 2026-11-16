"""Turn TraceGuard export batches into the records the manager keeps.

TraceGuard posts a JSON array of flat objects: ``timestamp``, ``level``,
``message`` and ``hostname`` plus event-specific fields. Everything here is
untrusted input, so each value is type-checked and bounded before use.
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import AlertKind

# TraceGuard caps a serialized record at 32 KiB; allow headroom, then refuse.
MAX_RECORD_BYTES = 64 * 1024
MAX_TITLE_LENGTH = 512
MAX_HOSTNAME_LENGTH = 255
MAX_LIST_ITEMS = 64
MAX_LIST_ITEM_LENGTH = 200
MAX_CLOCK_SKEW = timedelta(minutes=10)

# Syslog-style severities, as validated by TraceGuard's policy loader.
SEVERITY_RANK: dict[str, int] = {
    "debug": 0,
    "informational": 1,
    "notice": 2,
    "warning": 3,
    "error": 4,
    "critical": 5,
    "alert": 6,
    "emergency": 7,
}
SEVERITIES: tuple[str, ...] = tuple(SEVERITY_RANK)


@dataclass(frozen=True, slots=True)
class ParsedAlert:
    fingerprint: str
    kind: AlertKind
    severity: str
    title: str
    rule_id: str | None
    source_event: str | None
    hostname: str
    occurred_at: datetime
    tags: list[str]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    fields: dict[str, Any]


@dataclass(frozen=True, slots=True)
class Heartbeat:
    at: datetime
    hostname: str
    healthy: bool | None
    policy_sha256: str | None
    policy_mode: str | None
    uptime_seconds: int | None
    ringbuf_degraded: bool | None
    ringbuf_dropped_events: int | None
    detection_rules: int | None
    unavailable_hooks: list[str]


@dataclass(slots=True)
class ParsedBatch:
    received: int = 0
    invalid: int = 0
    ignored: int = 0
    alerts: list[ParsedAlert] = field(default_factory=list)
    heartbeat: Heartbeat | None = None
    hostname: str | None = None


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, SEVERITY_RANK["warning"])


def parse_batch(payload: object, *, now: datetime) -> ParsedBatch:
    """Classify every record in a batch. Malformed records are counted, never raised.

    A bad record must not fail the whole request: TraceGuard would spool the
    batch and replay it forever.
    """
    if not isinstance(payload, list):
        raise ValueError("request body must be a JSON array of event records")
    batch = ParsedBatch(received=len(payload))
    for raw in payload:
        record = _validated(raw)
        if record is None:
            batch.invalid += 1
            continue
        occurred_at = _timestamp(record["timestamp"], now=now)
        hostname = record["hostname"][:MAX_HOSTNAME_LENGTH]
        batch.hostname = hostname
        event = _text(record.get("event"), 64) or ""
        if event == "heartbeat":
            heartbeat = _heartbeat(record, at=occurred_at, hostname=hostname)
            if batch.heartbeat is None or heartbeat.at >= batch.heartbeat.at:
                batch.heartbeat = heartbeat
            continue
        kind = _classify(event, record)
        if kind is None:
            batch.ignored += 1
            continue
        batch.alerts.append(_alert(record, kind=kind, event=event, occurred_at=occurred_at, hostname=hostname))
    return batch


def _validated(raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    for key in ("timestamp", "level", "message", "hostname"):
        if not isinstance(raw.get(key), str):
            return None
    if not raw["timestamp"] or not raw["hostname"].strip():
        return None
    if not all(isinstance(key, str) for key in raw):
        return None
    return raw


def _classify(event: str, record: dict[str, Any]) -> AlertKind | None:
    message = record["message"]
    if event == "detection_alert":
        return AlertKind.DETECTION
    for name in (event, message):
        if name == "blocked" or name.endswith("_blocked"):
            return AlertKind.BLOCKED
        if name.endswith("_would_block"):
            return AlertKind.WOULD_BLOCK
    if event == "response":
        return AlertKind.RESPONSE
    if record["level"].lower() == "error":
        return AlertKind.AGENT_ERROR
    return None


def _alert(record: dict[str, Any], *, kind: AlertKind, event: str, occurred_at: datetime, hostname: str) -> ParsedAlert:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    oversized = len(canonical) > MAX_RECORD_BYTES
    fields = {"message": record["message"][:MAX_TITLE_LENGTH], "truncated_by_manager": True} if oversized else record

    alert_id = _text(record.get("alert_id"), 128)
    identity = f"alert:{alert_id}" if kind is AlertKind.DETECTION and alert_id else canonical
    fingerprint = hashlib.sha256(identity.encode()).hexdigest()

    match kind:
        case AlertKind.DETECTION:
            severity = (_text(record.get("severity"), 16) or "warning").lower()
            if severity not in SEVERITY_RANK:
                severity = "warning"
            title = _text(record.get("detection_message"), MAX_TITLE_LENGTH) or record["message"]
        case AlertKind.BLOCKED:
            severity, title = "warning", _describe(event or record["message"], record)
        case AlertKind.WOULD_BLOCK:
            severity, title = "notice", _describe(event or record["message"], record)
        case AlertKind.RESPONSE:
            severity = "error" if record.get("error") else "notice"
            title = record["message"]
        case AlertKind.AGENT_ERROR:
            severity, title = "error", record["message"]

    return ParsedAlert(
        fingerprint=fingerprint,
        kind=kind,
        severity=severity,
        title=title[:MAX_TITLE_LENGTH] or kind.value,
        rule_id=_text(record.get("detection_rule_id"), 200),
        source_event=_text(record.get("source_event"), 64) or (event or None),
        hostname=hostname,
        occurred_at=occurred_at,
        tags=_text_list(record.get("tags")),
        mitre_tactics=_text_list(record.get("mitre_tactics")),
        mitre_techniques=_text_list(record.get("mitre_techniques")),
        fields=fields,
    )


def _describe(name: str, record: dict[str, Any]) -> str:
    """Build a short, human-readable title for an enforcement event."""
    label = name.replace("_", " ").strip() or "blocked"
    for key in ("domain", "query", "path", "exe", "dest_ip", "daddr", "comm"):
        subject = _text(record.get(key), 200)
        if subject:
            return f"{label}: {subject}"
    return label


def _heartbeat(record: dict[str, Any], *, at: datetime, hostname: str) -> Heartbeat:
    policy_sha256 = _text(record.get("policy_sha256"), 64)
    if policy_sha256 is not None and not _is_hex(policy_sha256):
        policy_sha256 = None
    return Heartbeat(
        at=at,
        hostname=hostname,
        healthy=_boolean(record.get("healthy")),
        policy_sha256=policy_sha256,
        policy_mode=_text(record.get("policy_mode"), 32),
        uptime_seconds=_non_negative_int(record.get("uptime_seconds")),
        ringbuf_degraded=_boolean(record.get("ringbuf_degraded")),
        ringbuf_dropped_events=_non_negative_int(record.get("ringbuf_dropped_events")),
        detection_rules=_non_negative_int(record.get("detection_rules")),
        unavailable_hooks=_text_list(record.get("unavailable_hooks")),
    )


def _timestamp(value: str, *, now: datetime) -> datetime:
    """Parse an RFC 3339 timestamp, falling back to the receive time.

    A timestamp from the future would pin an alert to the top of every list, so
    anything beyond a small clock skew is replaced with the receive time.
    """
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return now
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    parsed = parsed.astimezone(UTC)
    return now if parsed > now + MAX_CLOCK_SKEW else parsed


def _text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped[:limit] if stripped else None


def _text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item[:MAX_LIST_ITEM_LENGTH] for item in value[:MAX_LIST_ITEMS] if isinstance(item, str) and item]


def _boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value < 2**63 else None


def _is_hex(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value.lower())
