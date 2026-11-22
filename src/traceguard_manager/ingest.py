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
MAX_ACTIVE_RESPONSES = 64
RESPONSE_ACTIONS = ("block_peer", "freeze_cgroup")
# Records the manager reads elsewhere, never as alerts.
_NOT_ALERTS = frozenset({"command", "agent_stopping"})

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
    source_alert_id: str | None = None


@dataclass(frozen=True, slots=True)
class ActiveResponse:
    action: str
    target: str
    until: datetime | None
    applied: bool
    manual: bool

    def as_json(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "target": self.target,
            "until": self.until.isoformat() if self.until else None,
            "applied": self.applied,
            "manual": self.manual,
        }


@dataclass(frozen=True, slots=True)
class Stopping:
    at: datetime
    reason: str
    error: str | None
    # Identifies the record itself, so a replay is recognised even when a
    # different stop has the same parsed time.
    fingerprint: str = ""
    # The run that stopped, when the agent counts its runs.
    run_seq: int | None = None
    run_id: str | None = None
    install_id: str | None = None
    # False when ``at`` is the receive time standing in for the agent's.
    own_time: bool = True


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
    # Sent by TraceGuard 1.9 and later; None from older agents.
    agent_version: str | None = None
    kernel_release: str | None = None
    os_name: str | None = None
    response_mode: str | None = None
    commands_enabled: bool | None = None
    policy_remote_sha256: str | None = None
    export_dropped_records: int | None = None
    export_dropped_alerts: int | None = None
    export_rejected_batches: int | None = None
    export_spool_batches: int | None = None
    # None when the agent does not report responses at all.
    active_responses: list[ActiveResponse] | None = None
    active_responses_truncated: bool = False
    # Random per agent process start, and the agent's run counter (TraceGuard
    # 1.9): a higher run_seq is a newer run.
    run_id: str | None = None
    run_seq: int | None = None
    # Names the agent's run counter; a new one means the count started again.
    install_id: str | None = None
    # False when ``at`` is the receive time standing in for a time from the
    # future or one that did not parse: it then proves nothing about order.
    own_time: bool = True


@dataclass(slots=True)
class ParsedBatch:
    received: int = 0
    invalid: int = 0
    ignored: int = 0
    alerts: list[ParsedAlert] = field(default_factory=list)
    heartbeat: Heartbeat | None = None
    hostname: str | None = None
    stopping: Stopping | None = None
    # Every stop record in the batch, oldest first; ``stopping`` is the newest.
    stops: list[Stopping] = field(default_factory=list)
    # The newest record time in the batch, stop records aside.
    latest_at: datetime | None = None


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
        occurred_at, own_time = _checked_timestamp(record["timestamp"], now=now)
        hostname = record["hostname"][:MAX_HOSTNAME_LENGTH]
        batch.hostname = hostname
        event = _text(record.get("event"), 64) or ""
        if event != "agent_stopping" and (batch.latest_at is None or occurred_at > batch.latest_at):
            batch.latest_at = occurred_at
        if event == "heartbeat":
            heartbeat = _heartbeat(record, at=occurred_at, hostname=hostname, own_time=own_time)
            if batch.heartbeat is None or heartbeat.at >= batch.heartbeat.at:
                batch.heartbeat = heartbeat
            continue
        if event == "agent_stopping":
            canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
            stop = Stopping(
                at=occurred_at,
                reason=_text(record.get("reason"), 16) or "unknown",
                error=_text(record.get("error"), MAX_TITLE_LENGTH),
                fingerprint=hashlib.sha256(f"stopped:{canonical}".encode()).hexdigest(),
                run_seq=_positive_int(record.get("run_seq")),
                run_id=_run_id(record.get("run_id")),
                install_id=_run_id(record.get("install_id")),
                own_time=own_time,
            )
            batch.stops.append(stop)
            continue
        if event in _NOT_ALERTS:
            # Command results arrive through the command API instead.
            batch.ignored += 1
            continue
        kind = _classify(event, record)
        if kind is None:
            batch.ignored += 1
            continue
        batch.alerts.append(_alert(record, kind=kind, event=event, occurred_at=occurred_at, hostname=hostname))
    # Sorted once, stably, so equal times keep their arrival order.
    batch.stops.sort(key=lambda item: item.at)
    batch.stopping = batch.stops[-1] if batch.stops else None
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
        if name == "blocked" or name.endswith("_blocked") or name.startswith("blocked-"):
            return AlertKind.BLOCKED
        # Dry-run DNS and resolver records say so only in their message.
        if name.endswith("_would_block") or name == "would-block" or name.startswith("would-block-"):
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
        source_alert_id=alert_id if kind in (AlertKind.DETECTION, AlertKind.RESPONSE) else None,
    )


def _describe(name: str, record: dict[str, Any]) -> str:
    """Build a short, human-readable title for an enforcement event."""
    label = name.replace("_", " ").strip() or "blocked"
    for key in ("domain", "query", "path", "exe", "dest_ip", "daddr", "comm"):
        subject = _text(record.get(key), 200)
        if subject:
            return f"{label}: {subject}"
    return label


def _heartbeat(record: dict[str, Any], *, at: datetime, hostname: str, own_time: bool = True) -> Heartbeat:
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
        agent_version=_text(record.get("agent_version"), 32),
        kernel_release=_text(record.get("kernel_release"), 128),
        os_name=_text(record.get("os_name"), 128),
        response_mode=_text(record.get("response_mode"), 16),
        commands_enabled=_boolean(record.get("commands_enabled")),
        policy_remote_sha256=_hex_digest(record.get("policy_remote_sha256")),
        export_dropped_records=_non_negative_int(record.get("export_dropped_records")),
        export_dropped_alerts=_non_negative_int(record.get("export_dropped_alerts")),
        export_rejected_batches=_non_negative_int(record.get("export_rejected_batches")),
        export_spool_batches=_non_negative_int(record.get("export_spool_batches")),
        active_responses=_active_responses(record.get("active_responses")),
        active_responses_truncated=record.get("active_responses_truncated") is True,
        run_id=_run_id(record.get("run_id")),
        run_seq=_positive_int(record.get("run_seq")),
        install_id=_run_id(record.get("install_id")),
        own_time=own_time,
    )


def _positive_int(value: object) -> int | None:
    number = _non_negative_int(value)
    return number if number else None


def _run_id(value: object) -> str | None:
    # Checked whole, before any truncation, so a longer value never aliases a real ID.
    if not isinstance(value, str) or len(value) != 32 or not all(char in "0123456789abcdef" for char in value.lower()):
        return None
    return value.lower()


def _hex_digest(value: object) -> str | None:
    digest = _text(value, 64)
    return digest.lower() if digest is not None and _is_hex(digest) else None


def _active_responses(value: object) -> list[ActiveResponse] | None:
    if not isinstance(value, list):
        return None
    responses: list[ActiveResponse] = []
    for item in value[:MAX_ACTIVE_RESPONSES]:
        if not isinstance(item, dict):
            continue
        action = _text(item.get("action"), 32)
        target = _text(item.get("target"), 200)
        if action not in RESPONSE_ACTIONS or target is None:
            continue
        until = None
        if isinstance(raw_until := item.get("until"), str):
            try:
                parsed = datetime.fromisoformat(raw_until)
                until = (parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed).astimezone(UTC)
            except ValueError, OverflowError:
                # Out of range once converted to UTC, such as year 1 with a positive offset.
                until = None
        responses.append(
            ActiveResponse(
                action=action,
                target=target,
                until=until,
                applied=item.get("applied") is True,
                manual=item.get("manual") is True,
            )
        )
    return responses


def _timestamp(value: str, *, now: datetime) -> datetime:
    return _checked_timestamp(value, now=now)[0]


def _checked_timestamp(value: str, *, now: datetime) -> tuple[datetime, bool]:
    """Parse an RFC 3339 timestamp, falling back to the receive time.

    A timestamp from the future would pin an alert to the top of every list, so
    anything beyond a small clock skew is replaced with the receive time. The
    flag says whether the time is the agent's own, not that replacement.
    """
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        parsed = parsed.astimezone(UTC)
    except ValueError, OverflowError:
        return now, False
    return (now, False) if parsed > now + MAX_CLOCK_SKEW else (parsed, True)


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
