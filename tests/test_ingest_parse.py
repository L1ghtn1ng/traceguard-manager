from datetime import UTC, datetime, timedelta

import pytest

from traceguard_manager.ingest import MAX_RECORD_BYTES, parse_batch
from traceguard_manager.models import AlertKind

from .helpers import blocked, detection, heartbeat, telemetry

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def test_rejects_non_array_payload() -> None:
    with pytest.raises(ValueError, match="JSON array"):
        parse_batch({"not": "a list"}, now=NOW)


def test_classifies_each_record_type() -> None:
    batch = parse_batch(
        [
            heartbeat(),
            detection(),
            blocked(),
            blocked(event="exec_would_block", message="exec_would_block"),
            {
                "timestamp": NOW.isoformat(),
                "level": "info",
                "message": "response applied",
                "hostname": "h",
                "event": "response",
            },
            {
                "timestamp": NOW.isoformat(),
                "level": "error",
                "message": "eBPF ring buffer full",
                "hostname": "h",
            },
            telemetry(),
        ],
        now=NOW,
    )
    assert batch.received == 7
    assert batch.ignored == 1
    assert batch.invalid == 0
    assert batch.heartbeat is not None
    assert [alert.kind for alert in batch.alerts] == [
        AlertKind.DETECTION,
        AlertKind.BLOCKED,
        AlertKind.WOULD_BLOCK,
        AlertKind.RESPONSE,
        AlertKind.AGENT_ERROR,
    ]


def test_detection_fields_are_extracted() -> None:
    alert = parse_batch([detection()], now=NOW).alerts[0]
    assert alert.severity == "critical"
    assert alert.title == "Interactive shell spawned by a network service"
    assert alert.rule_id == "tg-reverse-shell"
    assert alert.source_event == "exec"
    assert alert.mitre_tactics == ["TA0002"]
    assert alert.fields["exe"] == "/usr/bin/bash"


def test_blocked_event_gets_a_readable_title() -> None:
    alert = parse_batch([blocked()], now=NOW).alerts[0]
    assert alert.title == "egress blocked: evil.example"
    assert alert.severity == "warning"


@pytest.mark.parametrize(
    "record",
    [
        "a string",
        42,
        None,
        [],
        {},
        {"timestamp": "2026-11-16T12:00:00Z", "level": "info", "message": "x"},  # no hostname
        {"timestamp": "2026-11-16T12:00:00Z", "level": "info", "message": "x", "hostname": "  "},
        {"timestamp": 12345, "level": "info", "message": "x", "hostname": "h"},
        {"timestamp": "2026-11-16T12:00:00Z", "level": None, "message": "x", "hostname": "h"},
    ],
)
def test_malformed_records_are_counted_not_raised(record: object) -> None:
    batch = parse_batch([record, detection()], now=NOW)
    assert batch.invalid == 1
    assert len(batch.alerts) == 1


def test_detection_fingerprint_follows_alert_id() -> None:
    first = parse_batch([detection("A", pid=1)], now=NOW).alerts[0]
    replay = parse_batch([detection("A", pid=2)], now=NOW).alerts[0]
    other = parse_batch([detection("B", pid=1)], now=NOW).alerts[0]
    assert first.fingerprint == replay.fingerprint
    assert first.fingerprint != other.fingerprint


def test_unknown_severity_falls_back_to_warning() -> None:
    alert = parse_batch([detection(severity="apocalyptic")], now=NOW).alerts[0]
    assert alert.severity == "warning"


def test_future_and_invalid_timestamps_use_receive_time() -> None:
    future = (NOW + timedelta(days=30)).isoformat()
    alerts = parse_batch([detection("A", timestamp=future), detection("B", timestamp="not-a-date")], now=NOW).alerts
    assert [alert.occurred_at for alert in alerts] == [NOW, NOW]


def test_nanosecond_timestamps_from_go_are_accepted() -> None:
    alert = parse_batch([detection(timestamp="2026-11-16T11:59:58.123456789Z")], now=NOW).alerts[0]
    assert alert.occurred_at == datetime(2026, 11, 16, 11, 59, 58, 123456, tzinfo=UTC)


def test_oversized_record_is_stored_truncated() -> None:
    alert = parse_batch([detection(blob="x" * (MAX_RECORD_BYTES + 1))], now=NOW).alerts[0]
    assert alert.fields == {"message": "detection alert", "truncated_by_manager": True}


def test_list_fields_are_bounded_and_type_checked() -> None:
    alert = parse_batch([detection(tags=["ok", 7, None, "x" * 500] + ["t"] * 200)], now=NOW).alerts[0]
    assert len(alert.tags) <= 64
    assert all(isinstance(tag, str) and len(tag) <= 200 for tag in alert.tags)
    assert parse_batch([detection(tags="not-a-list")], now=NOW).alerts[0].tags == []


def test_heartbeat_ignores_wrongly_typed_fields() -> None:
    parsed = parse_batch(
        [
            heartbeat(
                healthy="yes",
                uptime_seconds=-5,
                policy_sha256="zz",
                detection_rules=True,
                unavailable_hooks="x",
            )
        ],
        now=NOW,
    ).heartbeat
    assert parsed is not None
    assert parsed.healthy is None
    assert parsed.uptime_seconds is None
    assert parsed.policy_sha256 is None
    assert parsed.detection_rules is None
    assert parsed.unavailable_hooks == []


def test_latest_heartbeat_in_a_batch_wins() -> None:
    older = heartbeat(timestamp=(NOW - timedelta(minutes=10)).isoformat(), uptime_seconds=1)
    newer = heartbeat(timestamp=(NOW - timedelta(minutes=1)).isoformat(), uptime_seconds=2)
    parsed = parse_batch([newer, older], now=NOW).heartbeat
    assert parsed is not None
    assert parsed.uptime_seconds == 2
