"""ISSUE-223: verify RedactingFormatter is installed on the app logger
and that log output never contains credential-shaped patterns."""

from __future__ import annotations

import io
import logging

import pytest

from app.core.sanitization import (
    REDACTED,
    RedactingFormatter,
    configure_app_logging,
    redact_sensitive_text,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _cleanup_app_logger() -> None:
    """Restore the ``app`` logger to a pristine state after every test (ISSUE-223 P2).

    Exception-safe teardown: even when an assertion fails mid-test the cleanup
    still runs, preventing handler leak and stale ``_REDACTING_LOGGING_CONFIGURED``
    flag from polluting downstream tests.
    """
    yield
    import app.core.sanitization as mod

    logging.getLogger("app").handlers.clear()
    mod._REDACTING_LOGGING_CONFIGURED = False


# ── Unit: RedactingFormatter ────────────────────────────────────────────────


_SENSITIVE_SAMPLES = [
    # GitHub / OpenAI / Slack / AWS token patterns from _KNOWN_TOKEN_RE
    ("ghp_1234567890abcdefghijklmnopqrstuv", "ghp_"),
    ("sk-proj-abcdefghijklmnopqrstuvwxyz", "sk-proj-"),
    ("xoxb-1234567890-abcdefghijkl", "xoxb-"),
    ("AKIA1234567890ABCDEF", "AKIA"),
    # Secret assignment patterns from _SECRET_ASSIGNMENT_RE
    ("token=sk-abc1234567890defghij", "sk-abc"),
    ("password=super-secret-password-123", "super-secret"),
    ('api_key="leaked-key-value-here"', "leaked-key"),
    # Auth-scheme patterns from _AUTH_SCHEME_RE
    ("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghij", "Bearer eyJ"),
    ("authorization: basic dXNlcjpwYXNzd29yZA==", "basic dXNl"),
    # URL credential patterns from _URL_CREDENTIAL_RE
    ("endpoint=https://admin:hunter2@host.internal/api", "admin:hunter2"),
    # JWT pattern from _JWT_RE
    ("jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature", "eyJhbGci"),
    # Sensitive header from _SENSITIVE_HEADER_RE
    ("authorization: Bearer leaked-token-value-here", "leaked-token"),
    # Secret assignment without quotes (bare value)
    ("session_id=abc123super-secret-value", "abc123"),
]


@pytest.mark.parametrize("sample,needle", _SENSITIVE_SAMPLES)
def test_redact_sensitive_text_strips_credential_patterns(sample: str, needle: str) -> None:
    """Every sensitive sample must have its credential portion removed."""
    result = redact_sensitive_text(sample)
    assert needle not in result, (
        f"Expected {needle!r} to be redacted from {sample!r}, got {result!r}"
    )
    assert REDACTED in result


def test_redact_sensitive_text_preserves_benign_content() -> None:
    """Benign log messages should pass through unchanged."""
    benign = [
        "event evt-1234 transitioned to triaging",
        "action act-5678 completed successfully",
        "outbox obx-9abc delivered to mock_xdr",
        "lease renewed for worker outbox-worker-1",
        "Connected to PostgreSQL at localhost:5432",
    ]
    for message in benign:
        assert redact_sensitive_text(message) == message, (
            f"Benign message should not be altered: {message!r}"
        )


# ── Integration: logger output via RedactingFormatter ───────────────────────


def _capture_logger_output(
    logger_name: str,
    messages: list[str],
) -> str:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(RedactingFormatter("%(message)s"))
    logger = logging.getLogger(logger_name)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    try:
        for msg in messages:
            logger.info(msg)
    finally:
        logger.removeHandler(handler)
        logger.propagate = True
    return stream.getvalue()


def test_logger_output_excludes_sensitive_patterns() -> None:
    """ISSUE-223: log records must not contain credential patterns."""
    output = _capture_logger_output(
        "app.test.redaction",
        [
            "token=sk-abc1234567890defghij leaked in log",
            "Authorization: Bearer my-secret-bearer-token",
            "password=super-secret-password-123",
            "api_key=ghp_1234567890abcdefghijklmnopqrstuv",
            "Normal operational message",
        ],
    )
    assert "sk-abc1234567890defghij" not in output
    assert "my-secret-bearer-token" not in output
    assert "super-secret-password-123" not in output
    assert "ghp_1234567890abcdefghijklmnopqrstuv" not in output
    assert "Normal operational message" in output
    assert REDACTED in output


def test_logger_output_preserves_operational_details() -> None:
    """Operational identifiers and status values must survive redaction."""
    output = _capture_logger_output(
        "app.test.redaction",
        [
            "event_id=evt-20260807-001 transitioned to triaging",
            "action_id=act-20260807-002 status=EXECUTING",
            "outbox_id=obx-3c4d5e6f delivery_status=DELIVERED",
            "writeback_id=wbk-a1b2c3d4 status=CONFIRMED",
        ],
    )
    assert "evt-20260807-001" in output
    assert "triaging" in output
    assert "act-20260807-002" in output
    assert "EXECUTING" in output
    assert "obx-3c4d5e6f" in output
    assert "DELIVERED" in output
    assert "wbk-a1b2c3d4" in output
    assert "CONFIRMED" in output


# ── configure_app_logging ───────────────────────────────────────────────────


def test_configure_app_logging_is_idempotent() -> None:
    """Repeated calls must not add duplicate handlers (ISSUE-223)."""
    app_logger = logging.getLogger("app")
    # Clear any handlers set by previous tests
    app_logger.handlers.clear()

    handler_count_before = len(app_logger.handlers)

    # Monkey-patch the global guard so we can test idempotency
    import app.core.sanitization as mod

    mod._REDACTING_LOGGING_CONFIGURED = False
    configure_app_logging()
    first_count = len(app_logger.handlers)

    # Second call must be a no-op
    configure_app_logging()
    second_count = len(app_logger.handlers)

    assert handler_count_before == 0
    assert first_count == 1, f"Expected 1 handler, got {first_count}"
    assert second_count == 1, f"Second call added a handler: {second_count - first_count}"


def test_configure_app_logging_handler_uses_redacting_formatter() -> None:
    """The handler installed by configure_app_logging must carry RedactingFormatter."""
    app_logger = logging.getLogger("app")
    app_logger.handlers.clear()

    import app.core.sanitization as mod

    mod._REDACTING_LOGGING_CONFIGURED = False
    configure_app_logging()

    assert len(app_logger.handlers) >= 1
    formatter = app_logger.handlers[0].formatter
    assert isinstance(formatter, RedactingFormatter), (
        f"Expected RedactingFormatter, got {type(formatter).__name__}"
    )


def test_configure_app_logging_adds_handler_when_existing_handler_lacks_redacting() -> None:
    """When another handler is already present but without RedactingFormatter,
    configure_app_logging must still install a RedactingFormatter handler.

    This prevents a stuck state where the ``_REDACTING_LOGGING_CONFIGURED``
    guard is set to True but no redacting handler was actually installed
    (ISSUE-223 follow-up).
    """
    app_logger = logging.getLogger("app")
    app_logger.handlers.clear()

    import app.core.sanitization as mod

    # Simulate a pre-existing handler without RedactingFormatter
    plain_handler = logging.StreamHandler()
    plain_handler.setFormatter(logging.Formatter("%(message)s"))
    app_logger.addHandler(plain_handler)

    mod._REDACTING_LOGGING_CONFIGURED = False
    configure_app_logging()

    redacting_handlers = [
        h for h in app_logger.handlers if isinstance(h.formatter, RedactingFormatter)
    ]
    assert len(redacting_handlers) >= 1, (
        "Expected at least one RedactingFormatter handler to be added "
        "when pre-existing handler lacked it"
    )
    # The original plain handler should still be present
    assert len(app_logger.handlers) >= 2


def test_configure_app_logging_skips_when_redacting_handler_already_present() -> None:
    """When a RedactingFormatter handler already exists, configure_app_logging
    must not add a duplicate (ISSUE-223 follow-up)."""
    app_logger = logging.getLogger("app")
    app_logger.handlers.clear()

    import app.core.sanitization as mod

    # Pre-install a RedactingFormatter handler
    existing = logging.StreamHandler()
    existing.setFormatter(RedactingFormatter("%(message)s"))
    app_logger.addHandler(existing)

    before = len(app_logger.handlers)

    mod._REDACTING_LOGGING_CONFIGURED = False
    configure_app_logging()

    after = len(app_logger.handlers)
    assert after == before, (
        f"configure_app_logging should not add a handler when "
        f"RedactingFormatter is already present (before={before}, after={after})"
    )


# ── Telemetry regression guard ──────────────────────────────────────────────


def test_redacting_formatter_does_not_strip_trace_ids() -> None:
    """Telemetry trace/span IDs (hex, 32-char) must survive redaction.

    OpenTelemetry injects trace-id into log records via a separate
    mechanism (LoggingInstrumentor), not via the formatter pipeline.
    This test asserts that hex identifiers — which look structurally
    similar to some token patterns — are not falsely redacted.
    """
    trace_id = "0af7651916cd43dd8448eb211c80319c"
    span_id = "b7ad6b7169203331"
    message = f"trace_id={trace_id} span_id={span_id} event_id=evt-test-001"
    result = redact_sensitive_text(message)
    assert trace_id in result, f"trace_id {trace_id} should not be redacted"
    assert span_id in result, f"span_id {span_id} should not be redacted"
    assert "evt-test-001" in result
