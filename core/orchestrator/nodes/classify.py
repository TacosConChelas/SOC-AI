"""Classify node — Ollama LLM client + retry/dead-letter logic."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from pydantic import ValidationError

from core.contracts.deadletter import DeadLetterReason, DeadLetterRecord
from core.contracts.event import UnifiedEvent
from core.contracts.triage import TriageContext, TriageModelOutput
from core.observability.metrics import CLASSIFY_TOTAL
from core.orchestrator.prompts import NUM_CTX, build_user_message, load_system_prompt

_MAX_RETRIES = 2
_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "soc-ai-triage")


class OllamaUnavailableError(Exception):
    """Raised when the Ollama service cannot be reached."""


@dataclass
class ClassifyOutcome:
    model_output: TriageModelOutput | None
    dead_letter: DeadLetterRecord | None


class OllamaClient:
    """Thin httpx wrapper for Ollama /api/chat — no SDK dependency."""

    def __init__(
        self,
        base_url: str = _OLLAMA_URL,
        model: str = _OLLAMA_MODEL,
        timeout: float = 60.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    def chat(self, system: str, user: str, temperature: float = 0.1) -> str:
        """Send a chat request; return raw text content. Raises OllamaUnavailableError on network failure.

        format: "json" guarantees syntactic JSON without masking which fields the model gets
        wrong — a stricter grammar mask was rejected (decisions.md task 25) because it would
        hide model degradation that ADR-0004 §2 wants visible via the parse_failure path.
        """
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "format": "json",
            "options": {"temperature": temperature, "num_ctx": NUM_CTX},
            "stream": False,
        }
        try:
            resp = httpx.post(
                f"{self._base_url}/api/chat",
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return str(resp.json()["message"]["content"])
        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as exc:
            raise OllamaUnavailableError(str(exc)) from exc


def classify_event(
    event: UnifiedEvent,
    context: TriageContext,
    ollama_client: OllamaClient,
) -> ClassifyOutcome:
    """Call Ollama, validate JSON output, retry up to _MAX_RETRIES times.

    Never publishes. Returns ClassifyOutcome with either model_output (success)
    or dead_letter (permanent parse failure).

    OllamaUnavailableError is deliberately NOT caught here — it propagates out
    of the graph so the worker can leave the message unacked and back off
    instead of losing it (ADR-0004 §2: connectivity failures are never a
    dead-letter).
    """
    system_prompt = load_system_prompt()
    user_msg = build_user_message(event, context)

    raw: str | None = None
    error_types: list[str] = []

    for attempt in range(_MAX_RETRIES):
        # First attempt at 0.1; retries at 0.2 — a deterministic resend at the same
        # temperature can't change the result (decisions.md task 25).
        temperature = 0.1 if attempt == 0 else 0.2
        raw = ollama_client.chat(system_prompt, user_msg, temperature=temperature)

        try:
            output = TriageModelOutput.model_validate_json(raw)
            CLASSIFY_TOTAL.labels(outcome="success").inc()
            return ClassifyOutcome(model_output=output, dead_letter=None)
        except ValidationError as exc:
            error_types = [type(e).__name__ for e in exc.errors()]
            # no feedback — identical prompt on retry (hard rule: no verbatim echo)

    # exhausted retries
    detail = f"ValidationError after {_MAX_RETRIES} attempts: {', '.join(dict.fromkeys(error_types))}"[:500]
    CLASSIFY_TOTAL.labels(outcome="parse_failure").inc()
    return ClassifyOutcome(
        model_output=None,
        dead_letter=DeadLetterRecord(
            alert_id=event.source_alert_id,
            event_id=event.event_id,
            source_module=event.source_module,
            sensor=event.sensor,
            severity=event.severity_hint,
            reason=DeadLetterReason.PARSE_FAILURE,
            retry_count=_MAX_RETRIES,
            dead_lettered_at=datetime.now(UTC),
            detail=detail or "ValidationError: unknown",
        ),
    )
