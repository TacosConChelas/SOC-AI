"""System prompt loaders and injection neutralization."""

import hashlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

from core.contracts.event import UnifiedEvent
from core.contracts.triage import TriageContext

_PROMPT_FILE = Path(__file__).parent / "system.txt"

# Byte caps before assembly (decisions.md task 19) and the context window they are sized for.
# Ollama silently drops the START of an over-long prompt — i.e. the system prompt. Budget measured
# with the pinned Foundation-Sec-1.1 tokenizer: system ~2.3k tokens + event <= 8192 B (worst case
# 1 token/byte) + context <= 1024 B + output ~1.3k  ->  ~12k. KV cache at 16k is ~2 GB on the L4.
NUM_CTX = 16384
EVENT_MAX_BYTES = 8192
CONTEXT_MAX_BYTES = 1024
_TRUNCATED = "[truncated]"
# Free-text event fields that may be cut after `summary`; identifiers never are.
_TRUNCATABLE = ("signature", "http_url", "http_user_agent", "dns_query", "process", "file_path", "username")

_ZW_RE = re.compile(r"[­​-‏⁠-⁤﻿]")
_SPACE_RE = re.compile(r" {2,}")

_INJECTION_PHRASES: list[str] = [
    "ignore previous instructions",
    "ignore all instructions",
    "disregard previous instructions",
    "disregard all instructions",
    "you are now ",
    "new instructions:",
    "override instructions",
    "<|system|>",
    "<|user|>",
    "<|assistant|>",
    "<|im_start|>",
    "<|im_end|>",
    "[system]",
    "[user]",
    "[assistant]",
    "### system",
    "### user",
    "### assistant",
    "<|end_of_text|>",
    # Block delimiters of build_user_message: a payload must never close its own block.
    "<alert_data>",
    "</alert_data>",
    "<context>",
    "</context>",
]

_WINDOW = 64


def _neutralize(text: str) -> str:
    """Canonical 64-char lookahead: replace injection triggers with [neutralized].

    Handles case, fullwidth (via NFKC), zero-width chars, and inter-character
    whitespace obfuscation by collapsing spaces within each lookahead window.
    """
    # Irreversible canonical transform: strip zero-width, NFKC-normalize, collapse spaces
    text = _ZW_RE.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    text = _SPACE_RE.sub(" ", text)

    out: list[str] = []
    i = 0
    n = len(text)
    phrase_stripped = [p.replace(" ", "") for p in _INJECTION_PHRASES]
    while i < n:
        window_nsp = text[i : i + _WINDOW].lower().replace(" ", "")
        matched = False
        hit_nsp_len = 0
        for stripped in phrase_stripped:
            if window_nsp.startswith(stripped):
                matched = True
                hit_nsp_len = len(stripped)
                break
        if not matched:
            out.append(text[i])
            i += 1
        else:
            out.append("[neutralized]")
            consumed = 0
            while i < n and consumed < hit_nsp_len:
                if text[i] != " ":
                    consumed += 1
                i += 1
    return "".join(out)


def load_system_prompt() -> str:
    return _PROMPT_FILE.read_text(encoding="utf-8")


def system_prompt_sha256() -> str:
    return hashlib.sha256(load_system_prompt().encode("utf-8")).hexdigest()


def _dumps(data: dict[str, Any]) -> str:
    # Byte-identical to model_dump_json(exclude_none=True) — compact, UTF-8, no escaping of non-ASCII.
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def _nbytes(data: dict[str, Any]) -> int:
    return len(_dumps(data).encode("utf-8"))


def _cut(text: str, excess: int) -> str:
    """Drop at least `excess` serialized bytes from text, marking the cut.

    JSON escaping only ever enlarges a char, so removing N raw bytes removes >= N serialized
    bytes; a single cut is enough. Never splits a UTF-8 sequence.
    """
    raw = text.encode("utf-8")
    keep = max(len(raw) - excess - len(_TRUNCATED), 0)
    return raw[:keep].decode("utf-8", errors="ignore") + _TRUNCATED


def truncate_event_json(event: UnifiedEvent) -> str:
    """Serialize the event within EVENT_MAX_BYTES, deterministically (decisions.md task 19).

    Order: drop `fields`, then cut `summary`, then cut the remaining free-text fields longest
    first. Identifiers are never touched, so the operator can always trace the event.
    """
    data = event.model_dump(mode="json", exclude_none=True)
    if _nbytes(data) <= EVENT_MAX_BYTES:
        return _dumps(data)
    data.pop("fields", None)
    rest = sorted((k for k in _TRUNCATABLE if k in data), key=lambda k: -len(data[k].encode("utf-8")))
    for key in ("summary", *rest):
        excess = _nbytes(data) - EVENT_MAX_BYTES
        if excess <= 0:
            break
        data[key] = _cut(data[key], excess)
    if _nbytes(data) > EVENT_MAX_BYTES:
        raise ValueError(f"event {event.event_id} exceeds {EVENT_MAX_BYTES} B even after truncation")
    return _dumps(data)


def build_user_message(event: UnifiedEvent, context: TriageContext) -> str:
    """Single assembler of the user message for training AND inference (hard rule 5).

    Takes the models, not JSON strings, so serialization and byte caps cannot drift
    between the dataset builder and the classify node.
    """
    event_json = truncate_event_json(event)
    context_json = context.model_dump_json()
    if len(context_json.encode("utf-8")) > CONTEXT_MAX_BYTES:
        # Code-derived: oversize is a bug upstream, never truncated (task 19).
        raise ValueError(f"context exceeds {CONTEXT_MAX_BYTES} B ({len(context_json.encode('utf-8'))})")
    return f"<alert_data>\n{_neutralize(event_json)}\n</alert_data>\n<context>\n{_neutralize(context_json)}\n</context>"
