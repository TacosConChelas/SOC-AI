"""System prompt loaders and injection neutralization."""

import re
import unicodedata
from pathlib import Path

_PROMPT_FILE = Path(__file__).parent / "system.txt"

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


def build_user_message(event_json: str, context_json: str) -> str:
    return f"EVENT:\n{_neutralize(event_json)}\n\nCONTEXT:\n{_neutralize(context_json)}"
