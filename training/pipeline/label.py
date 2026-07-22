"""Label mapping: Kaggle taxonomy → Classification + rubric-based deterministic labeling.

Two paths to ground truth:
  1. map_kaggle_label(native)   — maps public dataset native labels to our 3-class taxonomy.
  2. apply_rubric(event, ctx)   — deterministic label for owner-written manual examples
                                  where a rubric rule applies unambiguously.

If a case falls outside both paths, extend the rubric first, then label.
"""

from __future__ import annotations

from core.contracts.event import UnifiedEvent
from core.contracts.triage import Classification, TriageContext

# ─── Kaggle label mapping (Labeling_Rubric §Kaggle taxonomy mapping) ─────────

# Maps normalized kaggle label strings (lowercased/stripped) → our taxonomy.
# EXCLUDED rows must be dropped before building the dataset.
_KAGGLE_MAP: dict[str, Classification | None] = {
    # noise
    "false positive": Classification.NOISE,
    "benign": Classification.NOISE,
    "false_positive": Classification.NOISE,
    "fp": Classification.NOISE,
    "0": Classification.NOISE,
    # informational
    "true positive, low priority": Classification.INFORMATIONAL,
    "true positive low priority": Classification.INFORMATIONAL,
    "low priority": Classification.INFORMATIONAL,
    "informational": Classification.INFORMATIONAL,
    "info": Classification.INFORMATIONAL,
    "1": Classification.INFORMATIONAL,
    # alert
    "true positive, med/high priority": Classification.ALERT,
    "true positive, medium/high priority": Classification.ALERT,
    "true positive med/high priority": Classification.ALERT,
    "true positive, high priority": Classification.ALERT,
    "true positive, medium priority": Classification.ALERT,
    "true positive": Classification.ALERT,
    "alert": Classification.ALERT,
    "malicious": Classification.ALERT,
    "attack": Classification.ALERT,
    "2": Classification.ALERT,
    # excluded (ambiguous / unlabeled) — return None
    "ambiguous": None,
    "unlabeled": None,
    "unknown": None,
    "": None,
}


def map_kaggle_label(native: str) -> Classification | None:
    """Return Classification for a Kaggle native label, or None to exclude.

    None means the row must be dropped — ground truth cannot be trusted.
    """
    key = native.lower().strip()
    if key in _KAGGLE_MAP:
        return _KAGGLE_MAP[key]
    # Any row whose mapping isn't listed is ambiguous — exclude it.
    return None


# ─── Rubric-based deterministic label ────────────────────────────────────────
#
# Applies the signal-visible boundary rules from Labeling_Rubric.md.
# Only covers cases where the rubric yields an unambiguous label from
# fields visible at inference time. Falls back to None (needs human label).


def apply_rubric(event: UnifiedEvent, ctx: TriageContext) -> Classification | None:
    """Deterministic label from rubric rules, or None if the case is ambiguous.

    Only use signals available at inference time (event fields + frozen context).
    Do NOT use response/flow data that is not in these structs.
    """
    # ── Host integrity: FIM / rootcheck (the default is alert) ──────────────
    if event.event_type in ("syscheck", "rootcheck", "fim"):
        sensitive_paths = ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "sshd_config", "crontab")
        if event.file_path and any(p in event.file_path for p in sensitive_paths):
            return Classification.ALERT
        # Repeated identical FIM from known-noisy path → noise
        if event.file_path and any(p in event.file_path for p in ("/var/lib/dpkg/", "/var/cache/apt/")):
            return Classification.NOISE
        # Other watched-path changes → informational
        return Classification.INFORMATIONAL

    # ── Authorized scanner → informational ───────────────────────────────────
    if ctx.src_in_allowlist:
        return Classification.INFORMATIONAL

    # ── Scanning / NIDS ──────────────────────────────────────────────────────
    if event.event_type in ("NIDS", "ids", "suricata"):
        persistent = ctx.events_last_10min >= 3 or ctx.related_events_24h >= 5
        campaign = ctx.distinct_rules_from_src_24h >= 2
        if persistent or campaign:
            return Classification.ALERT
        # Single-burst probe from unknown source → noise
        if not ctx.src_ip_seen_before and ctx.related_events_24h == 0:
            return Classification.NOISE

    # ── Authentication ────────────────────────────────────────────────────────
    sig = (event.signature or event.rule_id or "").lower()
    if "auth" in sig or "login" in sig or "ssh" in sig or "brute" in sig:
        # Success after failure burst = always alert (T1110 success)
        if "success" in sig or "accepted" in sig:
            if ctx.related_events_24h >= 4:
                return Classification.ALERT
            return Classification.INFORMATIONAL
        # Failure burst
        if ctx.related_events_24h >= 4:
            return Classification.ALERT
        return Classification.INFORMATIONAL

    # ── Adversarial payload detected by neutralizer (signature check) ─────────
    if event.signature and "[neutralized]" in event.signature:
        return Classification.ALERT

    return None  # ambiguous — requires human label or teacher model
