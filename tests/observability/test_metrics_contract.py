"""Contract test: every soc_* metric must be in _LABEL_ALLOWLIST with matching labels.

Fails the build if a new metric is added outside the allowlist or with an
unlisted label (privacy rule 6 / ADR-0005 §2).
"""

from core.observability.metrics import _LABEL_ALLOWLIST, _METRICS


def test_all_metrics_are_allowlisted() -> None:
    assert set(_METRICS) == set(_LABEL_ALLOWLIST), (
        f"allowlist/metrics mismatch: "
        f"extra in metrics={set(_METRICS) - set(_LABEL_ALLOWLIST)}, "
        f"extra in allowlist={set(_LABEL_ALLOWLIST) - set(_METRICS)}"
    )


def test_no_extra_labels() -> None:
    for name, metric in _METRICS.items():
        actual = frozenset(getattr(metric, "_labelnames", ()))
        allowed = _LABEL_ALLOWLIST[name]
        assert actual == allowed, f"'{name}': labels {actual!r} != allowlist {allowed!r}"
