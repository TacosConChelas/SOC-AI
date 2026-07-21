"""Contract test: every soc_* metric must be in _LABEL_ALLOWLIST with matching labels.

Fails the build if a new metric is added outside the allowlist or with an
unlisted label (privacy rule 6 / ADR-0005 §2).
"""

from prometheus_client import Counter, Histogram

import core.observability.metrics as m


def _soc_metrics() -> dict[str, Counter | Histogram]:
    """Return {prometheus_name: metric} for all Counter/Histogram instances in metrics.py.

    Counter._name strips _total; reconstruct full name so keys match _LABEL_ALLOWLIST.
    """
    result: dict[str, Counter | Histogram] = {}
    for v in vars(m).values():
        if isinstance(v, Counter):
            result[v._name + "_total"] = v
        elif isinstance(v, Histogram):
            result[v._name] = v
    return result


def test_all_metrics_are_allowlisted() -> None:
    discovered = set(_soc_metrics())
    allowlisted = set(m._LABEL_ALLOWLIST)
    assert discovered == allowlisted, (
        f"extra in metrics={discovered - allowlisted}, extra in allowlist={allowlisted - discovered}"
    )


def test_no_extra_labels() -> None:
    for name, metric in _soc_metrics().items():
        actual = frozenset(getattr(metric, "_labelnames", ()))
        allowed = m._LABEL_ALLOWLIST[name]
        assert actual == allowed, f"'{name}': labels {actual!r} != allowlist {allowed!r}"
