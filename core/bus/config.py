"""Bus configuration — env-driven, all fields immutable after construction."""

import os
from dataclasses import dataclass, field


@dataclass
class BusConfig:
    redis_url: str = field(
        default_factory=lambda: os.getenv("SOC_REDIS_URL", "redis://localhost:6379")
    )
    events_stream: str = "soc:events"
    deadletter_stream: str = "soc:deadletter"
    consumer_group: str = "soc-workers"
    # socket_timeout_s must be > block_ms / 1000.
    # redis-py 8: socket_timeout=None → TimeoutError on block expiry, crash-looping idle worker.
    # ponytail: 30s > 20s block; raise if someone lowers socket_timeout below block_ms/1000
    block_ms: int = 20_000
    socket_timeout_s: float = 30.0
    claim_min_idle_ms: int = 60_000

    def __post_init__(self) -> None:
        if self.socket_timeout_s <= self.block_ms / 1000:
            raise ValueError(
                f"socket_timeout_s ({self.socket_timeout_s}s) must be greater than "
                f"block_ms ({self.block_ms}ms / 1000 = {self.block_ms / 1000}s)"
            )
