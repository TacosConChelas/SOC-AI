# Stage 1 — install dependencies into /install prefix
FROM python:3.11-slim AS builder
WORKDIR /build
COPY pyproject.toml README.md ./
COPY core/ core/
RUN pip install --no-cache-dir --prefix=/install ".[agent]"

# Stage 2 — minimal runtime image
FROM python:3.11-slim
RUN useradd -r -u 1001 -s /sbin/nologin soc

WORKDIR /app
COPY --from=builder /install /usr/local

# Healthcheck hits /metrics; METRICS_PORT is set per role in compose
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c \
        "import urllib.request, os; urllib.request.urlopen('http://localhost:' + os.getenv('METRICS_PORT', '9108') + '/metrics').read()"

USER soc
ENTRYPOINT ["python", "-m"]
CMD ["core.orchestrator"]
