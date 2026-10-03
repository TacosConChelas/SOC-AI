-- SOC-AI core schema
-- Apply once: psql -d <db> -f sql/schema.sql

CREATE TABLE IF NOT EXISTS triage_records (
    id               BIGSERIAL        PRIMARY KEY,
    alert_id         TEXT             NOT NULL,
    event_id         TEXT             NOT NULL,
    classification   TEXT             NOT NULL,
    confidence       REAL             NOT NULL,
    severity         TEXT             NOT NULL,
    summary          TEXT             NOT NULL,
    incident_group_key TEXT           NOT NULL,
    context          JSONB            NOT NULL,
    suggested_actions JSONB           NOT NULL,
    rationale        TEXT             NOT NULL,
    triaged_at       TIMESTAMPTZ      NOT NULL
);

-- finding_seen_before lookup (enrich node, ADR-0011 §4) keys on alert_id.
CREATE INDEX IF NOT EXISTS triage_records_alert_id_idx ON triage_records (alert_id);

-- Collector checkpoint: one row, updated in-place on each poll cycle.
CREATE TABLE IF NOT EXISTS collector_checkpoint (
    id             INTEGER     PRIMARY KEY DEFAULT 1,
    last_alert_id  TEXT,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT one_row CHECK (id = 1)
);
INSERT INTO collector_checkpoint (id, last_alert_id, updated_at)
    VALUES (1, NULL, NOW())
    ON CONFLICT (id) DO NOTHING;
