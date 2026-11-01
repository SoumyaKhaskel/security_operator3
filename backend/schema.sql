PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS datasets (
    dataset_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    provenance TEXT NOT NULL,
    source_uri TEXT,
    sha256 TEXT,
    event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    created_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'available'
);

CREATE TABLE IF NOT EXISTS ingestion_batches (
    batch_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
    source_name TEXT NOT NULL,
    source_format TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    accepted_count INTEGER NOT NULL DEFAULT 0 CHECK (accepted_count >= 0),
    rejected_count INTEGER NOT NULL DEFAULT 0 CHECK (rejected_count >= 0),
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS original_events (
    event_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
    batch_id TEXT REFERENCES ingestion_batches(batch_id),
    event_time TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    source_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    normalized_event TEXT NOT NULL,
    raw_event TEXT NOT NULL,
    event_sha256 TEXT NOT NULL,
    provenance TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_original_events_dataset_time ON original_events(dataset_id, event_time);
CREATE INDEX IF NOT EXISTS idx_original_events_dataset_severity ON original_events(dataset_id, severity);
CREATE INDEX IF NOT EXISTS idx_original_events_category ON original_events(dataset_id, category);
CREATE UNIQUE INDEX IF NOT EXISTS idx_original_events_dataset_hash ON original_events(dataset_id, event_sha256);
CREATE TRIGGER IF NOT EXISTS prevent_original_events_update
BEFORE UPDATE ON original_events
BEGIN
    SELECT RAISE(ABORT, 'original events are immutable');
END;
CREATE TRIGGER IF NOT EXISTS prevent_original_events_delete
BEFORE DELETE ON original_events
BEGIN
    SELECT RAISE(ABORT, 'original events are immutable');
END;

CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,
    dataset_id TEXT NOT NULL REFERENCES datasets(dataset_id),
    requested_by TEXT NOT NULL,
    status TEXT NOT NULL,
    agent_config_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_investigations_dataset_time ON investigations(dataset_id, started_at);

CREATE TABLE IF NOT EXISTS agent_findings (
    finding_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    event_id TEXT NOT NULL REFERENCES original_events(event_id),
    agent_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    title TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence_refs TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hunting_queries (
    query_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    query_text TEXT NOT NULL,
    result_count INTEGER NOT NULL DEFAULT 0 CHECK (result_count >= 0),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS response_proposals (
    proposal_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    finding_id TEXT REFERENCES agent_findings(finding_id),
    action_type TEXT NOT NULL,
    parameters TEXT NOT NULL,
    rationale TEXT NOT NULL,
    policy_status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_records (
    approval_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES response_proposals(proposal_id),
    reviewer TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'denied', 'modified')),
    modified_parameters TEXT,
    comment TEXT NOT NULL DEFAULT '',
    decided_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_approval_records_single_final_decision
    ON approval_records(proposal_id) WHERE decision IN ('approved', 'denied');

CREATE TABLE IF NOT EXISTS execution_records (
    execution_id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES response_proposals(proposal_id),
    approval_id TEXT NOT NULL REFERENCES approval_records(approval_id),
    mode TEXT NOT NULL CHECK (mode = 'simulation'),
    idempotency_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    outcome TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_records_one_per_approval
    ON execution_records(proposal_id, approval_id);

CREATE TABLE IF NOT EXISTS processed_events (
    processed_event_id TEXT PRIMARY KEY,
    original_event_id TEXT NOT NULL REFERENCES original_events(event_id),
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    finding_id TEXT REFERENCES agent_findings(finding_id),
    execution_id TEXT REFERENCES execution_records(execution_id),
    status TEXT NOT NULL,
    before_state TEXT NOT NULL,
    after_state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (original_event_id, investigation_id, execution_id)
);
CREATE INDEX IF NOT EXISTS idx_processed_events_original ON processed_events(original_event_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    audit_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    dataset_id TEXT REFERENCES datasets(dataset_id),
    details TEXT NOT NULL DEFAULT '{}',
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time ON audit_logs(occurred_at);

CREATE TABLE IF NOT EXISTS feedback_records (
    feedback_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id),
    finding_id TEXT REFERENCES agent_findings(finding_id),
    proposal_id TEXT REFERENCES response_proposals(proposal_id),
    analyst TEXT NOT NULL,
    decision TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ground_truth_labels (
    label_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES original_events(event_id),
    label TEXT NOT NULL,
    source TEXT NOT NULL,
    UNIQUE (event_id, label)
);
