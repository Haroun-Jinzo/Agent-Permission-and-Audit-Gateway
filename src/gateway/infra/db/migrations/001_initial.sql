-- Agent Permission and Audit Gateway: data model, version 1
-- SQLite-compatible. PostgreSQL notes are in docs/data-model.md.
-- Conventions: ids are UUID text, timestamps are UTC text in the form
-- YYYY-MM-DDTHH:MM:SS.ffffffZ, enums are enforced with CHECK constraints.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- Humans: admins, approvers, auditors, and their keys (the trust store)
-- ---------------------------------------------------------------------
CREATE TABLE principals (
  principal_id TEXT PRIMARY KEY,
  kind         TEXT NOT NULL CHECK (kind IN ('admin','approver','auditor')),
  name         TEXT NOT NULL UNIQUE,
  status       TEXT NOT NULL CHECK (status IN ('active','suspended','revoked')),
  created_at   TEXT NOT NULL
);

CREATE TABLE principal_keys (
  key_id        TEXT PRIMARY KEY,
  principal_id  TEXT NOT NULL REFERENCES principals(principal_id),
  purpose       TEXT NOT NULL CHECK (purpose IN ('approval_signing','admin_auth')),
  algorithm     TEXT NOT NULL CHECK (algorithm = 'ed25519'),
  public_key    TEXT NOT NULL,                 -- 64 hex characters
  status        TEXT NOT NULL CHECK (status IN ('active','revoked')),
  valid_from    TEXT NOT NULL,
  valid_until   TEXT,
  registered_by TEXT NOT NULL REFERENCES principals(principal_id),
  registered_at TEXT NOT NULL,
  revoked_at    TEXT,
  CHECK (length(public_key) = 64)
);

-- ---------------------------------------------------------------------
-- Agent identity
-- ---------------------------------------------------------------------
CREATE TABLE roles (
  role_id               TEXT PRIMARY KEY,
  name                  TEXT NOT NULL UNIQUE,
  description           TEXT,
  rate_limit_per_min    INTEGER NOT NULL CHECK (rate_limit_per_min > 0),
  max_concurrent        INTEGER NOT NULL CHECK (max_concurrent > 0),
  max_pending_approvals INTEGER NOT NULL CHECK (max_pending_approvals >= 0)
);

CREATE TABLE agents (
  agent_id                TEXT PRIMARY KEY,
  name                    TEXT NOT NULL UNIQUE,
  role_id                 TEXT NOT NULL REFERENCES roles(role_id),
  status                  TEXT NOT NULL CHECK (status IN ('active','suspended','revoked')),
  secret_hash             TEXT NOT NULL,       -- SHA-256 of a 256-bit random secret
  secret_created_at       TEXT NOT NULL,
  prev_secret_hash        TEXT,                -- rotation overlap
  prev_secret_valid_until TEXT,
  rate_limit_per_min      INTEGER CHECK (rate_limit_per_min IS NULL OR rate_limit_per_min > 0),
  max_concurrent          INTEGER CHECK (max_concurrent IS NULL OR max_concurrent > 0),
  max_pending_approvals   INTEGER CHECK (max_pending_approvals IS NULL OR max_pending_approvals >= 0),
  created_by              TEXT NOT NULL REFERENCES principals(principal_id),
  created_at              TEXT NOT NULL,
  revoked_at              TEXT
);

-- ---------------------------------------------------------------------
-- Tasks and the labels they accumulate (task-level taint)
-- ---------------------------------------------------------------------
CREATE TABLE tasks (
  task_id    TEXT PRIMARY KEY,
  agent_id   TEXT NOT NULL REFERENCES agents(agent_id),
  status     TEXT NOT NULL CHECK (status IN ('open','closed')),
  started_by TEXT NOT NULL REFERENCES principals(principal_id),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  closed_at  TEXT
);

CREATE TABLE task_labels (
  task_id          TEXT NOT NULL REFERENCES tasks(task_id),
  label            TEXT NOT NULL CHECK (label IN ('PUBLIC','CONFIDENTIAL','SECRET','UNTRUSTED')),
  added_at         TEXT NOT NULL,
  source_call_hash TEXT NOT NULL,
  PRIMARY KEY (task_id, label)
);

-- ---------------------------------------------------------------------
-- Tool manifests and policies (versioned, content-hashed documents)
-- ---------------------------------------------------------------------
CREATE TABLE tool_manifests (
  tool         TEXT NOT NULL,
  version      INTEGER NOT NULL CHECK (version > 0),
  status       TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
  content      TEXT NOT NULL,                  -- the manifest document
  content_hash TEXT NOT NULL,                  -- SHA-256 hex of content
  created_by   TEXT NOT NULL REFERENCES principals(principal_id),
  created_at   TEXT NOT NULL,
  activated_at TEXT,
  PRIMARY KEY (tool, version)
);
CREATE UNIQUE INDEX one_active_manifest_per_tool
  ON tool_manifests(tool) WHERE status = 'active';

CREATE TABLE policies (
  name         TEXT NOT NULL,
  version      INTEGER NOT NULL CHECK (version > 0),
  status       TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
  content      TEXT NOT NULL,                  -- the policy document
  content_hash TEXT NOT NULL,                  -- SHA-256 hex of content
  created_by   TEXT NOT NULL REFERENCES principals(principal_id),
  created_at   TEXT NOT NULL,
  activated_at TEXT,
  PRIMARY KEY (name, version)
); 
-- Version 1 allows exactly one active policy document at a time.
CREATE UNIQUE INDEX one_active_policy ON policies(status) WHERE status = 'active';

-- ---------------------------------------------------------------------
-- Approvals (state machine in docs/approval-state-machine.md)
-- ---------------------------------------------------------------------
CREATE TABLE approvals (
  approval_id        TEXT PRIMARY KEY,
  agent_id           TEXT NOT NULL REFERENCES agents(agent_id),
  task_id            TEXT NOT NULL REFERENCES tasks(task_id),
  call_hash          TEXT NOT NULL,
  tool               TEXT NOT NULL,
  risk               TEXT NOT NULL CHECK (risk IN ('low','medium','high','critical')),
  summary            TEXT NOT NULL,
  canonical_call     TEXT,                     -- full call for the approver, nulled after retention
  status             TEXT NOT NULL CHECK (status IN
                       ('PENDING','APPROVED','REJECTED','EXPIRED','CONSUMED','CANCELLED')),
  required_approvals INTEGER NOT NULL DEFAULT 1 CHECK (required_approvals = 1),
  created_at         TEXT NOT NULL,
  decision_deadline  TEXT NOT NULL,
  decided_at         TEXT,
  decided_by         TEXT REFERENCES principals(principal_id),
  decision_key_id    TEXT REFERENCES principal_keys(key_id),
  signature          TEXT,                     -- 128 hex characters
  use_deadline       TEXT,
  consumed_at        TEXT,
  cancelled_reason   TEXT,
  CHECK (length(call_hash) = 64),
  CHECK ((status IN ('APPROVED','REJECTED','CONSUMED') AND decided_at IS NOT NULL
            AND decided_by IS NOT NULL AND signature IS NOT NULL)
         OR status IN ('PENDING','EXPIRED','CANCELLED')),
  CHECK (status <> 'CONSUMED' OR consumed_at IS NOT NULL),
  CHECK (status <> 'CANCELLED' OR cancelled_reason IS NOT NULL)
);
-- At most one open approval per agent and exact call.
CREATE UNIQUE INDEX one_open_approval
  ON approvals(agent_id, call_hash) WHERE status IN ('PENDING','APPROVED');
CREATE INDEX approvals_by_status ON approvals(status, decision_deadline);

-- ---------------------------------------------------------------------
-- Audit log: one hash chain per agent, plus one chain named 'system'
-- ---------------------------------------------------------------------
CREATE TABLE audit_entries (
  chain_id   TEXT NOT NULL,                    -- agent_id, or 'system'
  seq        INTEGER NOT NULL CHECK (seq > 0),
  ts         TEXT NOT NULL,
  kind       TEXT NOT NULL CHECK (kind IN (
               'REJECTED','INTENT','OUTCOME','RECOVERY',
               'APPROVAL_PENDING','APPROVAL_DECISION','APPROVAL_CONSUMED',
               'APPROVAL_DENIED','APPROVAL_EXPIRED','APPROVAL_CANCELLED',
               'ADMIN_ACTION','ANCHOR')),
  call_hash  TEXT,                             -- copied from body for lookups
  approval_id TEXT,                            -- copied from body for lookups
  body       TEXT NOT NULL,                    -- the exact canonical JSON that was hashed
  prev_hash  TEXT NOT NULL CHECK (length(prev_hash) = 64),
  entry_hash TEXT NOT NULL CHECK (length(entry_hash) = 64),
  PRIMARY KEY (chain_id, seq)
);
CREATE INDEX audit_by_call ON audit_entries(call_hash);
CREATE INDEX audit_by_approval ON audit_entries(approval_id);

-- Application-level guard only. It does not stop someone with file access (threat T8).
CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries
BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END;
CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries
BEGIN SELECT RAISE(ABORT, 'audit entries are append-only'); END;

CREATE TABLE audit_heads (
  chain_id   TEXT PRIMARY KEY,
  head_seq   INTEGER NOT NULL CHECK (head_seq >= 0),
  head_hash  TEXT NOT NULL CHECK (length(head_hash) = 64),
  updated_at TEXT NOT NULL
);

CREATE TABLE anchors (
  anchor_id   INTEGER PRIMARY KEY AUTOINCREMENT,
  chain_id    TEXT NOT NULL,
  head_seq    INTEGER NOT NULL CHECK (head_seq > 0),
  head_hash   TEXT NOT NULL CHECK (length(head_hash) = 64),
  anchored_at TEXT NOT NULL,
  signature   TEXT NOT NULL CHECK (length(signature) = 128),
  anchor_ref  TEXT NOT NULL,                   -- where it was published (for example a Git commit)
  UNIQUE (chain_id, head_seq)
);
CREATE TRIGGER anchors_no_update BEFORE UPDATE ON anchors
BEGIN SELECT RAISE(ABORT, 'anchors are append-only'); END;
CREATE TRIGGER anchors_no_delete BEFORE DELETE ON anchors
BEGIN SELECT RAISE(ABORT, 'anchors are append-only'); END;
