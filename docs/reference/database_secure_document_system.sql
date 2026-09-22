-- He thong quan ly truy cap tai lieu mat
-- PostgreSQL 15+

BEGIN;

CREATE TYPE user_status AS ENUM ('PENDING', 'ACTIVE', 'LOCKED', 'DISABLED');
CREATE TYPE data_type AS ENUM ('STRING', 'NUMBER', 'BOOLEAN', 'DATE', 'ENUM');
CREATE TYPE attribute_scope AS ENUM ('USER', 'RESOURCE', 'ENVIRONMENT');
CREATE TYPE policy_effect AS ENUM ('PERMIT', 'DENY');
CREATE TYPE document_status AS ENUM ('DRAFT', 'ACTIVE', 'ARCHIVED', 'DELETED');
CREATE TYPE scan_status AS ENUM ('PENDING', 'CLEAN', 'INFECTED', 'FAILED');
CREATE TYPE request_status AS ENUM ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED', 'EXPIRED');
CREATE TYPE permission_code AS ENUM ('DISCOVER', 'VIEW', 'DOWNLOAD', 'SHARE', 'MANAGE');
CREATE TYPE principal_type AS ENUM ('USER', 'ROLE');
CREATE TYPE grant_source AS ENUM ('DIRECT', 'ACCESS_REQUEST', 'SYSTEM');
CREATE TYPE grant_status AS ENUM ('ACTIVE', 'REVOKED', 'EXPIRED', 'SUSPENDED');
CREATE TYPE session_status AS ENUM ('ACTIVE', 'ENDED', 'TERMINATED');
CREATE TYPE alert_status AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE');
CREATE TYPE severity_level AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
CREATE TYPE incident_status AS ENUM ('DRAFT', 'SUBMITTED', 'IN_REVIEW', 'CLOSED');
CREATE TYPE notification_status AS ENUM ('UNREAD', 'READ', 'ARCHIVED');

CREATE TABLE departments (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(30) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    parent_id           BIGINT REFERENCES departments(id) ON DELETE SET NULL,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username            VARCHAR(80) NOT NULL UNIQUE,
    email               VARCHAR(255) NOT NULL UNIQUE,
    password_hash       VARCHAR(255) NOT NULL,
    full_name           VARCHAR(150) NOT NULL,
    employee_code       VARCHAR(50) UNIQUE,
    department_id       BIGINT REFERENCES departments(id) ON DELETE SET NULL,
    status              user_status NOT NULL DEFAULT 'PENDING',
    failed_login_count  INTEGER NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
    locked_until        TIMESTAMPTZ,
    last_login_at       TIMESTAMPTZ,
    created_by          BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at         TIMESTAMPTZ,
    CHECK ((status = 'DISABLED') = (disabled_at IS NOT NULL))
);

CREATE TABLE roles (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(50) NOT NULL UNIQUE,
    name                VARCHAR(120) NOT NULL,
    description         TEXT,
    is_system_role      BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(80) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    resource_type       VARCHAR(80) NOT NULL,
    action              VARCHAR(80) NOT NULL,
    description         TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (resource_type, action)
);

CREATE TABLE user_roles (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id             BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_department_id BIGINT REFERENCES departments(id) ON DELETE CASCADE,
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    assigned_by         BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    UNIQUE (user_id, role_id, scope_department_id, valid_from)
);

CREATE TABLE role_permissions (
    role_id             BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id       BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_by          BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE attribute_definitions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(80) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    scope               attribute_scope NOT NULL,
    value_type          data_type NOT NULL,
    description         TEXT,
    is_required         BOOLEAN NOT NULL DEFAULT FALSE,
    is_multi_value      BOOLEAN NOT NULL DEFAULT FALSE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE attribute_options (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attribute_definition_id BIGINT NOT NULL REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    value_code              VARCHAR(120) NOT NULL,
    display_name            VARCHAR(150) NOT NULL,
    numeric_rank            INTEGER,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order              INTEGER NOT NULL DEFAULT 0,
    UNIQUE (attribute_definition_id, value_code)
);

CREATE TABLE user_attribute_assignments (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id                 BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    attribute_definition_id BIGINT NOT NULL REFERENCES attribute_definitions(id) ON DELETE RESTRICT,
    option_id               BIGINT REFERENCES attribute_options(id) ON DELETE RESTRICT,
    value_text              TEXT,
    value_number            NUMERIC(18,4),
    value_boolean           BOOLEAN,
    value_date              DATE,
    valid_from              TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to                TIMESTAMPTZ,
    assigned_by             BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    CHECK (num_nonnulls(option_id, value_text, value_number, value_boolean, value_date) = 1)
);

CREATE TABLE policy_rules (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(80) NOT NULL UNIQUE,
    name                VARCHAR(180) NOT NULL,
    description         TEXT,
    effect              policy_effect NOT NULL,
    priority            INTEGER NOT NULL DEFAULT 100 CHECK (priority >= 0),
    target_resource     VARCHAR(80) NOT NULL DEFAULT 'DOCUMENT',
    target_action       permission_code,
    combining_algorithm VARCHAR(40) NOT NULL DEFAULT 'DENY_OVERRIDES',
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    valid_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to            TIMESTAMPTZ,
    created_by          BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to > valid_from),
    CHECK (combining_algorithm IN ('DENY_OVERRIDES', 'PERMIT_OVERRIDES', 'FIRST_APPLICABLE'))
);

CREATE TABLE policy_rule_conditions (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_rule_id          BIGINT NOT NULL REFERENCES policy_rules(id) ON DELETE CASCADE,
    attribute_definition_id BIGINT REFERENCES attribute_definitions(id) ON DELETE RESTRICT,
    context_key             VARCHAR(100),
    operator                VARCHAR(30) NOT NULL,
    expected_value          JSONB NOT NULL,
    condition_group         INTEGER NOT NULL DEFAULT 1,
    sequence_no             INTEGER NOT NULL DEFAULT 1,
    CHECK ((attribute_definition_id IS NOT NULL) <> (context_key IS NOT NULL)),
    CHECK (operator IN ('EQ','NEQ','IN','NOT_IN','GTE','LTE','BETWEEN','CIDR_MATCH','TIME_BETWEEN','EXISTS')),
    UNIQUE (policy_rule_id, condition_group, sequence_no)
);

CREATE TABLE classification_levels (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(40) NOT NULL UNIQUE,
    name                VARCHAR(100) NOT NULL,
    rank                INTEGER NOT NULL UNIQUE CHECK (rank >= 0),
    description         TEXT,
    default_view_days   INTEGER CHECK (default_view_days > 0),
    allow_download      BOOLEAN NOT NULL DEFAULT FALSE,
    require_watermark   BOOLEAN NOT NULL DEFAULT TRUE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE business_categories (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code                VARCHAR(50) NOT NULL UNIQUE,
    name                VARCHAR(150) NOT NULL,
    department_id       BIGINT REFERENCES departments(id) ON DELETE SET NULL,
    description         TEXT,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE documents (
    id                  UUID PRIMARY KEY,
    document_code       VARCHAR(60) NOT NULL UNIQUE,
    title               VARCHAR(255) NOT NULL,
    description         TEXT,
    owner_id            BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    department_id       BIGINT NOT NULL REFERENCES departments(id) ON DELETE RESTRICT,
    current_version_id  BIGINT,
    status              document_status NOT NULL DEFAULT 'DRAFT',
    discoverable        BOOLEAN NOT NULL DEFAULT TRUE,
    retention_until     DATE,
    archived_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((status = 'ARCHIVED') = (archived_at IS NOT NULL))
);

CREATE TABLE document_versions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE RESTRICT,
    version_no          INTEGER NOT NULL CHECK (version_no > 0),
    original_filename   VARCHAR(255) NOT NULL,
    storage_key         VARCHAR(500) NOT NULL UNIQUE,
    mime_type           VARCHAR(150) NOT NULL,
    file_size_bytes     BIGINT NOT NULL CHECK (file_size_bytes > 0),
    sha256_hash         CHAR(64) NOT NULL,
    encryption_key_ref  VARCHAR(255) NOT NULL,
    scan_status         scan_status NOT NULL DEFAULT 'PENDING',
    change_note         TEXT,
    uploaded_by         BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_id, version_no),
    UNIQUE (document_id, sha256_hash)
);

ALTER TABLE documents
    ADD CONSTRAINT fk_documents_current_version
    FOREIGN KEY (current_version_id) REFERENCES document_versions(id) ON DELETE RESTRICT;

CREATE TABLE document_classification_history (
    id                      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    document_id             UUID NOT NULL REFERENCES documents(id) ON DELETE RESTRICT,
    classification_level_id BIGINT NOT NULL REFERENCES classification_levels(id) ON DELETE RESTRICT,
    business_category_id    BIGINT NOT NULL REFERENCES business_categories(id) ON DELETE RESTRICT,
    reason                  TEXT,
    classified_by           BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    effective_from          TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_to            TIMESTAMPTZ,
    CHECK (effective_to IS NULL OR effective_to > effective_from)
);

CREATE UNIQUE INDEX uq_document_current_classification
    ON document_classification_history(document_id)
    WHERE effective_to IS NULL;

CREATE TABLE access_requests (
    id                  UUID PRIMARY KEY,
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE RESTRICT,
    requester_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    reason              TEXT NOT NULL CHECK (length(trim(reason)) >= 10),
    requested_from      TIMESTAMPTZ NOT NULL,
    requested_until     TIMESTAMPTZ NOT NULL,
    status              request_status NOT NULL DEFAULT 'PENDING',
    submitted_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled_at        TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (requested_until > requested_from),
    CHECK ((status = 'CANCELLED') = (cancelled_at IS NOT NULL))
);

CREATE TABLE access_request_permissions (
    access_request_id   UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    permission          permission_code NOT NULL,
    PRIMARY KEY (access_request_id, permission),
    CHECK (permission IN ('VIEW', 'DOWNLOAD'))
);

CREATE TABLE access_request_decisions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    access_request_id   UUID NOT NULL UNIQUE REFERENCES access_requests(id) ON DELETE RESTRICT,
    decision            request_status NOT NULL,
    decided_by          BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    decision_note       TEXT,
    approved_from       TIMESTAMPTZ,
    approved_until      TIMESTAMPTZ,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (decision IN ('APPROVED', 'REJECTED')),
    CHECK (
      (decision = 'APPROVED' AND approved_from IS NOT NULL AND approved_until > approved_from)
      OR (decision = 'REJECTED' AND approved_from IS NULL AND approved_until IS NULL)
    )
);

CREATE TABLE access_grants (
    id                  UUID PRIMARY KEY,
    document_id         UUID NOT NULL REFERENCES documents(id) ON DELETE RESTRICT,
    principal_type      principal_type NOT NULL,
    principal_user_id   BIGINT REFERENCES users(id) ON DELETE CASCADE,
    principal_role_id   BIGINT REFERENCES roles(id) ON DELETE CASCADE,
    source              grant_source NOT NULL,
    access_request_id   UUID REFERENCES access_requests(id) ON DELETE RESTRICT,
    valid_from          TIMESTAMPTZ NOT NULL,
    valid_until         TIMESTAMPTZ NOT NULL,
    status              grant_status NOT NULL DEFAULT 'ACTIVE',
    granted_by          BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    granted_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by          BIGINT REFERENCES users(id) ON DELETE RESTRICT,
    revoked_at          TIMESTAMPTZ,
    revoke_reason       TEXT,
    CHECK (valid_until > valid_from),
    CHECK (
      (principal_type = 'USER' AND principal_user_id IS NOT NULL AND principal_role_id IS NULL)
      OR (principal_type = 'ROLE' AND principal_role_id IS NOT NULL AND principal_user_id IS NULL)
    ),
    CHECK ((source = 'ACCESS_REQUEST') = (access_request_id IS NOT NULL)),
    CHECK (
      (status = 'REVOKED' AND revoked_by IS NOT NULL AND revoked_at IS NOT NULL AND revoke_reason IS NOT NULL)
      OR (status <> 'REVOKED' AND revoked_by IS NULL AND revoked_at IS NULL)
    )
);

CREATE TABLE access_grant_permissions (
    access_grant_id     UUID NOT NULL REFERENCES access_grants(id) ON DELETE CASCADE,
    permission          permission_code NOT NULL,
    PRIMARY KEY (access_grant_id, permission),
    CHECK (permission IN ('VIEW', 'DOWNLOAD'))
);

CREATE TABLE access_sessions (
    id                  UUID PRIMARY KEY,
    access_grant_id     UUID NOT NULL REFERENCES access_grants(id) ON DELETE RESTRICT,
    document_version_id BIGINT NOT NULL REFERENCES document_versions(id) ON DELETE RESTRICT,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    ip_address          INET NOT NULL,
    user_agent          TEXT,
    device_fingerprint  VARCHAR(255),
    status              session_status NOT NULL DEFAULT 'ACTIVE',
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at            TIMESTAMPTZ,
    terminated_reason   TEXT,
    CHECK ((status = 'ACTIVE' AND ended_at IS NULL) OR (status <> 'ACTIVE' AND ended_at IS NOT NULL))
);

CREATE TABLE watermark_configs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                VARCHAR(120) NOT NULL,
    classification_level_id BIGINT REFERENCES classification_levels(id) ON DELETE CASCADE,
    is_default          BOOLEAN NOT NULL DEFAULT FALSE,
    is_visible          BOOLEAN NOT NULL DEFAULT TRUE,
    template_text       VARCHAR(500) NOT NULL,
    opacity_percent     SMALLINT NOT NULL DEFAULT 25 CHECK (opacity_percent BETWEEN 1 AND 100),
    rotation_degrees    SMALLINT NOT NULL DEFAULT -30 CHECK (rotation_degrees BETWEEN -90 AND 90),
    font_size           SMALLINT NOT NULL DEFAULT 12 CHECK (font_size BETWEEN 6 AND 72),
    color_hex           CHAR(7) NOT NULL DEFAULT '#808080',
    include_qr_code     BOOLEAN NOT NULL DEFAULT TRUE,
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_by          BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (color_hex ~ '^#[0-9A-Fa-f]{6}$')
);

CREATE TABLE watermark_instances (
    id                  UUID PRIMARY KEY,
    watermark_config_id BIGINT NOT NULL REFERENCES watermark_configs(id) ON DELETE RESTRICT,
    access_session_id   UUID NOT NULL REFERENCES access_sessions(id) ON DELETE RESTRICT,
    document_version_id BIGINT NOT NULL REFERENCES document_versions(id) ON DELETE RESTRICT,
    user_id             BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    watermark_token     VARCHAR(128) NOT NULL UNIQUE,
    rendered_text       VARCHAR(1000) NOT NULL,
    output_sha256_hash  CHAR(64),
    generated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id       BIGINT REFERENCES users(id) ON DELETE SET NULL,
    actor_username      VARCHAR(80),
    action              VARCHAR(100) NOT NULL,
    object_type         VARCHAR(80) NOT NULL,
    object_id           VARCHAR(100),
    document_id         UUID REFERENCES documents(id) ON DELETE SET NULL,
    access_session_id   UUID REFERENCES access_sessions(id) ON DELETE SET NULL,
    outcome             VARCHAR(20) NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILED')),
    reason_code         VARCHAR(80),
    ip_address          INET,
    user_agent          TEXT,
    correlation_id      UUID NOT NULL,
    details             JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash       CHAR(64),
    entry_hash          CHAR(64) NOT NULL,
    CHECK (actor_user_id IS NOT NULL OR actor_username IS NOT NULL)
);

CREATE TABLE security_alerts (
    id                  UUID PRIMARY KEY,
    alert_type          VARCHAR(80) NOT NULL,
    severity            severity_level NOT NULL,
    status              alert_status NOT NULL DEFAULT 'OPEN',
    title               VARCHAR(255) NOT NULL,
    description         TEXT NOT NULL,
    detected_user_id    BIGINT REFERENCES users(id) ON DELETE SET NULL,
    document_id         UUID REFERENCES documents(id) ON DELETE SET NULL,
    detected_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_to         BIGINT REFERENCES users(id) ON DELETE SET NULL,
    resolved_at         TIMESTAMPTZ,
    resolution_note     TEXT,
    CHECK ((status IN ('RESOLVED','FALSE_POSITIVE')) = (resolved_at IS NOT NULL))
);

CREATE TABLE alert_audit_links (
    alert_id            UUID NOT NULL REFERENCES security_alerts(id) ON DELETE CASCADE,
    audit_log_id        BIGINT NOT NULL REFERENCES audit_logs(id) ON DELETE RESTRICT,
    PRIMARY KEY (alert_id, audit_log_id)
);

CREATE TABLE incident_reports (
    id                  UUID PRIMARY KEY,
    incident_code       VARCHAR(50) NOT NULL UNIQUE,
    alert_id            UUID REFERENCES security_alerts(id) ON DELETE SET NULL,
    title               VARCHAR(255) NOT NULL,
    summary             TEXT NOT NULL,
    findings            TEXT,
    impact_assessment   TEXT,
    status              incident_status NOT NULL DEFAULT 'DRAFT',
    prepared_by         BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    submitted_to_owner  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    submitted_to_admin  BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at        TIMESTAMPTZ,
    closed_at           TIMESTAMPTZ,
    CHECK ((status = 'DRAFT') OR submitted_at IS NOT NULL),
    CHECK ((status = 'CLOSED') = (closed_at IS NOT NULL))
);

CREATE TABLE incident_actions (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_report_id  UUID NOT NULL REFERENCES incident_reports(id) ON DELETE CASCADE,
    action_type         VARCHAR(80) NOT NULL,
    recommendation      TEXT NOT NULL,
    assigned_to         BIGINT REFERENCES users(id) ON DELETE SET NULL,
    due_at              TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    completion_note     TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (completed_at IS NULL OR completion_note IS NOT NULL)
);

CREATE TABLE notifications (
    id                  UUID PRIMARY KEY,
    recipient_id        BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    notification_type   VARCHAR(80) NOT NULL,
    title               VARCHAR(255) NOT NULL,
    body                TEXT NOT NULL,
    related_object_type VARCHAR(80),
    related_object_id   VARCHAR(100),
    status              notification_status NOT NULL DEFAULT 'UNREAD',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at             TIMESTAMPTZ,
    CHECK ((status = 'UNREAD' AND read_at IS NULL) OR (status <> 'UNREAD' AND read_at IS NOT NULL))
);

CREATE TABLE system_health_snapshots (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    captured_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    service_name        VARCHAR(100) NOT NULL,
    status              VARCHAR(20) NOT NULL CHECK (status IN ('HEALTHY','DEGRADED','DOWN')),
    response_time_ms    INTEGER CHECK (response_time_ms >= 0),
    storage_used_bytes  BIGINT CHECK (storage_used_bytes >= 0),
    storage_total_bytes BIGINT CHECK (storage_total_bytes > 0),
    error_count         INTEGER NOT NULL DEFAULT 0 CHECK (error_count >= 0),
    details             JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_users_department_status ON users(department_id, status);
CREATE INDEX idx_user_roles_active ON user_roles(user_id, role_id, valid_from, valid_to);
CREATE INDEX idx_user_attrs_active ON user_attribute_assignments(user_id, attribute_definition_id, valid_from, valid_to);
CREATE INDEX idx_documents_owner_status ON documents(owner_id, status);
CREATE INDEX idx_documents_department_status ON documents(department_id, status);
CREATE INDEX idx_document_versions_document ON document_versions(document_id, version_no DESC);
CREATE INDEX idx_access_requests_owner_queue ON access_requests(document_id, status, submitted_at);
CREATE INDEX idx_access_requests_requester ON access_requests(requester_id, status, submitted_at DESC);
CREATE INDEX idx_access_grants_user_active ON access_grants(principal_user_id, document_id, status, valid_until);
CREATE INDEX idx_access_grants_role_active ON access_grants(principal_role_id, document_id, status, valid_until);
CREATE INDEX idx_sessions_user_active ON access_sessions(user_id, status, last_activity_at DESC);
CREATE INDEX idx_audit_actor_time ON audit_logs(actor_user_id, occurred_at DESC);
CREATE INDEX idx_audit_document_time ON audit_logs(document_id, occurred_at DESC);
CREATE INDEX idx_audit_action_time ON audit_logs(action, occurred_at DESC);
CREATE INDEX idx_audit_details_gin ON audit_logs USING GIN(details);
CREATE INDEX idx_alert_status_severity ON security_alerts(status, severity, detected_at DESC);
CREATE INDEX idx_notifications_recipient ON notifications(recipient_id, status, created_at DESC);

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_departments_updated BEFORE UPDATE ON departments
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_roles_updated BEFORE UPDATE ON roles
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_attribute_definitions_updated BEFORE UPDATE ON attribute_definitions
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_policy_rules_updated BEFORE UPDATE ON policy_rules
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_documents_updated BEFORE UPDATE ON documents
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_access_requests_updated BEFORE UPDATE ON access_requests
FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_watermark_configs_updated BEFORE UPDATE ON watermark_configs
FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Bao dam current_version_id thuoc dung document.
CREATE OR REPLACE FUNCTION validate_current_document_version() RETURNS trigger AS $$
BEGIN
  IF NEW.current_version_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM document_versions v
    WHERE v.id = NEW.current_version_id AND v.document_id = NEW.id
  ) THEN
    RAISE EXCEPTION 'current_version_id does not belong to document';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_validate_current_document_version
BEFORE INSERT OR UPDATE OF current_version_id ON documents
FOR EACH ROW EXECUTE FUNCTION validate_current_document_version();

-- Ngan cap quyen VIEW/DOWNLOAD khi clearance hien tai thap hon muc mat.
-- Gia dinh attribute definition CLEARANCE_LEVEL dung option.numeric_rank.
CREATE OR REPLACE FUNCTION validate_user_clearance_for_grant() RETURNS trigger AS $$
DECLARE
  user_rank INTEGER;
  document_rank INTEGER;
BEGIN
  IF NEW.principal_type = 'USER' AND NEW.status = 'ACTIVE' THEN
    SELECT ao.numeric_rank INTO user_rank
    FROM user_attribute_assignments uaa
    JOIN attribute_definitions ad ON ad.id = uaa.attribute_definition_id
    JOIN attribute_options ao ON ao.id = uaa.option_id
    WHERE uaa.user_id = NEW.principal_user_id
      AND ad.code = 'CLEARANCE_LEVEL'
      AND uaa.valid_from <= now()
      AND (uaa.valid_to IS NULL OR uaa.valid_to > now())
    ORDER BY ao.numeric_rank DESC
    LIMIT 1;

    SELECT cl.rank INTO document_rank
    FROM document_classification_history dch
    JOIN classification_levels cl ON cl.id = dch.classification_level_id
    WHERE dch.document_id = NEW.document_id
      AND dch.effective_to IS NULL;

    IF user_rank IS NULL OR document_rank IS NULL OR user_rank < document_rank THEN
      RAISE EXCEPTION 'Clearance level is insufficient for this document';
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_validate_user_clearance_for_grant
BEFORE INSERT OR UPDATE OF principal_user_id, document_id, status ON access_grants
FOR EACH ROW EXECUTE FUNCTION validate_user_clearance_for_grant();

-- Audit log la append-only: khong cho sua/xoa bang vai tro ung dung.
CREATE OR REPLACE FUNCTION prevent_audit_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_logs is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_no_update
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();

COMMIT;
