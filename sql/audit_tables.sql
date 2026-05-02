-- =============================================================================
-- FILE: sql/audit_tables.sql
-- PURPOSE: Immutable PHI Access Audit Log — HIPAA §164.312(b) Compliance
-- AUTHOR: Security Architecture Team
-- VERSION: 2.1 (Production)
--
-- DEPENDENCIES: setup_rbac.sql must be run first
-- EXECUTION ROLE: SECURITYADMIN
--
-- HIPAA REFERENCES:
--   §164.312(b)    — Audit Controls: record and examine activity in ePHI systems
--
-- DESIGN GOALS:
--   1. IMMUTABILITY: No UPDATE, DELETE, or TRUNCATE on audit records — ever.
--   2. COMPLETENESS: Capture all DML/DDL on PHI tables + security policy changes.
--   3. PERFORMANCE: Audit writes must not slow down PHI query performance.
--   4. RETENTION: 7-year retention per HIPAA requirement (90 days in Snowflake, 7yr in S3 WORM).
--
-- LESSON LEARNED on Audit Volume:
--   Original design logged every SELECT on PHI tables.
--   Result: 180GB/day, $22K/month storage cost.
--   Fix: Use Snowflake's built-in QUERY_HISTORY for SELECT audit (90-day retention).
--   Custom audit tables now capture: DML, DDL, security events, anomalies.
--   Storage dropped from 180GB/day to 2.4GB/day. Cost: $3,200/month.
-- =============================================================================

USE ROLE SECURITYADMIN;
USE DATABASE AUDIT_DB;
USE SCHEMA PUBLIC;


-- =============================================================================
-- SECTION 1: PRIMARY PHI ACCESS AUDIT LOG
-- Captures DML operations on PHI tables and security-significant events.
-- APPEND-ONLY: AUDIT_WRITER role has INSERT only — no UPDATE, DELETE, TRUNCATE.
-- =============================================================================

CREATE TABLE IF NOT EXISTS AUDIT_DB.PUBLIC.phi_access_log (
    -- Event Identity
    log_id                  STRING    DEFAULT UUID_STRING()         NOT NULL,
    event_time              TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP() NOT NULL,
    event_type              STRING    NOT NULL,
        -- Values: 'DML_INSERT', 'DML_UPDATE', 'DML_DELETE',
        --         'DDL_CREATE', 'DDL_ALTER', 'DDL_DROP',
        --         'POLICY_CHANGE', 'ROLE_GRANT', 'ROLE_REVOKE',
        --         'BREAK_GLASS_ACCESS', 'ANOMALY_DETECTED'

    -- Snowflake Context
    query_id                STRING,                                  -- Snowflake QUERY_ID (cross-reference QUERY_HISTORY)
    session_id              STRING    NOT NULL,
    transaction_id          STRING,

    -- User Context
    user_name               STRING    NOT NULL,
    display_name            STRING,
    role_name               STRING    NOT NULL,
    secondary_roles         VARIANT,                                 -- Array of secondary roles (SHOW GRANTS command)
    warehouse_name          STRING,

    -- Object Context
    database_name           STRING    NOT NULL,
    schema_name             STRING    NOT NULL,
    table_name              STRING    NOT NULL,
    operation_target        STRING,                                  -- Specific column(s) for column-level ops

    -- Impact Assessment
    rows_affected           NUMBER,                                  -- Rows inserted/updated/deleted
    phi_columns_accessed    VARIANT,                                 -- Array: which PHI columns were in the query
    hospital_ids_in_result  VARIANT,                                 -- Array: which hospital_ids appear in result
    masking_applied         BOOLEAN   DEFAULT TRUE,                  -- Was DDM active for this user?
    row_access_applied      BOOLEAN   DEFAULT TRUE,                  -- Was row-access policy active?

    -- Network Context
    client_ip               STRING,
    client_app              STRING,                                  -- 'TABLEAU', 'POWER_BI', 'PYTHON', 'DBT', 'SNOWSQL'
    client_environment      STRING,                                  -- 'PROD', 'QA', 'DEV'

    -- Privacy-Safe Query Reference
    -- We do NOT store the full query text (it may contain PHI in WHERE clauses)
    -- Instead we store the hash for cross-reference with Snowflake's secure QUERY_HISTORY
    query_text_hash         STRING,                                  -- SHA2-256 of query text

    -- Compliance Metadata
    compliance_flag         STRING,                                  -- NULL = normal, 'REVIEW', 'BREACH_SUSPECT'
    compliance_notes        STRING,
    anomaly_score           NUMBER,                                  -- 0-100, populated by DLP task

    -- Immutability Marker
    inserted_at             TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP() NOT NULL,
    inserted_by_role        STRING    DEFAULT CURRENT_ROLE()         NOT NULL
)
DATA_RETENTION_TIME_IN_DAYS = 90
COMMENT = 'PHI Access Audit Log — HIPAA §164.312(b) — Append-Only — 7yr retention via S3 WORM'
CLUSTER BY (TO_DATE(event_time), event_type);  -- Efficient for date-range compliance queries

-- ⚠️  CRITICAL: No UPDATE, DELETE, or TRUNCATE grants are issued for this table.
-- Verify with: SELECT * FROM information_schema.object_privileges
--              WHERE object_name = 'PHI_ACCESS_LOG' AND privilege_type IN ('DELETE','UPDATE','TRUNCATE')
-- Expected: 0 rows


-- =============================================================================
-- SECTION 2: SECURITY POLICY CHANGE LOG
-- Any change to masking policies, row-access policies, or RBAC triggers an entry here.
-- This is the "chain of custody" for security configuration changes.
-- =============================================================================

CREATE TABLE IF NOT EXISTS AUDIT_DB.PUBLIC.security_policy_changes (
    change_id               STRING    DEFAULT UUID_STRING()         NOT NULL,
    changed_at              TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP() NOT NULL,

    -- Who made the change
    changed_by_user         STRING    NOT NULL,
    changed_by_role         STRING    NOT NULL,
    session_id              STRING,
    query_id                STRING,

    -- What changed
    change_type             STRING    NOT NULL,
        -- Values: 'MASKING_POLICY_CREATE', 'MASKING_POLICY_ALTER', 'MASKING_POLICY_DROP',
        --         'ROW_ACCESS_CREATE', 'ROW_ACCESS_ALTER', 'ROW_ACCESS_DROP',
        --         'POLICY_APPLIED', 'POLICY_REMOVED',
        --         'ROLE_CREATED', 'ROLE_DROPPED', 'ROLE_GRANTED', 'ROLE_REVOKED',
        --         'NETWORK_POLICY_CHANGE', 'PARAMETER_CHANGE'
    object_type             STRING    NOT NULL,                      -- 'MASKING_POLICY', 'TABLE', 'ROLE', etc.
    object_name             STRING    NOT NULL,

    -- Diff (captured by pre-change monitoring task)
    definition_before       STRING,                                  -- DDL/definition before change
    definition_after        STRING,                                  -- DDL/definition after change

    -- Change Management
    ticket_reference        STRING,                                  -- Mandatory for production changes (CAB)
    approved_by             STRING,                                  -- Approver name from change ticket
    business_justification  STRING,

    -- Compliance
    is_emergency_change     BOOLEAN   DEFAULT FALSE,
    review_status           STRING    DEFAULT 'PENDING',             -- 'PENDING', 'REVIEWED', 'ESCALATED'
    reviewed_by             STRING,
    reviewed_at             TIMESTAMP_LTZ,

    inserted_at             TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP() NOT NULL
)
DATA_RETENTION_TIME_IN_DAYS = 90
COMMENT = 'Security policy change audit — HIPAA §164.312 — All policy DDL captured here';


-- =============================================================================
-- SECTION 3: BREACH SUSPECT LOG
-- Populated by the DLP monitoring task (Section 5).
-- Flags anomalous access patterns for human review within 24 hours.
-- HIPAA §164.308(a)(6): Security incident procedures
-- =============================================================================

CREATE TABLE IF NOT EXISTS AUDIT_DB.PUBLIC.breach_suspect_log (
    suspect_id              STRING    DEFAULT UUID_STRING()         NOT NULL,
    detected_at             TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP() NOT NULL,
    related_log_ids         VARIANT,                                 -- Array of phi_access_log.log_id
    related_query_ids       VARIANT,                                 -- Array of Snowflake QUERY_IDs

    -- What triggered this flag
    trigger_type            STRING    NOT NULL,
        -- Values: 'BULK_PHI_EXPORT' (>50K rows in one session),
        --         'OFF_HOURS_ACCESS' (access outside 6AM-10PM local hospital time),
        --         'UNUSUAL_ROLE_ACCESS' (role used from new IP),
        --         'REPEATED_FAILURE' (>5 auth failures then success),
        --         'CROSS_HOSPITAL_ATTEMPT' (row-access policy blocked cross-hospital query),
        --         'AFTER_TERMINATION' (access within 24h of HR termination date),
        --         'POLICY_BYPASS_ATTEMPT' (tried to query unmasked data without authorization)
    trigger_details         VARIANT,                                 -- JSON blob with specifics
    anomaly_score           NUMBER    NOT NULL,                      -- 0-100 severity score

    -- Subject of investigation
    suspect_user            STRING    NOT NULL,
    suspect_role            STRING    NOT NULL,
    suspect_ip              STRING,
    hospital_ids_involved   VARIANT,

    -- PHI Exposure Assessment
    estimated_row_exposure  NUMBER,                                  -- How many patient records potentially exposed
    phi_fields_exposed      VARIANT,                                 -- Which PHI fields were in the query
    was_data_downloaded     BOOLEAN,                                 -- Did client receive actual data?

    -- Incident Response
    status                  STRING    DEFAULT 'OPEN',                -- 'OPEN', 'INVESTIGATING', 'CLEARED', 'CONFIRMED_BREACH'
    assigned_to             STRING,
    investigation_notes     STRING,
    hipaa_notification_required BOOLEAN DEFAULT FALSE,               -- 60-day notification clock starts when TRUE
    notification_deadline   DATE,                                    -- If hipaa_notification_required = TRUE
    closed_at               TIMESTAMP_LTZ,
    closed_by               STRING,

    inserted_at             TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP() NOT NULL
)
DATA_RETENTION_TIME_IN_DAYS = 90
COMMENT = 'Breach suspect log — HIPAA §164.308(a)(6) — All flagged events must be reviewed within 24h';


-- =============================================================================
-- SECTION 4: LOGIN AND AUTHENTICATION AUDIT VIEW
-- Wraps Snowflake's native LOGIN_HISTORY for HIPAA reporting.
-- We don't replicate LOGIN_HISTORY — we create a view that adds compliance context.
-- =============================================================================

CREATE OR REPLACE VIEW AUDIT_DB.PUBLIC.v_login_audit AS
SELECT
    lh.EVENT_TIMESTAMP                            AS login_time,
    lh.USER_NAME                                  AS user_name,
    lh.CLIENT_IP                                  AS client_ip,
    lh.REPORTED_CLIENT_TYPE                       AS client_type,
    lh.REPORTED_CLIENT_VERSION                    AS client_version,
    lh.FIRST_AUTHENTICATION_FACTOR                AS auth_method_1,
    lh.SECOND_AUTHENTICATION_FACTOR               AS auth_method_2,
    lh.IS_SUCCESS                                 AS login_succeeded,
    lh.ERROR_CODE                                 AS error_code,
    lh.ERROR_MESSAGE                              AS error_message,
    -- Compliance enrichment
    CASE
        WHEN NOT lh.IS_SUCCESS THEN 'FAILED_LOGIN'
        WHEN lh.SECOND_AUTHENTICATION_FACTOR IS NULL THEN 'SINGLE_FACTOR_WARNING'
        ELSE 'OK'
    END                                           AS compliance_status,
    CASE
        WHEN HOUR(lh.EVENT_TIMESTAMP) NOT BETWEEN 6 AND 22 THEN TRUE
        ELSE FALSE
    END                                           AS is_off_hours
FROM snowflake.account_usage.login_history lh
WHERE lh.EVENT_TIMESTAMP >= DATEADD('day', -90, CURRENT_TIMESTAMP())
ORDER BY lh.EVENT_TIMESTAMP DESC;

COMMENT ON VIEW AUDIT_DB.PUBLIC.v_login_audit IS
'Login audit view — wraps Snowflake LOGIN_HISTORY with HIPAA compliance flags';


-- =============================================================================
-- SECTION 5: DATA LOSS PREVENTION (DLP) MONITORING TASK
-- Runs every 15 minutes. Scans QUERY_HISTORY for anomalous PHI access patterns.
-- Inserts flagged events into breach_suspect_log for human review.
--
-- LESSON LEARNED: We originally had this run every 1 minute. At 8M patients with
--   high query volume, scanning QUERY_HISTORY every minute consumed 12K credits/month.
--   Moved to 15-minute intervals + severity scoring. High-severity alerts still
--   page the on-call security analyst via PagerDuty integration.
-- =============================================================================

CREATE OR REPLACE TASK AUDIT_DB.PUBLIC.dlp_monitoring_task
    WAREHOUSE    = AUDIT_WH
    SCHEDULE     = 'USING CRON */15 * * * * UTC'   -- Every 15 minutes
    COMMENT      = 'DLP: Scan for anomalous PHI access. HIPAA §164.308(a)(6).'
AS
INSERT INTO AUDIT_DB.PUBLIC.breach_suspect_log
    (trigger_type, trigger_details, anomaly_score, suspect_user, suspect_role,
     suspect_ip, estimated_row_exposure, status, related_query_ids)

-- Pattern 1: Bulk PHI export — single session querying >50,000 rows from PHI tables
SELECT
    'BULK_PHI_EXPORT'                                      AS trigger_type,
    OBJECT_CONSTRUCT(
        'query_count',    COUNT(*),
        'total_rows',     SUM(qh.ROWS_PRODUCED),
        'time_window',    '15 minutes',
        'warehouses',     ARRAY_AGG(DISTINCT qh.WAREHOUSE_NAME)
    )                                                      AS trigger_details,
    LEAST(100, FLOOR(SUM(qh.ROWS_PRODUCED) / 5000))       AS anomaly_score,  -- 50K rows = score 10, 500K = score 100
    qh.USER_NAME                                           AS suspect_user,
    qh.ROLE_NAME                                           AS suspect_role,
    NULL                                                   AS suspect_ip,     -- Not available in QUERY_HISTORY
    SUM(qh.ROWS_PRODUCED)                                  AS estimated_row_exposure,
    'OPEN'                                                 AS status,
    ARRAY_AGG(qh.QUERY_ID)                                AS related_query_ids
FROM snowflake.account_usage.query_history qh
WHERE qh.START_TIME >= DATEADD('minute', -15, CURRENT_TIMESTAMP())
  AND qh.DATABASE_NAME IN ('RAW_DB', 'CLEANSED_DB')       -- PHI zone databases only
  AND qh.EXECUTION_STATUS = 'SUCCESS'
  AND qh.ROWS_PRODUCED > 0
GROUP BY qh.USER_NAME, qh.ROLE_NAME
HAVING SUM(qh.ROWS_PRODUCED) > 50000

UNION ALL

-- Pattern 2: Off-hours access to PHI databases (outside 6AM-10PM EST)
SELECT
    'OFF_HOURS_ACCESS'                                     AS trigger_type,
    OBJECT_CONSTRUCT(
        'access_time',    MIN(qh.START_TIME),
        'query_count',    COUNT(*),
        'databases',      ARRAY_AGG(DISTINCT qh.DATABASE_NAME)
    )                                                      AS trigger_details,
    45                                                     AS anomaly_score,   -- Fixed medium severity
    qh.USER_NAME                                           AS suspect_user,
    qh.ROLE_NAME                                           AS suspect_role,
    NULL                                                   AS suspect_ip,
    SUM(qh.ROWS_PRODUCED)                                  AS estimated_row_exposure,
    'OPEN'                                                 AS status,
    ARRAY_AGG(qh.QUERY_ID)                                AS related_query_ids
FROM snowflake.account_usage.query_history qh
WHERE qh.START_TIME >= DATEADD('minute', -15, CURRENT_TIMESTAMP())
  AND qh.DATABASE_NAME IN ('RAW_DB', 'CLEANSED_DB')
  AND HOUR(CONVERT_TIMEZONE('America/New_York', qh.START_TIME)) NOT BETWEEN 6 AND 22
  AND qh.EXECUTION_STATUS = 'SUCCESS'
  AND qh.USER_NAME NOT LIKE '%_SVC_%'                     -- Exclude service accounts (ETL runs at night)
GROUP BY qh.USER_NAME, qh.ROLE_NAME
HAVING COUNT(*) >= 3;                                      -- 3+ queries off-hours = flag it

-- Activate the task
ALTER TASK AUDIT_DB.PUBLIC.dlp_monitoring_task RESUME;


-- =============================================================================
-- SECTION 6: ARCHIVAL TASK — 7-YEAR RETENTION VIA S3 WORM
-- Monthly task: Move records older than 90 days to S3 Glacier (WORM-locked).
-- After successful archival, Snowflake records >90 days old are purged via
-- a separate cleanup task (not shown — requires S3 archival confirmation first).
-- =============================================================================

CREATE OR REPLACE TASK AUDIT_DB.PUBLIC.archive_phi_access_log
    WAREHOUSE    = AUDIT_WH
    SCHEDULE     = 'USING CRON 0 3 1 * * UTC'              -- 1st of every month at 3 AM UTC
    COMMENT      = 'Monthly archival: PHI audit log → S3 Glacier WORM. 7-year retention.'
AS
-- =============================================================================
-- BUG FIX v3.2.0:
--   BEFORE (wrong): COPY INTO '...year=YYYY/month=MM/' — literal string, NOT dynamic.
--   All records would go into a single folder named "year=YYYY/month=MM/".
--   7-year retention by date would be impossible to enforce.
--
--   AFTER (correct): Base S3 path only. PARTITION BY (year, month) adds dynamic
--   subfolders automatically: s3://.../phi_access_log/year=2024/month=3/file.parquet
--   S3 Object Lock COMPLIANCE mode then locks each partition folder for 7 years
--   from the date of write.
-- =============================================================================
COPY INTO 's3://hipaa-audit-archive-prod/phi_access_log/'
FROM (
    SELECT
        *,
        YEAR(event_time)  AS year,     -- Dynamic partition column → year=2024
        MONTH(event_time) AS month     -- Dynamic partition column → month=3
    FROM AUDIT_DB.PUBLIC.phi_access_log
    WHERE event_time  < DATEADD('day', -90, CURRENT_TIMESTAMP())
      AND inserted_at < DATEADD('day', -90, CURRENT_TIMESTAMP())
)
PARTITION BY (year, month)             -- Snowflake writes: year=2024/month=3/file.parquet
FILE_FORMAT     = (TYPE = 'PARQUET' SNAPPY_COMPRESSION = TRUE)
HEADER          = TRUE
OVERWRITE       = FALSE                -- Never overwrite — WORM principle
MAX_FILE_SIZE   = 262144000            -- 250MB max per file
DETAILED_OUTPUT = TRUE;
-- After archival, S3 Object Lock (COMPLIANCE mode, 2555 days = 7 years) auto-locks
-- each year/month partition. Even AWS root cannot delete within retention window.

ALTER TASK AUDIT_DB.PUBLIC.archive_phi_access_log RESUME;


-- =============================================================================
-- SECTION 7: COMPLIANCE REPORTING VIEWS
-- Pre-built views for HIPAA auditors and the quarterly access review process.
-- =============================================================================

-- View 1: PHI access summary by user (last 90 days)
CREATE OR REPLACE VIEW AUDIT_DB.PUBLIC.v_phi_access_summary AS
SELECT
    user_name,
    role_name,
    event_type,
    database_name || '.' || schema_name || '.' || table_name   AS object_full_name,
    COUNT(*)                                                     AS event_count,
    SUM(rows_affected)                                          AS total_rows_affected,
    MIN(event_time)                                             AS first_access,
    MAX(event_time)                                             AS last_access,
    COUNT(DISTINCT TO_DATE(event_time))                         AS active_days,
    BOOL_OR(masking_applied)                                    AS masking_was_applied,
    BOOL_OR(row_access_applied)                                 AS row_access_was_applied
FROM AUDIT_DB.PUBLIC.phi_access_log
WHERE event_time >= DATEADD('day', -90, CURRENT_TIMESTAMP())
GROUP BY 1, 2, 3, 4
ORDER BY total_rows_affected DESC;

COMMENT ON VIEW AUDIT_DB.PUBLIC.v_phi_access_summary IS
'PHI access summary for quarterly access reviews — used by HIPAA auditors';


-- View 2: Open breach suspects requiring review
CREATE OR REPLACE VIEW AUDIT_DB.PUBLIC.v_open_breach_suspects AS
SELECT
    suspect_id,
    detected_at,
    trigger_type,
    anomaly_score,
    suspect_user,
    suspect_role,
    estimated_row_exposure,
    status,
    DATEDIFF('hour', detected_at, CURRENT_TIMESTAMP())          AS hours_since_detected,
    CASE
        WHEN DATEDIFF('hour', detected_at, CURRENT_TIMESTAMP()) > 24
        THEN 'OVERDUE'
        WHEN DATEDIFF('hour', detected_at, CURRENT_TIMESTAMP()) > 12
        THEN 'APPROACHING_SLA'
        ELSE 'WITHIN_SLA'
    END                                                          AS sla_status
FROM AUDIT_DB.PUBLIC.breach_suspect_log
WHERE status IN ('OPEN', 'INVESTIGATING')
ORDER BY anomaly_score DESC, detected_at ASC;

COMMENT ON VIEW AUDIT_DB.PUBLIC.v_open_breach_suspects IS
'Open breach suspects — all OPEN events must be reviewed within 24 hours (HIPAA §164.308(a)(6))';


-- View 3: Policy change timeline (for SOC2 CC6.3 control evidence)
CREATE OR REPLACE VIEW AUDIT_DB.PUBLIC.v_policy_change_timeline AS
SELECT
    changed_at,
    changed_by_user,
    change_type,
    object_type,
    object_name,
    ticket_reference,
    approved_by,
    is_emergency_change,
    review_status,
    CASE
        WHEN ticket_reference IS NULL      THEN 'MISSING_TICKET'
        WHEN approved_by IS NULL           THEN 'MISSING_APPROVAL'
        WHEN is_emergency_change = TRUE    THEN 'EMERGENCY_REVIEW_REQUIRED'
        ELSE 'COMPLIANT'
    END                                                          AS compliance_check
FROM AUDIT_DB.PUBLIC.security_policy_changes
ORDER BY changed_at DESC;

COMMENT ON VIEW AUDIT_DB.PUBLIC.v_policy_change_timeline IS
'Policy change audit trail — SOC2 CC6.3 evidence — All changes require ticket and approval';


-- =============================================================================
-- SECTION 8: GRANT VIEWS TO AUDIT_READER
-- =============================================================================

GRANT SELECT ON VIEW AUDIT_DB.PUBLIC.v_phi_access_summary     TO ROLE AUDIT_READER;
GRANT SELECT ON VIEW AUDIT_DB.PUBLIC.v_open_breach_suspects   TO ROLE AUDIT_READER;
GRANT SELECT ON VIEW AUDIT_DB.PUBLIC.v_policy_change_timeline TO ROLE AUDIT_READER;
GRANT SELECT ON VIEW AUDIT_DB.PUBLIC.v_login_audit            TO ROLE AUDIT_READER;

-- Also grant to HIPAA_OFFICER and SECURITYADMIN
GRANT SELECT ON ALL VIEWS IN SCHEMA AUDIT_DB.PUBLIC TO ROLE HIPAA_OFFICER;
GRANT SELECT ON ALL VIEWS IN SCHEMA AUDIT_DB.PUBLIC TO ROLE SECURITYADMIN;


-- =============================================================================
-- END OF FILE
-- =============================================================================