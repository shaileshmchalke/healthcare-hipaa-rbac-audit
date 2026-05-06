-- =============================================================================
-- FILE: sql/validation_queries.sql
-- PURPOSE: Verify RBAC, masking policies, row-access policies, and audit integrity
-- AUTHOR: Security Architecture Team
-- VERSION: 1.9 (Production)
--
-- RUN SCHEDULE: After every deployment | Before every audit | Weekly automated check
-- EXECUTION ROLE: SECURITYADMIN (for most checks), HIPAA_OFFICER (for masking tests)
--
-- HOW TO USE:
--   1. Run full script as SECURITYADMIN to get baseline validation results
--   2. Run individual sections as specific roles to test masking behavior
--   3. Expected results are documented in comments next to each query
--
-- AUTOMATED: These queries are also run weekly via a Snowflake Task
--   that inserts results into AUDIT_DB.PUBLIC.validation_results
-- =============================================================================


-- =============================================================================
-- SECTION 1: DATABASE OWNERSHIP VALIDATION
-- Confirms PHI databases are owned by SECURITYADMIN (not SYSADMIN)
-- This is the most critical structural check.
-- =============================================================================

-- CHECK 1A: PHI database ownership
-- Expected: All PHI databases owned by SECURITYADMIN
SELECT
    database_name,
    database_owner,
    CASE
        WHEN database_name IN ('RAW_DB', 'CLEANSED_DB', 'AUDIT_DB', 'PHI_POLICIES_DB')
             AND database_owner = 'SECURITYADMIN' THEN '✅ PASS'
        WHEN database_name IN ('RAW_DB', 'CLEANSED_DB', 'AUDIT_DB', 'PHI_POLICIES_DB')
             AND database_owner != 'SECURITYADMIN' THEN '❌ FAIL — PHI DB must be SECURITYADMIN-owned'
        ELSE '✅ OK'
    END AS ownership_check
FROM information_schema.databases
ORDER BY database_name;


-- CHECK 1B: SYSADMIN should have ZERO access to PHI databases
-- Expected: 0 rows returned
SELECT
    grantee_name,
    privilege_type,
    object_name AS database_name,
    '❌ CRITICAL FAIL — SYSADMIN has PHI database access' AS finding
FROM information_schema.object_privileges
WHERE grantee_name = 'SYSADMIN'
  AND object_type   = 'DATABASE'
  AND object_name  IN ('RAW_DB', 'CLEANSED_DB');
-- Expected: 0 rows


-- =============================================================================
-- SECTION 2: MASKING POLICY COVERAGE VALIDATION
-- Confirm every PHI column has a masking policy applied.
-- Any PHI column without a masking policy is a HIPAA violation.
-- =============================================================================

-- CHECK 2A: List all masking policy applications on CLEANSED_DB
-- Expected: All known PHI columns should appear here with a non-NULL policy
SELECT
    ref.ref_database_name                             AS database_name,
    ref.ref_schema_name                               AS schema_name,
    ref.ref_entity_name                               AS table_name,
    ref.ref_column_name                               AS column_name,
    pol.policy_name,
    pol.policy_kind,
    '✅ Masking applied'                              AS status
FROM table(
    information_schema.policy_references(policy_kind => 'MASKING_POLICY')
) ref
JOIN snowflake.account_usage.masking_policies pol
    ON pol.policy_name = ref.policy_name
WHERE ref.ref_database_name = 'CLEANSED_DB'
ORDER BY ref.ref_entity_name, ref.ref_column_name;


-- CHECK 2B: PHI columns WITHOUT masking policy (should return 0 rows)
-- This query lists known PHI column names that do NOT have a masking policy applied.
-- Run this after any schema change or new table creation.
WITH phi_columns AS (
    SELECT
        c.table_catalog,
        c.table_schema,
        c.table_name,
        c.column_name
    FROM information_schema.columns c
    WHERE c.table_catalog = 'CLEANSED_DB'
      AND LOWER(c.column_name) IN (
          'patient_ssn', 'ssn', 'social_security_number',
          'patient_dob', 'date_of_birth', 'birth_date',
          'patient_name', 'first_name', 'last_name', 'full_name',
          'patient_mrn', 'mrn', 'medical_record_number',
          'patient_phone', 'phone', 'phone_number',
          'patient_email', 'email', 'email_address',
          'patient_address_1', 'street_address', 'address',
          'patient_zip', 'zip_code', 'postal_code'
      )
),
masked_columns AS (
    SELECT
        ref.ref_database_name,
        ref.ref_schema_name,
        ref.ref_entity_name,
        ref.ref_column_name
    FROM table(
        information_schema.policy_references(policy_kind => 'MASKING_POLICY')
    ) ref
    WHERE ref.ref_database_name = 'CLEANSED_DB'
)
SELECT
    phi.table_catalog,
    phi.table_schema,
    phi.table_name,
    phi.column_name,
    '❌ FAIL — PHI column missing masking policy' AS finding
FROM phi_columns phi
LEFT JOIN masked_columns mc
    ON  mc.ref_database_name = phi.table_catalog
    AND mc.ref_schema_name   = phi.table_schema
    AND mc.ref_entity_name   = phi.table_name
    AND mc.ref_column_name   = phi.column_name
WHERE mc.ref_column_name IS NULL;
-- Expected: 0 rows — any result is a HIPAA compliance gap


-- =============================================================================
-- SECTION 3: ROW-ACCESS POLICY VALIDATION
-- Confirm patient tables have hospital isolation policy applied.
-- =============================================================================

-- CHECK 3A: Row-access policy applied to patient tables
SELECT
    ref.ref_database_name,
    ref.ref_schema_name,
    ref.ref_entity_name    AS table_name,
    ref.ref_column_name    AS policy_column,
    pol.policy_name,
    '✅ Row-access policy applied'  AS status
FROM table(
    information_schema.policy_references(policy_kind => 'ROW_ACCESS_POLICY')
) ref
JOIN snowflake.account_usage.row_access_policies pol
    ON pol.policy_name = ref.policy_name
WHERE ref.ref_database_name IN ('RAW_DB', 'CLEANSED_DB');


-- CHECK 3B: Hospital role mapping — active assignments (no expired access)
SELECT
    snowflake_role,
    hospital_id,
    effective_from,
    effective_to,
    granted_by,
    ticket_ref,
    CASE
        WHEN effective_to IS NULL                            THEN '✅ Active (no end date)'
        WHEN effective_to >= CURRENT_DATE()                  THEN '✅ Active until ' || effective_to::STRING
        WHEN effective_to < CURRENT_DATE()                   THEN '⚠️ EXPIRED — role still in mapping table'
        ELSE '❓ Unknown'
    END AS access_status
FROM PHI_POLICIES_DB.PHI.hospital_role_map
ORDER BY snowflake_role, hospital_id;


-- CHECK 3C: Hospital isolation behavioral test
-- Simulate as HOSPITAL_ADMIN_H01 — should only see H01 patients
-- Run this block as HOSPITAL_ADMIN_H01 to test isolation
-- Expected: Only hospital_id = 'H01' rows should appear
/*
USE ROLE HOSPITAL_ADMIN_H01;
SELECT hospital_id, COUNT(*) AS patient_count
FROM CLEANSED_DB.CLINICAL.patients
GROUP BY hospital_id
ORDER BY hospital_id;
-- Expected: Only one row: H01 | <count>
-- Any other hospital ID appearing = row-access policy failure = CRITICAL
*/


-- =============================================================================
-- SECTION 4: MASKING BEHAVIOR TESTING
-- Run these blocks as different roles to verify masking works correctly.
-- Compare results across roles.
-- =============================================================================

-- As HIPAA_OFFICER: Should see REAL values
/*
USE ROLE HIPAA_OFFICER;
SELECT
    patient_id,
    patient_name,
    patient_ssn,
    patient_dob,
    patient_mrn,
    patient_zip
FROM CLEANSED_DB.CLINICAL.patients
LIMIT 5;
-- Expected: Real names, real SSN values (unmasked), real DOBs, real MRNs
*/

-- As HOSPITAL_ADMIN_H01: Should see partial masking
/*
USE ROLE HOSPITAL_ADMIN_H01;
SELECT
    patient_id,
    patient_name,         -- Full name ✅
    patient_ssn,          -- Last 4 only: 'XXX-XX-6789' ✅
    patient_dob,          -- Full DOB ✅
    patient_mrn,          -- Full MRN ✅
    patient_zip,          -- Full ZIP ✅
    hospital_id           -- Should be H01 only ✅
FROM CLEANSED_DB.CLINICAL.patients
LIMIT 5;
*/

-- As ANALYST_CLINICAL: Should see heavy masking
/*
USE ROLE ANALYST_CLINICAL;
SELECT
    patient_id,
    patient_name,         -- First initial only: 'J***'
    patient_ssn,          -- Fully masked: 'XXX-XX-XXXX'
    patient_dob,          -- Year only: '1978-01-01'
    patient_mrn,          -- Token: 'MRN-a3f8b2c7d1e4'
    patient_zip           -- First 3 digits: '452**'
FROM CLEANSED_DB.CLINICAL.patients
LIMIT 5;
*/

-- As DS_ROLE: Should see de-identified data
/*
USE ROLE DS_ROLE;
SELECT
    patient_id,
    patient_name,         -- '***' (fully masked)
    patient_ssn,          -- NULL
    patient_dob,          -- Year only, 90+ capped at 1930
    patient_mrn,          -- Token
    patient_zip           -- First 3 digits
FROM CLEANSED_DB.CLINICAL.patients
LIMIT 5;
*/


-- =============================================================================
-- SECTION 5: AUDIT LOG INTEGRITY VALIDATION
-- Verify audit log is append-only (no deletes, no updates allowed)
-- =============================================================================

-- CHECK 5A: No DELETE/UPDATE/TRUNCATE privileges on audit tables
-- Expected: 0 rows for each (any row = CRITICAL FAIL)
SELECT
    grantee_name,
    privilege_type,
    object_name,
    '❌ CRITICAL — Destructive privilege on audit table' AS finding
FROM information_schema.object_privileges
WHERE object_catalog   = 'AUDIT_DB'
  AND privilege_type  IN ('DELETE', 'UPDATE', 'TRUNCATE')
  AND object_type      = 'TABLE';
-- Expected: 0 rows


-- CHECK 5B: Audit log record count trend (look for unexpected drops = possible tampering)
SELECT
    TO_DATE(event_time)     AS log_date,
    event_type,
    COUNT(*)                AS event_count,
    MIN(event_time)         AS first_event,
    MAX(event_time)         AS last_event
FROM AUDIT_DB.PUBLIC.phi_access_log
WHERE event_time >= DATEADD('day', -30, CURRENT_TIMESTAMP())
GROUP BY 1, 2
ORDER BY 1 DESC, 3 DESC;
-- Look for: Any date with 0 records when there should be some = potential tampering
-- Normal pattern: Relatively consistent counts per day (barring weekends/holidays)


-- CHECK 5C: Audit log has no gaps (automated check)
-- Returns dates in the last 30 days where audit log has fewer than 10 records
-- These dates need explanation (planned maintenance, holidays, etc.)
WITH date_spine AS (
    SELECT DATEADD('day', -seq4(), CURRENT_DATE())::DATE AS check_date
    FROM TABLE(GENERATOR(ROWCOUNT => 30))
),
daily_counts AS (
    SELECT
        TO_DATE(event_time) AS log_date,
        COUNT(*)            AS record_count
    FROM AUDIT_DB.PUBLIC.phi_access_log
    WHERE event_time >= DATEADD('day', -30, CURRENT_TIMESTAMP())
    GROUP BY 1
)
SELECT
    ds.check_date,
    COALESCE(dc.record_count, 0) AS audit_records,
    CASE
        WHEN COALESCE(dc.record_count, 0) = 0
             AND DAYOFWEEK(ds.check_date) BETWEEN 2 AND 6  -- Monday-Friday
        THEN '⚠️ REVIEW — Zero records on business day'
        WHEN COALESCE(dc.record_count, 0) < 10
        THEN '⚠️ LOW — Under 10 records this day'
        ELSE '✅ OK'
    END AS gap_check
FROM date_spine ds
LEFT JOIN daily_counts dc ON dc.log_date = ds.check_date
ORDER BY ds.check_date DESC;


-- =============================================================================
-- SECTION 6: ORPHAN ROLE AND ACCESS REVIEW
-- Identifies roles with no users assigned (orphan roles) and
-- users with PHI access whose employment status should be verified.
-- RUN: Quarterly as part of formal access review process
-- =============================================================================

-- CHECK 6A: Roles with PHI database access and their current user count
SELECT
    r.name               AS role_name,
    COUNT(DISTINCT u.name) AS assigned_user_count,
    LISTAGG(DISTINCT u.name, ', ')
        WITHIN GROUP (ORDER BY u.name)  AS assigned_users,
    CASE
        WHEN COUNT(DISTINCT u.name) = 0 THEN '⚠️ ORPHAN — No users assigned'
        WHEN COUNT(DISTINCT u.name) > 10 THEN '⚠️ REVIEW — High user count for PHI role'
        ELSE '✅ OK'
    END                  AS access_check
FROM snowflake.account_usage.roles r
LEFT JOIN snowflake.account_usage.grants_to_users gtu
    ON gtu.role = r.name
LEFT JOIN snowflake.account_usage.users u
    ON u.name = gtu.grantee_name
    AND u.deleted_on IS NULL
WHERE r.name IN (
    'HIPAA_OFFICER', 'PHI_READER',
    'HOSPITAL_ADMIN_H01', 'HOSPITAL_ADMIN_H02', 'HOSPITAL_ADMIN_H03',
    'HOSPITAL_ADMIN_H04', 'HOSPITAL_ADMIN_H05', 'HOSPITAL_ADMIN_H06',
    'HOSPITAL_ADMIN_H07', 'HOSPITAL_ADMIN_H08', 'HOSPITAL_ADMIN_H09',
    'HOSPITAL_ADMIN_H10', 'HOSPITAL_ADMIN_H11', 'HOSPITAL_ADMIN_H12',
    'ANALYST_CLINICAL', 'ANALYST_REVENUE'
)
GROUP BY r.name
ORDER BY r.name;


-- CHECK 6B: Users who haven't logged in for 60+ days but still have PHI role access
-- These are candidates for access revocation
SELECT
    u.name                AS user_name,
    u.last_success_login  AS last_login,
    DATEDIFF('day', u.last_success_login, CURRENT_TIMESTAMP()) AS days_since_login,
    LISTAGG(DISTINCT gtu.role, ', ')
        WITHIN GROUP (ORDER BY gtu.role)     AS phi_roles_assigned,
    '⚠️ REVIEW — Inactive user with PHI access'  AS finding
FROM snowflake.account_usage.users u
JOIN snowflake.account_usage.grants_to_users gtu
    ON gtu.grantee_name = u.name
WHERE u.deleted_on IS NULL
  AND gtu.role IN (
    'HIPAA_OFFICER', 'PHI_READER',
    'HOSPITAL_ADMIN_H01', 'HOSPITAL_ADMIN_H02', 'HOSPITAL_ADMIN_H03',
    'ANALYST_CLINICAL', 'ANALYST_REVENUE'
    -- Add all PHI roles here
  )
  AND (
    u.last_success_login IS NULL                                       -- Never logged in
    OR u.last_success_login < DATEADD('day', -60, CURRENT_TIMESTAMP()) -- 60+ days inactive
  )
GROUP BY u.name, u.last_success_login
ORDER BY days_since_login DESC NULLS FIRST;


-- =============================================================================
-- SECTION 7: NETWORK POLICY COMPLIANCE
-- =============================================================================

-- CHECK 7A: Current network policy configuration
SHOW NETWORK POLICIES;

-- CHECK 7B: Account-level network policy assignment
SELECT
    key,
    value,
    CASE
        WHEN key = 'NETWORK_POLICY' AND value = 'HIPAA_PRODUCTION_POLICY'
        THEN '✅ Correct production network policy applied'
        WHEN key = 'NETWORK_POLICY' AND value = ''
        THEN '❌ FAIL — No network policy at account level'
        WHEN key = 'NETWORK_POLICY'
        THEN '⚠️ REVIEW — Unexpected network policy: ' || value
        ELSE NULL
    END AS policy_check
FROM TABLE(FLATTEN(INPUT => PARSE_JSON(SYSTEM$GET_NETWORK_POLICY_INFO())))
WHERE key = 'NETWORK_POLICY';


-- =============================================================================
-- SECTION 8: COMPREHENSIVE COMPLIANCE SCORECARD
-- Single-query compliance overview. Run before every audit.
-- =============================================================================

WITH checks AS (
    -- Check: No SYSADMIN PHI access
    SELECT
        'RBAC'              AS category,
        'SYSADMIN PHI Access' AS check_name,
        CASE WHEN COUNT(*) = 0 THEN '✅ PASS' ELSE '❌ FAIL' END AS result,
        COUNT(*) || ' privilege(s) found'  AS detail
    FROM information_schema.object_privileges
    WHERE grantee_name = 'SYSADMIN'
      AND object_type   = 'DATABASE'
      AND object_name  IN ('RAW_DB', 'CLEANSED_DB')

    UNION ALL

    -- Check: Audit table no DELETE privilege
    SELECT
        'AUDIT'             AS category,
        'Audit Table Immutability' AS check_name,
        CASE WHEN COUNT(*) = 0 THEN '✅ PASS' ELSE '❌ CRITICAL FAIL' END AS result,
        COUNT(*) || ' destructive privilege(s) found'  AS detail
    FROM information_schema.object_privileges
    WHERE object_catalog   = 'AUDIT_DB'
      AND privilege_type  IN ('DELETE', 'UPDATE', 'TRUNCATE')
      AND object_type      = 'TABLE'

    UNION ALL

    -- Check: Row-access policy exists
    SELECT
        'POLICY'            AS category,
        'Hospital Isolation Policy Exists' AS check_name,
        CASE WHEN COUNT(*) > 0 THEN '✅ PASS' ELSE '❌ FAIL' END AS result,
        COUNT(*) || ' row-access policies found' AS detail
    FROM snowflake.account_usage.row_access_policies
    WHERE policy_name = 'PATIENT_HOSPITAL_ISOLATION'

    UNION ALL

    -- Check: Masking policies exist
    SELECT
        'POLICY'            AS category,
        'Masking Policies (expect ≥12)' AS check_name,
        CASE WHEN COUNT(*) >= 12 THEN '✅ PASS' ELSE '⚠️ WARNING' END AS result,
        COUNT(*) || ' masking policies found'  AS detail
    FROM snowflake.account_usage.masking_policies
    WHERE policy_name LIKE 'MASK_%'

    UNION ALL

    -- Check: DLP task is running
    SELECT
        'AUDIT'             AS category,
        'DLP Monitoring Task Active' AS check_name,
        CASE WHEN COUNT(*) > 0 THEN '✅ PASS' ELSE '❌ FAIL' END AS result,
        state AS detail
    FROM snowflake.account_usage.task_history
    WHERE name = 'DLP_MONITORING_TASK'
      AND state = 'SUCCEEDED'
      AND SCHEDULED_TIME >= DATEADD('hour', -1, CURRENT_TIMESTAMP())
    HAVING COUNT(*) > 0
)
SELECT
    category,
    check_name,
    result,
    detail
FROM checks
ORDER BY
    CASE result
        WHEN '❌ CRITICAL FAIL' THEN 1
        WHEN '❌ FAIL'          THEN 2
        WHEN '⚠️ WARNING'      THEN 3
        WHEN '⚠️ REVIEW'       THEN 4
        ELSE 5
    END,
    category,
    check_name;


-- =============================================================================
-- END OF FILE
-- To run this as an automated weekly check, wrap in a Snowflake Task and
-- insert results into AUDIT_DB.PUBLIC.validation_results
-- =============================================================================