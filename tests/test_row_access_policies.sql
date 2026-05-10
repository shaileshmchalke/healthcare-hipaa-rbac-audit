-- =============================================================================
-- FILE: tests/test_row_access_policies.sql
-- PURPOSE: Behavioral tests for hospital isolation row-access policy
-- VERSION: 1.0
--
-- EXECUTION ROLE: SECURITYADMIN (setup), then switch roles per test
-- DEPENDENCIES: synthetic_data.sql must be run first (uses DEMO_DB)
--
-- TESTS COVERED:
--   A. Hospital isolation: H01 role cannot see H02 patients
--   B. HIPAA_OFFICER bypass: cross-hospital visibility
--   C. Time-bounded access: expired mappings are blocked
--   D. mapping_table audit: every grant has required fields
-- =============================================================================

USE ROLE SECURITYADMIN;
USE WAREHOUSE ANALYTICS_WH;

SELECT '=== ROW ACCESS POLICY TESTS STARTING ===' AS test_status;


-- =============================================================================
-- TEST A: Hospital Isolation
-- HOSPITAL_ADMIN_H01 must see only H01 rows
-- HOSPITAL_ADMIN_H02 must see only H02 rows
-- =============================================================================

-- Test A1: Count by hospital for H01 role
/*
USE ROLE HOSPITAL_ADMIN_H01;
SELECT
    hospital_id,
    COUNT(*) AS patient_count,
    CASE WHEN hospital_id = 'H01' THEN 'EXPECTED'
         ELSE 'UNEXPECTED - isolation breach' END AS result
FROM demo_db.clinical.patients
GROUP BY hospital_id
ORDER BY hospital_id;

-- PASS: Only H01 row appears
-- FAIL: Any other hospital_id appearing = isolation failure
*/

-- Test A2: Cross-hospital join attempt (should return 0 rows)
/*
USE ROLE HOSPITAL_ADMIN_H01;
SELECT COUNT(*) AS cross_hospital_rows
FROM demo_db.clinical.patients
WHERE hospital_id != 'H01';

-- PASS: 0 rows (row-access policy filters before WHERE clause evaluates)
*/


-- =============================================================================
-- TEST B: HIPAA_OFFICER bypass
-- HIPAA_OFFICER must see ALL hospitals (cross-hospital access)
-- =============================================================================

/*
USE ROLE HIPAA_OFFICER;
SELECT
    hospital_id,
    COUNT(*) AS patient_count
FROM demo_db.clinical.patients
GROUP BY hospital_id
ORDER BY hospital_id;

-- PASS: All 12 hospitals visible (H01 through H12)
-- FAIL: Any hospital missing = bypass not working
*/


-- =============================================================================
-- TEST C: Time-bounded access
-- Insert a mapping with expired effective_to date
-- That role should see 0 rows after expiry
-- =============================================================================

USE ROLE SECURITYADMIN;

-- Insert an expired mapping for testing
INSERT INTO phi_policies_db.phi.hospital_role_map
    (snowflake_role, hospital_id, effective_from, effective_to,
     granted_by, business_reason, ticket_ref)
VALUES
    ('DS_ROLE', 'H01',
     DATEADD('day', -90, CURRENT_DATE()),
     DATEADD('day', -1, CURRENT_DATE()),  -- expired yesterday
     CURRENT_USER(), 'Test: expired access for DS_ROLE', 'TEST-001');

-- Now DS_ROLE should see 0 H01 rows (mapping expired)
/*
USE ROLE DS_ROLE;
SELECT COUNT(*) AS expired_access_rows
FROM demo_db.clinical.patients
WHERE hospital_id = 'H01';

-- PASS: 0 rows (expired mapping correctly blocks access)
-- FAIL: Any rows returned = time-bounded access not enforced
*/

-- Cleanup test mapping
DELETE FROM phi_policies_db.phi.hospital_role_map
WHERE snowflake_role = 'DS_ROLE'
  AND hospital_id = 'H01'
  AND ticket_ref = 'TEST-001';


-- =============================================================================
-- TEST D: hospital_role_map data quality
-- Every active mapping must have all required fields
-- =============================================================================

USE ROLE SECURITYADMIN;

SELECT
    snowflake_role,
    hospital_id,
    effective_from,
    effective_to,
    granted_by,
    ticket_ref,
    CASE
        WHEN granted_by IS NULL     THEN 'FAIL: missing granted_by'
        WHEN ticket_ref IS NULL     THEN 'FAIL: missing ticket_ref'
        WHEN business_reason IS NULL THEN 'FAIL: missing business_reason'
        WHEN effective_from IS NULL THEN 'FAIL: missing effective_from'
        ELSE 'PASS'
    END AS data_quality_check
FROM phi_policies_db.phi.hospital_role_map
WHERE effective_to IS NULL OR effective_to >= CURRENT_DATE()
ORDER BY snowflake_role, hospital_id;

-- Expected: All rows show PASS
-- Any FAIL row = incomplete audit trail = SOC2 CC6 finding


-- =============================================================================
-- TEST E: Policy is applied to all required tables
-- =============================================================================

USE ROLE SECURITYADMIN;

WITH required_tables AS (
    SELECT column1 AS db, column2 AS schema_name, column3 AS tbl
    FROM VALUES
        ('CLEANSED_DB', 'CLINICAL',  'PATIENTS'),
        ('RAW_DB',      'EHR',       'PATIENT_DEMOGRAPHICS'),
        ('RAW_DB',      'BILLING',   'CLAIMS')
),
applied_policies AS (
    SELECT
        ref.ref_database_name  AS db,
        ref.ref_schema_name    AS schema_name,
        ref.ref_entity_name    AS tbl
    FROM snowflake.account_usage.policy_references ref
    WHERE ref.policy_kind  = 'ROW_ACCESS_POLICY'
      AND ref.policy_name  = 'PATIENT_HOSPITAL_ISOLATION'
)
SELECT
    r.db,
    r.schema_name,
    r.tbl,
    CASE WHEN a.tbl IS NOT NULL THEN 'PASS: policy applied'
         ELSE 'FAIL: policy missing'
    END AS policy_check
FROM required_tables r
LEFT JOIN applied_policies a
    ON  a.db          = r.db
    AND a.schema_name = r.schema_name
    AND a.tbl         = r.tbl
ORDER BY r.db, r.tbl;

-- Expected: All rows show PASS
-- Any FAIL = unprotected table = HIPAA gap

SELECT '=== ROW ACCESS POLICY TESTS COMPLETE ===' AS test_status;

-- =============================================================================
-- END OF FILE
-- =============================================================================