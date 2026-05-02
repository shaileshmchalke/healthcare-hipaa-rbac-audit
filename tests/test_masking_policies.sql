-- =============================================================================
-- FILE: tests/test_masking_policies.sql
-- PURPOSE: Behavioral verification of all masking policies across all roles
-- AUTHOR: Security Architecture Team
-- VERSION: 1.0
--
-- HOW TO RUN:
--   1. Run as SECURITYADMIN to create test infrastructure
--   2. Switch roles (as documented per test) to verify masking behavior
--   3. Compare results against EXPECTED columns
--   4. All tests should show ✅ — any ❌ is a compliance gap
--
-- IMPORTANT: These tests require synthetic (fake) patient data.
--   NEVER run against real PHI data.
--   Use the synthetic seed data provided in this file.
--
-- ESTIMATED RUNTIME: ~10 minutes (including role switches)
-- =============================================================================


-- =============================================================================
-- SECTION 1: TEST INFRASTRUCTURE SETUP
-- Run as SECURITYADMIN
-- =============================================================================

USE ROLE SECURITYADMIN;
USE WAREHOUSE ANALYTICS_WH;

-- Create synthetic test data (NOT real PHI — all values are clearly fake)
CREATE OR REPLACE TEMPORARY TABLE cleansed_db.clinical.test_patients_synthetic AS
SELECT
    'TEST-001'           AS patient_id,
    'H01'                AS hospital_id,
    'John Test-Patient'  AS patient_name,       -- Clearly synthetic name
    '999-99-0001'        AS patient_ssn,         -- 999 prefix = SSN test block (not real)
    '1978-03-15'::DATE   AS patient_dob,
    'MRN-SYNTHETIC-001'  AS patient_mrn,
    '555-TEST-0001'      AS patient_phone,       -- 555 = test numbers (not real)
    'test.patient@example.com' AS patient_email, -- example.com = not real
    '123 Test Street'    AS patient_address_1,
    '45201'              AS patient_zip,
    'E11.65'             AS primary_dx_code,     -- Type 2 diabetes w/ complications
    '2024-01-10'::DATE   AS admission_date,
    '2024-01-15'::DATE   AS discharge_date,
    '1234567890'         AS attending_npi        -- NPI test value

UNION ALL SELECT
    'TEST-002', 'H02',
    'Jane Synthetic-Test',
    '999-99-0002',
    '1925-07-04'::DATE,   -- Born 1925 → should trigger 90+ age cap (DS_ROLE)
    'MRN-SYNTHETIC-002',
    '555-TEST-0002',
    'jane.test@example.com',
    '456 Demo Avenue',
    '46201',
    'C7A.1',              -- Rare carcinoid tumor — should be truncated to 'C7A' for ANALYST
    '2024-02-01'::DATE,
    '2024-02-05'::DATE,
    '0987654321';

-- Apply masking policies to the test table (same as production)
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_name     SET MASKING POLICY phi_policies_db.phi.mask_patient_name;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_ssn      SET MASKING POLICY phi_policies_db.phi.mask_ssn;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_dob      SET MASKING POLICY phi_policies_db.phi.mask_dob;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_mrn      SET MASKING POLICY phi_policies_db.phi.mask_mrn;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_phone    SET MASKING POLICY phi_policies_db.phi.mask_phone;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_email    SET MASKING POLICY phi_policies_db.phi.mask_email;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_address_1 SET MASKING POLICY phi_policies_db.phi.mask_address_street;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_zip      SET MASKING POLICY phi_policies_db.phi.mask_zip_code;
ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN primary_dx_code  SET MASKING POLICY phi_policies_db.phi.mask_diagnosis_code;


SELECT '✅ Test infrastructure ready. Now run Section 2 tests with role switches.' AS status;


-- =============================================================================
-- SECTION 2: MASKING BEHAVIOR TESTS
--
-- Run each block SEPARATELY after switching to the indicated role.
-- Expected results documented inline.
-- =============================================================================


-- -----------------------------------------------------------------------
-- TEST SET A: HIPAA_OFFICER — Full PHI visibility (no masking)
-- -----------------------------------------------------------------------
-- Switch role first: USE ROLE HIPAA_OFFICER;

/*
USE ROLE HIPAA_OFFICER;
USE WAREHOUSE PHI_WH;

SELECT
    patient_id,
    patient_name,
    patient_ssn,
    patient_dob::STRING        AS patient_dob,
    patient_mrn,
    patient_zip,
    primary_dx_code,
    '--- EXPECTED RESULTS ---'   AS separator,
    'John Test-Patient'          AS expected_name,
    '999-99-0001'                AS expected_ssn,
    '1978-03-15'                 AS expected_dob,
    'MRN-SYNTHETIC-001'          AS expected_mrn,
    '45201'                      AS expected_zip,
    'E11.65'                     AS expected_dx
FROM cleansed_db.clinical.test_patients_synthetic
WHERE patient_id = 'TEST-001';

-- PASS criteria:
-- patient_name    = 'John Test-Patient'      ← Full name ✅
-- patient_ssn     = '999-99-0001'            ← Full SSN ✅
-- patient_dob     = '1978-03-15'             ← Full DOB ✅
-- patient_mrn     = 'MRN-SYNTHETIC-001'      ← Full MRN ✅
-- patient_zip     = '45201'                  ← Full ZIP ✅
-- primary_dx_code = 'E11.65'                 ← Full ICD-10 ✅
*/


-- -----------------------------------------------------------------------
-- TEST SET B: HOSPITAL_ADMIN_H01 — Partial masking (last 4 SSN, full rest)
-- -----------------------------------------------------------------------
/*
USE ROLE HOSPITAL_ADMIN_H01;
USE WAREHOUSE ANALYTICS_WH;

SELECT
    patient_id,
    hospital_id,       -- Should only see H01 (row-access policy)
    patient_name,
    patient_ssn,
    patient_dob::STRING AS patient_dob,
    patient_mrn,
    patient_zip,
    primary_dx_code
FROM cleansed_db.clinical.test_patients_synthetic;

-- PASS criteria for TEST-001 (H01 patient):
-- hospital_id     = 'H01'                    ← Only H01 visible (row-access) ✅
-- patient_name    = 'John Test-Patient'      ← Full name ✅
-- patient_ssn     = 'XXX-XX-0001'            ← Last 4 only ✅
-- patient_dob     = '1978-03-15'             ← Full DOB ✅
-- patient_mrn     = 'MRN-SYNTHETIC-001'      ← Full MRN ✅
-- patient_zip     = '45201'                  ← Full ZIP ✅
-- primary_dx_code = 'E11.65'                 ← Full ICD-10 ✅

-- PASS criteria: TEST-002 (H02 patient) should NOT appear (row-access isolation)
-- Expected row count: 1 (only TEST-001 visible)
*/


-- -----------------------------------------------------------------------
-- TEST SET C: ANALYST_CLINICAL — Heavy masking, year-only DOB
-- -----------------------------------------------------------------------
/*
USE ROLE ANALYST_CLINICAL;
USE WAREHOUSE ANALYTICS_WH;

SELECT
    patient_id,
    patient_name,
    patient_ssn,
    patient_dob::STRING   AS patient_dob,
    patient_mrn,
    patient_zip,
    primary_dx_code
FROM cleansed_db.clinical.test_patients_synthetic
WHERE patient_id = 'TEST-001';

-- PASS criteria:
-- patient_name    = 'J***'                   ← First initial only ✅
-- patient_ssn     = 'XXX-XX-XXXX'            ← Fully masked ✅
-- patient_dob     = '1978-01-01'             ← Year only ✅
-- patient_mrn     = 'MRN-<12char_token>'     ← Deterministic token ✅
-- patient_zip     = '452**'                  ← First 3 digits ✅
-- primary_dx_code = 'E11'                    ← Category only ✅
*/


-- -----------------------------------------------------------------------
-- TEST SET D: DS_ROLE — De-identified, 90+ age cap
-- -----------------------------------------------------------------------
/*
USE ROLE DS_ROLE;
USE WAREHOUSE ANALYTICS_WH;

SELECT
    patient_id,
    patient_name,
    patient_ssn,
    patient_dob::STRING   AS patient_dob,
    patient_mrn,
    patient_zip,
    primary_dx_code
FROM cleansed_db.clinical.test_patients_synthetic;

-- PASS criteria for TEST-001 (born 1978):
-- patient_name    = '***'                    ← Fully masked ✅
-- patient_ssn     = NULL                     ← NULL (DS_ROLE has no SSN need) ✅
-- patient_dob     = '1978-01-01'             ← Year only ✅
-- patient_mrn     = 'MRN-<12char_token>'     ← Deterministic token ✅

-- PASS criteria for TEST-002 (born 1925 → age 99):
-- patient_dob     = '1930-01-01'             ← MUST show 1930 (90+ cap) ✅
-- Any other year = HIPAA §164.514(b)(2)(i) VIOLATION ❌
*/


-- -----------------------------------------------------------------------
-- TEST SET E: NULL HANDLING — Ensure NULL input returns NULL (not error)
-- -----------------------------------------------------------------------
-- Run as SECURITYADMIN

USE ROLE SECURITYADMIN;

-- Insert a record with NULL PHI fields
INSERT INTO cleansed_db.clinical.test_patients_synthetic
    (patient_id, hospital_id, patient_name, patient_ssn, patient_dob, patient_mrn,
     patient_phone, patient_email, patient_address_1, patient_zip, primary_dx_code,
     admission_date, discharge_date, attending_npi)
VALUES
    ('TEST-NULL', 'H01', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     '2024-03-01', '2024-03-02', '1111111111');

-- Now switch to ANALYST and query — all masked NULL fields should return NULL (not error)
/*
USE ROLE ANALYST_CLINICAL;
SELECT patient_id, patient_name, patient_ssn, patient_dob, patient_mrn
FROM cleansed_db.clinical.test_patients_synthetic
WHERE patient_id = 'TEST-NULL';

-- PASS criteria:
-- patient_name    = NULL   ← Not '***' or error ✅
-- patient_ssn     = NULL   ← Not 'XXX-XX-XXXX' or error ✅
-- patient_dob     = NULL   ← Not '1970-01-01' or error ✅
-- patient_mrn     = NULL   ← Not 'MRN-null...' or error ✅
*/


-- =============================================================================
-- SECTION 3: AUTOMATED PASS/FAIL VALIDATION
-- Run as SECURITYADMIN after completing the manual tests above
-- This produces a summary scorecard
-- =============================================================================

USE ROLE SECURITYADMIN;

WITH test_results AS (
    -- Verify masking policies are applied to the test table
    SELECT
        ref.ref_column_name                          AS column_name,
        ref.policy_name,
        CASE WHEN ref.policy_name IS NOT NULL
             THEN '✅ PASS — Policy applied'
             ELSE '❌ FAIL — No masking policy'
        END                                          AS result
    FROM snowflake.account_usage.policy_references ref
    WHERE ref.ref_database_name  = 'CLEANSED_DB'
      AND ref.ref_entity_name    = 'TEST_PATIENTS_SYNTHETIC'
      AND ref.policy_kind        = 'MASKING_POLICY'
)
SELECT
    column_name,
    policy_name,
    result
FROM test_results
ORDER BY column_name;

-- Expected: 10 rows, all showing ✅ PASS


-- =============================================================================
-- SECTION 4: CLEANUP TEST OBJECTS
-- Run after all tests complete
-- =============================================================================

USE ROLE SECURITYADMIN;

ALTER TABLE cleansed_db.clinical.test_patients_synthetic
    MODIFY COLUMN patient_name      UNSET MASKING POLICY,
    MODIFY COLUMN patient_ssn       UNSET MASKING POLICY,
    MODIFY COLUMN patient_dob       UNSET MASKING POLICY,
    MODIFY COLUMN patient_mrn       UNSET MASKING POLICY,
    MODIFY COLUMN patient_phone     UNSET MASKING POLICY,
    MODIFY COLUMN patient_email     UNSET MASKING POLICY,
    MODIFY COLUMN patient_address_1 UNSET MASKING POLICY,
    MODIFY COLUMN patient_zip       UNSET MASKING POLICY,
    MODIFY COLUMN primary_dx_code   UNSET MASKING POLICY;

DROP TABLE IF EXISTS cleansed_db.clinical.test_patients_synthetic;

SELECT '✅ Test objects cleaned up successfully.' AS status;

-- =============================================================================
-- END OF FILE
-- =============================================================================