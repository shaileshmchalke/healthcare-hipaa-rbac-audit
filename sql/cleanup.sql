-- =============================================================================
-- FILE: sql/cleanup.sql
-- PURPOSE: Tear down ALL resources created by this case study
-- AUTHOR: Security Architecture Team
-- VERSION: 1.1 (Bug fix: correct DROP order)
--
-- WARNING: ONLY RUN IN DEMO / TRIAL ACCOUNT
--     NEVER RUN IN PRODUCTION
--
-- EXECUTION ROLE: ACCOUNTADMIN
--
-- BUG FIX vs v1.0:
--   DeepSeek's original cleanup.sql dropped PHI_POLICIES_DB first,
--   then tried to DROP MASKING POLICY on PHI_POLICIES_DB.PHI.mask_* —
--   which fails because the database no longer exists.
--   Masking policies must be UNSET from tables, THEN dropped,
--   THEN the database can be dropped.
--   Correct order: UNSET policies → DROP policies → DROP databases → DROP roles
--
-- ESTIMATED RUNTIME: ~3 minutes
-- =============================================================================

USE ROLE ACCOUNTADMIN;

SELECT '🔄 Starting HIPAA case study cleanup...' AS status;


-- =============================================================================
-- STEP 1: REMOVE ROW ACCESS POLICIES FROM TABLES
-- Must be done before dropping the policy object
-- =============================================================================

-- CLEANSED_DB
ALTER TABLE IF EXISTS CLEANSED_DB.CLINICAL.patients
    DROP ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation;

-- RAW_DB
ALTER TABLE IF EXISTS RAW_DB.EHR.patient_demographics
    DROP ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation;

ALTER TABLE IF EXISTS RAW_DB.EHR.patient_events
    DROP ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation;

ALTER TABLE IF EXISTS RAW_DB.BILLING.claims
    DROP ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation;


-- =============================================================================
-- STEP 2: UNSET MASKING POLICIES FROM COLUMNS
-- Must be done before dropping the masking policy objects
-- =============================================================================

ALTER TABLE IF EXISTS CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_name      UNSET MASKING POLICY,
    MODIFY COLUMN patient_ssn       UNSET MASKING POLICY,
    MODIFY COLUMN patient_dob       UNSET MASKING POLICY,
    MODIFY COLUMN patient_mrn       UNSET MASKING POLICY,
    MODIFY COLUMN patient_phone     UNSET MASKING POLICY,
    MODIFY COLUMN patient_email     UNSET MASKING POLICY,
    MODIFY COLUMN patient_address_1 UNSET MASKING POLICY,
    MODIFY COLUMN patient_zip       UNSET MASKING POLICY,
    MODIFY COLUMN primary_dx_code   UNSET MASKING POLICY,
    MODIFY COLUMN attending_npi     UNSET MASKING POLICY;


-- =============================================================================
-- STEP 3: DROP TASKS (stop before dropping databases)
-- =============================================================================

ALTER TASK IF EXISTS AUDIT_DB.PUBLIC.dlp_monitoring_task SUSPEND;
ALTER TASK IF EXISTS AUDIT_DB.PUBLIC.archive_phi_access_log SUSPEND;
DROP TASK IF EXISTS AUDIT_DB.PUBLIC.dlp_monitoring_task;
DROP TASK IF EXISTS AUDIT_DB.PUBLIC.archive_phi_access_log;


-- =============================================================================
-- STEP 4: DROP MASKING POLICIES (before dropping PHI_POLICIES_DB)
-- =============================================================================

DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_ssn;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_dob;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_patient_name;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_mrn;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_phone;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_address_street;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_zip_code;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_email;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_diagnosis_code;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_medication_name;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_npi;
DROP MASKING POLICY IF EXISTS PHI_POLICIES_DB.PHI.mask_account_number;

-- DROP ROW ACCESS POLICY (after all table references are removed in Step 1)
DROP ROW ACCESS POLICY IF EXISTS PHI_POLICIES_DB.PHI.patient_hospital_isolation;


-- =============================================================================
-- STEP 5: DROP SECURITY / AUTH POLICIES
-- =============================================================================

ALTER ACCOUNT UNSET AUTHENTICATION POLICY;
DROP AUTHENTICATION POLICY IF EXISTS hipaa_mfa_auth_policy;

ALTER ACCOUNT UNSET PASSWORD POLICY;
DROP PASSWORD POLICY IF EXISTS hipaa_password_policy;


-- =============================================================================
-- STEP 6: DROP DATABASES
-- All databases drop their schemas, tables, views automatically
-- Note: PHI_POLICIES_DB MUST be dropped AFTER policies are dropped (done in Step 4)
-- =============================================================================

DROP DATABASE IF EXISTS AUDIT_DB;
DROP DATABASE IF EXISTS MARTS_DB;
DROP DATABASE IF EXISTS CLEANSED_DB;
DROP DATABASE IF EXISTS RAW_DB;
DROP DATABASE IF EXISTS PHI_POLICIES_DB;     -- ← Drop LAST (policies already dropped above)


-- =============================================================================
-- STEP 7: DROP WAREHOUSES
-- =============================================================================

DROP WAREHOUSE IF EXISTS PHI_WH;
DROP WAREHOUSE IF EXISTS ANALYTICS_WH;
DROP WAREHOUSE IF EXISTS ETL_WH;
DROP WAREHOUSE IF EXISTS AUDIT_WH;


-- =============================================================================
-- STEP 8: DROP ROLES (reverse hierarchy order — children before parents)
-- =============================================================================

-- Analyst roles (leaf nodes)
DROP ROLE IF EXISTS ANALYST_CLINICAL;
DROP ROLE IF EXISTS ANALYST_REVENUE;
DROP ROLE IF EXISTS DS_ROLE;
DROP ROLE IF EXISTS ANALYST_BASE;

-- Hospital admin roles
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H01;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H02;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H03;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H04;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H05;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H06;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H07;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H08;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H09;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H10;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H11;
DROP ROLE IF EXISTS HOSPITAL_ADMIN_H12;

-- ETL / pipeline roles
DROP ROLE IF EXISTS DBT_ROLE;
DROP ROLE IF EXISTS PIPELINE_ROLE;
DROP ROLE IF EXISTS AUDIT_WRITER;

-- Security roles
DROP ROLE IF EXISTS AUDIT_READER;
DROP ROLE IF EXISTS PHI_READER;
DROP ROLE IF EXISTS HIPAA_OFFICER;

-- Note: SECURITYADMIN, SYSADMIN, ACCOUNTADMIN are system roles — cannot be dropped


-- =============================================================================
-- STEP 9: REMOVE NETWORK POLICY
-- Comment out in PRODUCTION — only unset in demo/trial
-- =============================================================================

ALTER ACCOUNT UNSET NETWORK_POLICY;
DROP NETWORK POLICY IF EXISTS hipaa_production_policy;


-- =============================================================================
-- FINAL: Verify cleanup
-- =============================================================================

SELECT '✅ Cleanup complete. All HIPAA case study objects removed.' AS status;

-- Confirm no custom roles remain
SHOW ROLES LIKE 'HIPAA%';
SHOW ROLES LIKE 'HOSPITAL_ADMIN%';
SHOW ROLES LIKE 'ANALYST%';
SHOW ROLES LIKE 'PHI%';
SHOW ROLES LIKE 'AUDIT%';
-- Expected: 0 rows for each

-- =============================================================================
-- END OF FILE
-- =============================================================================