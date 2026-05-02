-- =============================================================================
-- FILE: sql/policies.sql
-- PURPOSE: Dynamic Data Masking Policies and Row-Access Policies for HIPAA PHI
-- AUTHOR: Security Architecture Team
-- VERSION: 2.8 (Production)
--
-- DEPENDENCIES: setup_rbac.sql must be run first
-- EXECUTION ROLE: SECURITYADMIN
--
-- HIPAA REFERENCES:
--   §164.312(a)(1)  — Access Control (role-based)
--   §164.514(b)     — De-identification (Safe Harbor method)
--   §164.514(e)     — Limited data sets
--
-- DESIGN PRINCIPLES:
--   1. Default deny: If role is not explicitly exempted, PHI is masked
--   2. Least privilege: ANALYST sees minimum necessary PHI for their function
--   3. Consistency: Same patient's SSN tokenizes identically across all tables
--   4. Auditability: Policy assignments are tracked in PHI_POLICIES_DB
-- =============================================================================

USE ROLE SECURITYADMIN;
USE DATABASE PHI_POLICIES_DB;
USE SCHEMA PHI;


-- =============================================================================
-- SECTION 1: HOSPITAL-ROLE MAPPING TABLE
-- Central authority for row-level access control.
-- This table is the single source of truth for which roles access which hospitals.
-- LESSON LEARNED: We initially hard-coded hospital IDs in the policy function.
--   Adding a 13th hospital required an ALTER POLICY statement (a DDL change that
--   requires CAB approval and a deployment pipeline). Using a mapping table means
--   adding a hospital is just an INSERT — no code change, no deployment.
-- =============================================================================

CREATE TABLE IF NOT EXISTS PHI_POLICIES_DB.PHI.hospital_role_map (
    map_id          STRING  DEFAULT UUID_STRING() NOT NULL,
    snowflake_role  STRING  NOT NULL,
    hospital_id     STRING  NOT NULL,
    access_type     STRING  NOT NULL DEFAULT 'READ',  -- 'READ', 'READ_WRITE'
    effective_from  DATE    NOT NULL,
    effective_to    DATE,               -- NULL = currently active, no end date
    granted_by      STRING  NOT NULL,   -- User who inserted this record
    business_reason STRING  NOT NULL,   -- Why this access was granted
    ticket_ref      STRING,             -- ServiceNow/JIRA change ticket
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    CONSTRAINT pk_hrm PRIMARY KEY (snowflake_role, hospital_id)
);

-- Seed with initial hospital-role mappings
INSERT INTO PHI_POLICIES_DB.PHI.hospital_role_map
    (snowflake_role, hospital_id, effective_from, granted_by, business_reason, ticket_ref)
VALUES
    ('HOSPITAL_ADMIN_H01', 'H01', '2024-01-01', 'SECURITYADMIN', 'Hospital H01 Cincinnati staff access', 'CHG0001001'),
    ('HOSPITAL_ADMIN_H02', 'H02', '2024-01-01', 'SECURITYADMIN', 'Hospital H02 Dayton staff access', 'CHG0001002'),
    ('HOSPITAL_ADMIN_H03', 'H03', '2024-01-01', 'SECURITYADMIN', 'Hospital H03 Cleveland staff access', 'CHG0001003'),
    ('HOSPITAL_ADMIN_H04', 'H04', '2024-01-01', 'SECURITYADMIN', 'Hospital H04 Columbus staff access', 'CHG0001004'),
    ('HOSPITAL_ADMIN_H05', 'H05', '2024-01-01', 'SECURITYADMIN', 'Hospital H05 Toledo staff access', 'CHG0001005'),
    ('HOSPITAL_ADMIN_H06', 'H06', '2024-01-01', 'SECURITYADMIN', 'Hospital H06 Akron staff access', 'CHG0001006'),
    ('HOSPITAL_ADMIN_H07', 'H07', '2024-01-01', 'SECURITYADMIN', 'Hospital H07 Indianapolis staff access', 'CHG0001007'),
    ('HOSPITAL_ADMIN_H08', 'H08', '2024-01-01', 'SECURITYADMIN', 'Hospital H08 Fort Wayne staff access', 'CHG0001008'),
    ('HOSPITAL_ADMIN_H09', 'H09', '2024-01-01', 'SECURITYADMIN', 'Hospital H09 Evansville staff access', 'CHG0001009'),
    ('HOSPITAL_ADMIN_H10', 'H10', '2024-01-01', 'SECURITYADMIN', 'Hospital H10 Louisville staff access', 'CHG0001010'),
    ('HOSPITAL_ADMIN_H11', 'H11', '2024-01-01', 'SECURITYADMIN', 'Hospital H11 Lexington staff access', 'CHG0001011'),
    ('HOSPITAL_ADMIN_H12', 'H12', '2024-01-01', 'SECURITYADMIN', 'Hospital H12 Ann Arbor staff access', 'CHG0001012');


-- =============================================================================
-- SECTION 2: DYNAMIC DATA MASKING POLICIES
--
-- NAMING CONVENTION: mask_<field_type>
-- APPLIES TO: CLEANSED_DB tables (and RAW_DB tables via separate application)
--
-- ROLE EXEMPTION HIERARCHY (most permissive to least):
--   ACCOUNTADMIN, HIPAA_OFFICER, PHI_READER  → Full unmasked PHI
--   HOSPITAL_ADMIN_H*                         → Partially unmasked (treating provider)
--   ANALYST_CLINICAL, ANALYST_REVENUE         → Heavily masked
--   DS_ROLE                                   → De-identified (year only, etc.)
--   Everything else (default)                 → Fully masked / NULL
-- =============================================================================


-- POLICY 1: Social Security Number (SSN)
-- Most sensitive PHI field. Format: XXX-XX-XXXX
-- LESSON LEARNED: We originally used SHA-256 here. Broke cross-table joins because
--   billing table hashed '123456789' while EHR hashed '123-45-6789'.
--   See README "What Didn't Work Initially" for full story.
--   Solution: Format-Preserving Encryption via external tokenization.
--   In this reference implementation, we simulate FPE with a deterministic mask.
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_ssn
    AS (ssn_val STRING) RETURNS STRING ->
    CASE
        WHEN ssn_val IS NULL THEN NULL                         -- ✅ NULL guard — prevents edge case failures
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN ssn_val                                        -- Full SSN — authorized roles only
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN 'XXX-XX-' || RIGHT(REGEXP_REPLACE(ssn_val, '-', ''), 4)  -- Last 4 only
        WHEN CURRENT_ROLE() IN ('ANALYST_CLINICAL', 'ANALYST_REVENUE')
            THEN 'XXX-XX-XXXX'                                 -- Fully masked
        WHEN CURRENT_ROLE() = 'DS_ROLE'
            THEN NULL                                           -- NULL for data scientists — no SSN needed
        ELSE 'XXX-XX-XXXX'                                     -- Default: fully mask
    END;


-- POLICY 2: Patient Date of Birth (DOB)
-- HIPAA §164.514(b)(2)(i): Ages over 90 must be aggregated.
-- Note the special handling for DS_ROLE to cap birth year at 1930 (age 90+ as of 2024).
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_dob
    AS (dob_val DATE) RETURNS DATE ->
    CASE
        WHEN dob_val IS NULL THEN NULL                         -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN dob_val                                        -- Full DOB
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN dob_val                                        -- Full DOB — treating providers need this
        WHEN CURRENT_ROLE() IN ('ANALYST_CLINICAL', 'ANALYST_REVENUE')
            THEN DATE_FROM_PARTS(YEAR(dob_val), 1, 1)          -- Year only: e.g., 1978-01-01
        WHEN CURRENT_ROLE() = 'DS_ROLE'
            THEN DATE_FROM_PARTS(
                     CASE WHEN YEAR(dob_val) < 1930 THEN 1930   -- Cap at 1930 for 90+ age compliance
                          ELSE YEAR(dob_val)
                     END, 1, 1)
        ELSE NULL
    END;


-- POLICY 3: Patient Full Name
-- Returns progressively less information by role
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_patient_name
    AS (name_val STRING) RETURNS STRING ->
    CASE
        WHEN name_val IS NULL THEN NULL                        -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN name_val                                       -- Full name
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN name_val                                       -- Full name — clinical use
        WHEN CURRENT_ROLE() IN ('ANALYST_CLINICAL', 'ANALYST_REVENUE')
            THEN LEFT(name_val, 1) || '***'                     -- First initial only: 'J***'
        ELSE '***'                                              -- Fully masked
    END;


-- POLICY 4: Medical Record Number (MRN)
-- MRN is a facility-specific direct identifier under HIPAA.
-- Analysts get a deterministic but opaque token (consistent for joins, meaningless externally)
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_mrn
    AS (mrn_val STRING) RETURNS STRING ->
    CASE
        WHEN mrn_val IS NULL THEN NULL                         -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN mrn_val                                        -- Real MRN
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN mrn_val                                        -- Real MRN for clinical staff
        WHEN CURRENT_ROLE() IN ('ANALYST_CLINICAL', 'ANALYST_REVENUE', 'DS_ROLE')
            -- Deterministic token: always same output for same input = join-safe
            -- SHA2 of MRN + static salt → truncated to 12 chars → 'MRN-' prefix for readability
            THEN 'MRN-' || LEFT(SHA2(mrn_val || 'HIPAA_SALT_2024_V2'), 12)
        ELSE '***'
    END;


-- POLICY 5: Patient Phone Number
-- No partial reveal at any analyst tier — too re-identifiable even with partial data
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_phone
    AS (phone_val STRING) RETURNS STRING ->
    CASE
        WHEN phone_val IS NULL THEN NULL                       -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN phone_val
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN phone_val                                      -- Hospital staff need to contact patients
        ELSE '***-***-****'
    END;


-- POLICY 6: Patient Address (Street)
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_address_street
    AS (addr_val STRING) RETURNS STRING ->
    CASE
        WHEN addr_val IS NULL THEN NULL                        -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN addr_val
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN addr_val
        ELSE '*** REDACTED ***'
    END;


-- POLICY 7: Patient Address (ZIP Code)
-- HIPAA Safe Harbor: Only first 3 digits of ZIP if population > 20,000.
-- Zip codes with population < 20,000 must be replaced with '000'.
-- We use first 3 digits for all analysts as a conservative safe harbor compliance approach.
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_zip_code
    AS (zip_val STRING) RETURNS STRING ->
    CASE
        WHEN zip_val IS NULL THEN NULL                         -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN zip_val                                        -- Full ZIP
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN zip_val                                        -- Full ZIP
        WHEN CURRENT_ROLE() IN ('ANALYST_CLINICAL', 'ANALYST_REVENUE')
            THEN LEFT(zip_val, 3) || '**'                      -- First 3 digits: e.g., '452**'
        WHEN CURRENT_ROLE() = 'DS_ROLE'
            THEN LEFT(zip_val, 3) || '**'                      -- First 3 digits only
        ELSE '00000'
    END;


-- POLICY 8: Patient Email Address
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_email
    AS (email_val STRING) RETURNS STRING ->
    CASE
        WHEN email_val IS NULL THEN NULL                       -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN email_val
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN email_val
        ELSE '***@***.***'
    END;


-- POLICY 9: Diagnosis Code (ICD-10)
-- Full ICD-10 code can re-identify rare disease patients.
-- Analysts get the 3-character category (e.g., 'E11' for Type 2 Diabetes instead of 'E11.65')
-- LESSON LEARNED: A researcher had a dataset of 50-year-old males with diagnosis code 'C7A.1'
--   (malignant carcinoid tumor of midgut — ~400 cases/year in the US). Combined with hospital and
--   year-of-birth, this single patient was re-identifiable. Truncating to category level
--   was the audit finding that prompted this policy revision.
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_diagnosis_code
    AS (dx_val STRING) RETURNS STRING ->
    CASE
        WHEN dx_val IS NULL THEN NULL                          -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN dx_val                                         -- Full ICD-10 code
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN dx_val                                         -- Full code for clinical staff
        WHEN CURRENT_ROLE() IN ('ANALYST_CLINICAL', 'ANALYST_REVENUE')
            THEN LEFT(dx_val, 3)                               -- Category only: 'E11' not 'E11.65'
        WHEN CURRENT_ROLE() = 'DS_ROLE'
            THEN LEFT(dx_val, 3)                               -- Category only
        ELSE '***'
    END;


-- POLICY 10: Drug/Medication Name (from pharmacy records)
-- Certain medications are re-identifying (HIV medications, rare disease treatments)
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_medication_name
    AS (med_val STRING) RETURNS STRING ->
    CASE
        WHEN med_val IS NULL THEN NULL                         -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN med_val
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN med_val
        WHEN CURRENT_ROLE() IN ('ANALYST_CLINICAL', 'ANALYST_REVENUE')
            THEN med_val                                        -- Medication name is OK for analysts (not a direct identifier)
        WHEN CURRENT_ROLE() = 'DS_ROLE'
            THEN med_val                                        -- OK for population health research
        ELSE '***'
    END;


-- POLICY 11: Provider/Physician NPI
-- NPI is a public identifier but can be used to correlate with patient data
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_npi
    AS (npi_val STRING) RETURNS STRING ->
    CASE
        WHEN npi_val IS NULL THEN NULL                         -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER',
                                 'ANALYST_CLINICAL', 'ANALYST_REVENUE', 'DS_ROLE')
            THEN npi_val                                        -- NPI is public — OK to show
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN npi_val
        ELSE '**********'
    END;


-- POLICY 12: Patient Account Number (billing)
CREATE OR REPLACE MASKING POLICY PHI_POLICIES_DB.PHI.mask_account_number
    AS (acct_val STRING) RETURNS STRING ->
    CASE
        WHEN acct_val IS NULL THEN NULL                        -- ✅ NULL guard
        WHEN CURRENT_ROLE() IN ('ACCOUNTADMIN', 'HIPAA_OFFICER', 'PHI_READER')
            THEN acct_val
        WHEN CURRENT_ROLE() LIKE 'HOSPITAL_ADMIN_%'
            THEN acct_val
        WHEN CURRENT_ROLE() IN ('ANALYST_REVENUE')
            -- Revenue analysts need to track payment patterns but not the actual account number
            THEN 'ACCT-' || LEFT(SHA2(acct_val || 'BILLING_SALT_V2'), 8)
        ELSE '***'
    END;


-- =============================================================================
-- SECTION 3: ROW-ACCESS POLICY — HOSPITAL ISOLATION
--
-- This is the most architecturally important security control.
-- Every query against patient tables is filtered by this policy.
--
-- PERFORMANCE NOTE: This policy uses a subquery against hospital_role_map.
--   On large fact tables (2B+ rows), this WILL cause performance issues without
--   clustering on hospital_id. See README for the full performance failure story.
--
--   MANDATORY: Any table that gets this policy applied MUST have hospital_id as
--   a clustering key or be clustered on (hospital_id, <date_column>).
-- =============================================================================

CREATE OR REPLACE ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation
    AS (hospital_id STRING) RETURNS BOOLEAN ->
    -- Bypass: Authorized cross-hospital roles
    CURRENT_ROLE() IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'HIPAA_OFFICER', 'PHI_READER')
    -- Hospital-specific access: Check the mapping table
    OR EXISTS (
        SELECT 1
        FROM PHI_POLICIES_DB.PHI.hospital_role_map hrm
        WHERE hrm.snowflake_role  = CURRENT_ROLE()
          AND hrm.hospital_id     = hospital_id
          AND hrm.effective_from  <= CURRENT_DATE()
          AND (hrm.effective_to IS NULL OR hrm.effective_to >= CURRENT_DATE())
    );


-- =============================================================================
-- SECTION 4: APPLY POLICIES TO TABLES
-- This section assumes the CLEANSED_DB tables already exist.
-- In practice, this is run as part of the table creation DDL,
-- or via a post-deployment step in the CI/CD pipeline.
-- =============================================================================

-- Sample patient table structure for reference
-- (In production, this table is created by the EHR ETL pipeline)
CREATE TABLE IF NOT EXISTS CLEANSED_DB.CLINICAL.patients (
    patient_id          STRING       NOT NULL,  -- Internal PK (not SSN, not MRN)
    hospital_id         STRING       NOT NULL,  -- Foreign key → drives row-access policy
    patient_name        STRING,
    patient_ssn         STRING,
    patient_dob         DATE,
    patient_mrn         STRING,
    patient_phone       STRING,
    patient_email       STRING,
    patient_address_1   STRING,
    patient_zip         STRING,
    primary_dx_code     STRING,
    admission_date      DATE,
    discharge_date      DATE,
    attending_npi       STRING,
    created_at          TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at          TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
)
CLUSTER BY (hospital_id, admission_date)  -- MANDATORY: required for row-access policy performance
DATA_RETENTION_TIME_IN_DAYS = 30
COMMENT = 'Cleansed patient demographics. DDM + Row-Access applied.';

-- Apply Dynamic Data Masking policies to patient table
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_name     SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_patient_name;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_ssn      SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_ssn;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_dob      SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_dob;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_mrn      SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_mrn;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_phone    SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_phone;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_email    SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_email;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_address_1 SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_address_street;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN patient_zip      SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_zip_code;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN primary_dx_code  SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_diagnosis_code;
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    MODIFY COLUMN attending_npi    SET MASKING POLICY PHI_POLICIES_DB.PHI.mask_npi;

-- Apply Row-Access Policy for hospital isolation
ALTER TABLE CLEANSED_DB.CLINICAL.patients
    ADD ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation ON (hospital_id);


-- =============================================================================
-- FIX: Apply Row-Access Policy to RAW_DB tables as well
-- LESSON LEARNED: Original design only applied hospital isolation to CLEANSED_DB.
--   During internal audit review it was flagged that PHI_READER service accounts
--   querying RAW_DB had no hospital-level filter. Although PHI_READER is a trusted
--   role, defense-in-depth requires the policy at every layer.
-- PERFORMANCE NOTE: RAW_DB tables MUST have hospital_id as a clustering key
--   before this policy is applied. Verify clustering first:
--   SELECT SYSTEM$CLUSTERING_INFORMATION('RAW_DB.EHR.patient_demographics');
-- =============================================================================

-- RAW zone — EHR tables
ALTER TABLE RAW_DB.EHR.patient_demographics
    ADD ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation ON (hospital_id);

-- RAW zone — Large fact table (MUST have clustering on hospital_id first — see README failure story)
-- ALTER TABLE RAW_DB.EHR.patient_events
--     ADD ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation ON (hospital_id);
-- ↑ Uncomment only AFTER confirming: ALTER TABLE RAW_DB.EHR.patient_events CLUSTER BY (hospital_id, event_date);

-- RAW zone — Billing tables
ALTER TABLE RAW_DB.BILLING.claims
    ADD ROW ACCESS POLICY PHI_POLICIES_DB.PHI.patient_hospital_isolation ON (hospital_id);


-- =============================================================================
-- SECTION 5: POLICY REGISTRY TABLE
-- Tracks every policy assignment for compliance reporting.
-- Updated every time a policy is applied to a table.
-- =============================================================================

CREATE TABLE IF NOT EXISTS PHI_POLICIES_DB.PHI.policy_assignments (
    assignment_id   STRING    DEFAULT UUID_STRING() NOT NULL,
    policy_type     STRING    NOT NULL,  -- 'MASKING', 'ROW_ACCESS'
    policy_name     STRING    NOT NULL,
    database_name   STRING    NOT NULL,
    schema_name     STRING    NOT NULL,
    table_name      STRING    NOT NULL,
    column_name     STRING,             -- NULL for row-access policies
    applied_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    applied_by      STRING    NOT NULL DEFAULT CURRENT_USER(),
    ticket_ref      STRING,
    is_active       BOOLEAN   DEFAULT TRUE
);

-- Seed with applied policies
INSERT INTO PHI_POLICIES_DB.PHI.policy_assignments
    (policy_type, policy_name, database_name, schema_name, table_name, column_name, ticket_ref)
VALUES
    ('MASKING',     'mask_patient_name',       'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_NAME',      'CHG0002001'),
    ('MASKING',     'mask_ssn',                'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_SSN',       'CHG0002001'),
    ('MASKING',     'mask_dob',                'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_DOB',       'CHG0002001'),
    ('MASKING',     'mask_mrn',                'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_MRN',       'CHG0002001'),
    ('MASKING',     'mask_phone',              'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_PHONE',     'CHG0002001'),
    ('MASKING',     'mask_email',              'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_EMAIL',     'CHG0002001'),
    ('MASKING',     'mask_address_street',     'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_ADDRESS_1', 'CHG0002001'),
    ('MASKING',     'mask_zip_code',           'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PATIENT_ZIP',       'CHG0002001'),
    ('MASKING',     'mask_diagnosis_code',     'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'PRIMARY_DX_CODE',   'CHG0002001'),
    ('MASKING',     'mask_npi',                'CLEANSED_DB', 'CLINICAL', 'PATIENTS', 'ATTENDING_NPI',     'CHG0002001'),
    ('ROW_ACCESS',  'patient_hospital_isolation', 'CLEANSED_DB', 'CLINICAL', 'PATIENTS', NULL,             'CHG0002001');


-- =============================================================================
-- END OF FILE
-- =============================================================================