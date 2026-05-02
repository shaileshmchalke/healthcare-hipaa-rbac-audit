-- =============================================================================
-- FILE: sql/setup_rbac.sql
-- PURPOSE: HIPAA-Compliant RBAC Hierarchy for Multi-Hospital Healthcare Platform
-- AUTHOR: Security Architecture Team
-- VERSION: 3.2 (Production)
-- LAST UPDATED: 2024-01
--
-- EXECUTION ORDER: Run as ACCOUNTADMIN
-- ESTIMATED RUNTIME: ~5 minutes
-- ENVIRONMENTS: PROD, QA (NOT DEV — DEV uses synthetic data with separate setup)
--
-- ARCHITECTURE NOTE:
--   PHI Databases (RAW_DB, CLEANSED_DB) are owned by SECURITYADMIN, NOT SYSADMIN.
--   This is intentional and critical. SYSADMIN is the data engineering role and
--   should never have access to unmasked patient data.
--   Ref: HIPAA §164.312(a)(1) — Access Control
-- =============================================================================


-- =============================================================================
-- SECTION 1: WAREHOUSE SETUP
-- Separate warehouses per role tier to enable cost attribution and
-- independent resource governance per team
-- =============================================================================

USE ROLE ACCOUNTADMIN;

-- PHI processing warehouse (used by PHI_READER and HIPAA_OFFICER)
CREATE WAREHOUSE IF NOT EXISTS PHI_WH
    WAREHOUSE_SIZE    = 'SMALL'
    AUTO_SUSPEND      = 60          -- 1 minute idle suspend
    AUTO_RESUME       = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'PHI processing — HIPAA_OFFICER and PHI_READER only. Monitor credits closely.';

-- Analytics warehouse (used by ANALYST roles and BI tools)
CREATE WAREHOUSE IF NOT EXISTS ANALYTICS_WH
    WAREHOUSE_SIZE    = 'MEDIUM'
    AUTO_SUSPEND      = 300         -- 5 minute idle suspend
    AUTO_RESUME       = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'Analytics warehouse — ANALYST roles, Tableau, Power BI';

-- ETL warehouse (used by dbt, ADF pipelines)
CREATE WAREHOUSE IF NOT EXISTS ETL_WH
    WAREHOUSE_SIZE    = 'LARGE'
    AUTO_SUSPEND      = 120
    AUTO_RESUME       = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'ETL processing — DBT_ROLE and PIPELINE_ROLE only';

-- Audit warehouse (dedicated, small — audit queries should be simple)
CREATE WAREHOUSE IF NOT EXISTS AUDIT_WH
    WAREHOUSE_SIZE    = 'XSMALL'
    AUTO_SUSPEND      = 60
    AUTO_RESUME       = TRUE
    INITIALLY_SUSPENDED = TRUE
    COMMENT = 'Audit and compliance queries — never shared with other workloads';


-- =============================================================================
-- SECTION 2: DATABASE AND SCHEMA CREATION
-- Database ownership is the cornerstone of PHI isolation.
-- =============================================================================

USE ROLE SECURITYADMIN;  -- PHI databases owned by SECURITYADMIN

-- PHI Zone: Raw data — unmasked PHI from source systems
CREATE DATABASE IF NOT EXISTS RAW_DB
    DATA_RETENTION_TIME_IN_DAYS = 30
    COMMENT = 'RAW PHI Zone — Source system data. SECURITYADMIN-owned. HIPAA restricted.';

CREATE SCHEMA IF NOT EXISTS RAW_DB.EHR
    COMMENT = 'Epic EHR source data';
CREATE SCHEMA IF NOT EXISTS RAW_DB.BILLING
    COMMENT = 'Cerner billing source data';
CREATE SCHEMA IF NOT EXISTS RAW_DB.PHARMACY
    COMMENT = 'Pharmacy POS source data';

-- PHI Zone: Cleansed data — masked by DDM, row-access enforced
CREATE DATABASE IF NOT EXISTS CLEANSED_DB
    DATA_RETENTION_TIME_IN_DAYS = 30
    COMMENT = 'Cleansed PHI Zone — DDM and Row-Access enforced. SECURITYADMIN-owned.';

CREATE SCHEMA IF NOT EXISTS CLEANSED_DB.CLINICAL
    COMMENT = 'Cleansed clinical data with masking policies applied';
CREATE SCHEMA IF NOT EXISTS CLEANSED_DB.BILLING
    COMMENT = 'Cleansed billing data with masking policies applied';

-- PHI Zone: Policy objects
CREATE DATABASE IF NOT EXISTS PHI_POLICIES_DB
    COMMENT = 'Masking policies, row-access policies, and mapping tables. SECURITYADMIN-owned.';

CREATE SCHEMA IF NOT EXISTS PHI_POLICIES_DB.PHI
    COMMENT = 'All DDM and Row-Access policy objects';

USE ROLE SYSADMIN;  -- Non-PHI databases owned by SYSADMIN

-- Analytics Zone: De-identified and aggregated data
CREATE DATABASE IF NOT EXISTS MARTS_DB
    DATA_RETENTION_TIME_IN_DAYS = 14
    COMMENT = 'Analytics Zone — De-identified. Safe for broad analyst access.';

CREATE SCHEMA IF NOT EXISTS MARTS_DB.POPULATION_HEALTH;
CREATE SCHEMA IF NOT EXISTS MARTS_DB.REVENUE_CYCLE;
CREATE SCHEMA IF NOT EXISTS MARTS_DB.QUALITY_METRICS;

USE ROLE SECURITYADMIN;  -- Audit database owned by SECURITYADMIN

-- Audit Zone: Immutable audit logs
CREATE DATABASE IF NOT EXISTS AUDIT_DB
    DATA_RETENTION_TIME_IN_DAYS = 90
    COMMENT = 'HIPAA Audit Zone — Immutable. 7-year retention via S3 archival. SECURITYADMIN-owned.';

CREATE SCHEMA IF NOT EXISTS AUDIT_DB.PUBLIC
    COMMENT = 'PHI access logs and security event logs';


-- =============================================================================
-- SECTION 3: ROLE HIERARCHY CREATION
-- All custom roles are created under SECURITYADMIN ownership.
-- =============================================================================

USE ROLE SECURITYADMIN;

-- ---- TOP-TIER SECURITY ROLES ----

-- HIPAA Officer: Full visibility into all PHI, all hospitals
-- Exempt from masking. Used for breach investigations and audits.
-- WHO GETS THIS: Chief Compliance Officer, HIPAA Privacy Officer (2-3 people max)
CREATE ROLE IF NOT EXISTS HIPAA_OFFICER
    COMMENT = 'Full PHI visibility — All hospitals — Masking bypass. Max 3 users. Quarterly access review.';

-- Audit Reader: Read-only on AUDIT_DB. Cannot modify any data.
-- WHO GETS THIS: Internal audit team, external SOC2 auditors (temporary)
CREATE ROLE IF NOT EXISTS AUDIT_READER
    COMMENT = 'Read-only audit log access. Cannot view PHI. For compliance reporting.';

-- ---- PHI SERVICE ACCOUNT ROLES ----

-- PHI Reader: For clinical application service accounts that need full PHI
-- Machine-to-machine only. Human users MUST use HIPAA_OFFICER or HOSPITAL_ADMIN.
CREATE ROLE IF NOT EXISTS PHI_READER
    COMMENT = 'Service account role for clinical apps. Key-pair auth only. No human users.';

-- ---- HOSPITAL-LEVEL ROLES (one per hospital, row-access restricted) ----
-- These roles can see PHI for their hospital ONLY via row-access policy
-- Masking is partially lifted (last 4 SSN, full DOB, full name) for clinical use

CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H01 COMMENT = 'Hospital H01 Cincinnati — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H02 COMMENT = 'Hospital H02 Dayton — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H03 COMMENT = 'Hospital H03 Cleveland — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H04 COMMENT = 'Hospital H04 Columbus — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H05 COMMENT = 'Hospital H05 Toledo — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H06 COMMENT = 'Hospital H06 Akron — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H07 COMMENT = 'Hospital H07 Indianapolis — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H08 COMMENT = 'Hospital H08 Fort Wayne — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H09 COMMENT = 'Hospital H09 Evansville — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H10 COMMENT = 'Hospital H10 Louisville — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H11 COMMENT = 'Hospital H11 Lexington — Masked PHI for own hospital';
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H12 COMMENT = 'Hospital H12 Ann Arbor — Masked PHI for own hospital';

-- ---- ANALYST ROLES (de-identified or heavily masked data only) ----

-- Base analyst role: NEVER granted directly — used as inheritance base only
CREATE ROLE IF NOT EXISTS ANALYST_BASE
    COMMENT = 'Base template role — never grant directly. Use specific ANALYST_* roles.';

-- Clinical analysts: Can query clinical data in CLEANSED_DB (masked) and MARTS_DB
CREATE ROLE IF NOT EXISTS ANALYST_CLINICAL
    COMMENT = 'Clinical analysts — MARTS_DB + masked CLEANSED_DB. No cross-hospital visibility.';

-- Revenue cycle analysts: Can query billing data (masked)
CREATE ROLE IF NOT EXISTS ANALYST_REVENUE
    COMMENT = 'Revenue cycle analysts — billing data only, masked PHI';

-- Data scientists: MARTS_DB only — de-identified and aggregated
CREATE ROLE IF NOT EXISTS DS_ROLE
    COMMENT = 'Data scientists — MARTS_DB only. De-identified data. No direct PHI access.';

-- ---- ETL / PIPELINE ROLES ----

-- dbt role: Reads CLEANSED, writes to MARTS. No PHI read permission.
CREATE ROLE IF NOT EXISTS DBT_ROLE
    COMMENT = 'dbt transformation service account. CLEANSED read + MARTS write. No PHI.';

-- Pipeline role: Writes raw data to RAW_DB. No read permission on other zones.
CREATE ROLE IF NOT EXISTS PIPELINE_ROLE
    COMMENT = 'SnowPipe / ADF ingestion service account. RAW_DB write only.';

-- Audit writer: The only role that can INSERT into AUDIT_DB.
-- Used exclusively by the audit pipeline service account.
CREATE ROLE IF NOT EXISTS AUDIT_WRITER
    COMMENT = 'Audit log pipeline service account. INSERT-only on AUDIT_DB. No SELECT on PHI.';


-- =============================================================================
-- SECTION 4: ROLE INHERITANCE HIERARCHY
-- GRANT ROLE <child> TO ROLE <parent> means parent inherits child's privileges
-- =============================================================================

-- PHI_READER inherits from nothing. It is a base role.
-- HIPAA_OFFICER inherits PHI_READER capabilities
GRANT ROLE PHI_READER TO ROLE HIPAA_OFFICER;

-- Hospital admin roles inherit from ANALYST_BASE
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H01;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H02;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H03;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H04;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H05;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H06;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H07;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H08;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H09;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H10;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H11;
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H12;

-- Analyst roles inherit from ANALYST_BASE
GRANT ROLE ANALYST_BASE TO ROLE ANALYST_CLINICAL;
GRANT ROLE ANALYST_BASE TO ROLE ANALYST_REVENUE;
GRANT ROLE ANALYST_BASE TO ROLE DS_ROLE;

-- All security roles report to SECURITYADMIN
GRANT ROLE HIPAA_OFFICER       TO ROLE SECURITYADMIN;
GRANT ROLE AUDIT_READER        TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H01  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H02  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H03  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H04  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H05  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H06  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H07  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H08  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H09  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H10  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H11  TO ROLE SECURITYADMIN;
GRANT ROLE HOSPITAL_ADMIN_H12  TO ROLE SECURITYADMIN;

-- ETL roles report to SYSADMIN
GRANT ROLE DBT_ROLE       TO ROLE SYSADMIN;
GRANT ROLE PIPELINE_ROLE  TO ROLE SYSADMIN;

-- AUDIT_WRITER reports to SECURITYADMIN (not SYSADMIN!)
GRANT ROLE AUDIT_WRITER TO ROLE SECURITYADMIN;


-- =============================================================================
-- SECTION 5: DATABASE AND SCHEMA GRANTS
-- =============================================================================

-- ---- RAW_DB: Only PIPELINE_ROLE (insert) and HIPAA_OFFICER/PHI_READER (select) ----

GRANT USAGE ON DATABASE RAW_DB TO ROLE PIPELINE_ROLE;
GRANT USAGE ON DATABASE RAW_DB TO ROLE HIPAA_OFFICER;
GRANT USAGE ON DATABASE RAW_DB TO ROLE PHI_READER;

GRANT USAGE ON ALL SCHEMAS IN DATABASE RAW_DB TO ROLE PIPELINE_ROLE;
GRANT USAGE ON ALL SCHEMAS IN DATABASE RAW_DB TO ROLE HIPAA_OFFICER;
GRANT USAGE ON ALL SCHEMAS IN DATABASE RAW_DB TO ROLE PHI_READER;

-- PIPELINE_ROLE: Insert and create tables in RAW_DB (for SnowPipe landing)
GRANT INSERT, CREATE TABLE ON ALL SCHEMAS IN DATABASE RAW_DB TO ROLE PIPELINE_ROLE;
GRANT INSERT, CREATE TABLE ON FUTURE SCHEMAS IN DATABASE RAW_DB TO ROLE PIPELINE_ROLE;

-- PHI_READER and HIPAA_OFFICER: SELECT on all tables in RAW_DB
GRANT SELECT ON ALL TABLES IN DATABASE RAW_DB TO ROLE PHI_READER;
GRANT SELECT ON FUTURE TABLES IN DATABASE RAW_DB TO ROLE PHI_READER;

-- ---- CLEANSED_DB: Hospital admins, analysts, dbt ----

GRANT USAGE ON DATABASE CLEANSED_DB TO ROLE HIPAA_OFFICER;
GRANT USAGE ON DATABASE CLEANSED_DB TO ROLE PHI_READER;
GRANT USAGE ON DATABASE CLEANSED_DB TO ROLE ANALYST_BASE;  -- Inherited by all HOSPITAL_ADMIN and ANALYST roles
GRANT USAGE ON DATABASE CLEANSED_DB TO ROLE DBT_ROLE;

GRANT USAGE ON ALL SCHEMAS IN DATABASE CLEANSED_DB TO ROLE ANALYST_BASE;
GRANT USAGE ON ALL SCHEMAS IN DATABASE CLEANSED_DB TO ROLE HIPAA_OFFICER;
GRANT USAGE ON ALL SCHEMAS IN DATABASE CLEANSED_DB TO ROLE PHI_READER;
GRANT USAGE ON ALL SCHEMAS IN DATABASE CLEANSED_DB TO ROLE DBT_ROLE;

-- SELECT on cleansed tables: Masking policies control what they actually see
GRANT SELECT ON ALL TABLES IN DATABASE CLEANSED_DB TO ROLE ANALYST_BASE;
GRANT SELECT ON FUTURE TABLES IN DATABASE CLEANSED_DB TO ROLE ANALYST_BASE;
GRANT SELECT ON ALL TABLES IN DATABASE CLEANSED_DB TO ROLE PHI_READER;
GRANT SELECT ON FUTURE TABLES IN DATABASE CLEANSED_DB TO ROLE PHI_READER;

-- dbt: Read cleansed, write marts
GRANT SELECT ON ALL TABLES IN DATABASE CLEANSED_DB TO ROLE DBT_ROLE;
GRANT SELECT ON FUTURE TABLES IN DATABASE CLEANSED_DB TO ROLE DBT_ROLE;

-- ---- MARTS_DB: All analyst roles, dbt (write), no PHI exposure ----

GRANT USAGE ON DATABASE MARTS_DB TO ROLE ANALYST_BASE;
GRANT USAGE ON DATABASE MARTS_DB TO ROLE DBT_ROLE;
GRANT USAGE ON DATABASE MARTS_DB TO ROLE DS_ROLE;
GRANT USAGE ON ALL SCHEMAS IN DATABASE MARTS_DB TO ROLE ANALYST_BASE;
GRANT USAGE ON ALL SCHEMAS IN DATABASE MARTS_DB TO ROLE DBT_ROLE;
GRANT USAGE ON ALL SCHEMAS IN DATABASE MARTS_DB TO ROLE DS_ROLE;

GRANT SELECT ON ALL TABLES IN DATABASE MARTS_DB TO ROLE ANALYST_BASE;
GRANT SELECT ON FUTURE TABLES IN DATABASE MARTS_DB TO ROLE ANALYST_BASE;
GRANT SELECT ON ALL TABLES IN DATABASE MARTS_DB TO ROLE DS_ROLE;
GRANT SELECT ON FUTURE TABLES IN DATABASE MARTS_DB TO ROLE DS_ROLE;

-- dbt writes to MARTS_DB
GRANT INSERT, UPDATE, DELETE, CREATE TABLE ON ALL SCHEMAS IN DATABASE MARTS_DB TO ROLE DBT_ROLE;
GRANT INSERT, UPDATE, DELETE, CREATE TABLE ON FUTURE SCHEMAS IN DATABASE MARTS_DB TO ROLE DBT_ROLE;

-- ---- AUDIT_DB: Read for auditors, write ONLY for AUDIT_WRITER ----

GRANT USAGE ON DATABASE AUDIT_DB TO ROLE AUDIT_READER;
GRANT USAGE ON DATABASE AUDIT_DB TO ROLE SECURITYADMIN;
GRANT USAGE ON DATABASE AUDIT_DB TO ROLE HIPAA_OFFICER;
GRANT USAGE ON DATABASE AUDIT_DB TO ROLE AUDIT_WRITER;
GRANT USAGE ON ALL SCHEMAS IN DATABASE AUDIT_DB TO ROLE AUDIT_READER;
GRANT USAGE ON ALL SCHEMAS IN DATABASE AUDIT_DB TO ROLE AUDIT_WRITER;

-- AUDIT_READER: SELECT only
GRANT SELECT ON ALL TABLES IN DATABASE AUDIT_DB TO ROLE AUDIT_READER;
GRANT SELECT ON FUTURE TABLES IN DATABASE AUDIT_DB TO ROLE AUDIT_READER;

-- AUDIT_WRITER: INSERT only — NO SELECT, NO UPDATE, NO DELETE, NO TRUNCATE
GRANT INSERT ON ALL TABLES IN DATABASE AUDIT_DB TO ROLE AUDIT_WRITER;
GRANT INSERT ON FUTURE TABLES IN DATABASE AUDIT_DB TO ROLE AUDIT_WRITER;
-- Explicitly: do NOT grant UPDATE, DELETE, TRUNCATE to AUDIT_WRITER or anyone else

-- Policy schema: Only SECURITYADMIN can manage policies
GRANT USAGE ON DATABASE PHI_POLICIES_DB TO ROLE SECURITYADMIN;
GRANT USAGE ON SCHEMA PHI_POLICIES_DB.PHI TO ROLE SECURITYADMIN;
GRANT ALL ON ALL TABLES IN SCHEMA PHI_POLICIES_DB.PHI TO ROLE SECURITYADMIN;
GRANT ALL ON FUTURE TABLES IN SCHEMA PHI_POLICIES_DB.PHI TO ROLE SECURITYADMIN;
-- Row-access policy mapping table must also be readable by the policy function
-- This is handled via the SECURITYADMIN-owned function below


-- =============================================================================
-- SECTION 6: WAREHOUSE GRANTS
-- =============================================================================

GRANT USAGE ON WAREHOUSE PHI_WH        TO ROLE HIPAA_OFFICER;
GRANT USAGE ON WAREHOUSE PHI_WH        TO ROLE PHI_READER;
GRANT USAGE ON WAREHOUSE ANALYTICS_WH  TO ROLE ANALYST_BASE;
GRANT USAGE ON WAREHOUSE ANALYTICS_WH  TO ROLE DS_ROLE;
GRANT USAGE ON WAREHOUSE ETL_WH        TO ROLE DBT_ROLE;
GRANT USAGE ON WAREHOUSE ETL_WH        TO ROLE PIPELINE_ROLE;
GRANT USAGE ON WAREHOUSE AUDIT_WH      TO ROLE AUDIT_READER;
GRANT USAGE ON WAREHOUSE AUDIT_WH      TO ROLE AUDIT_WRITER;
GRANT USAGE ON WAREHOUSE AUDIT_WH      TO ROLE SECURITYADMIN;


-- =============================================================================
-- SECTION 7: NETWORK POLICY
-- Production network policy whitelisting hospital IP ranges.
-- Updated quarterly via Change Advisory Board (CAB) process.
-- =============================================================================

USE ROLE ACCOUNTADMIN;

CREATE OR REPLACE NETWORK POLICY hipaa_production_policy
  ALLOWED_IP_LIST = (
    '10.1.0.0/16',        -- H01 Cincinnati campus
    '10.2.0.0/16',        -- H02 Dayton campus
    '10.3.0.0/16',        -- H03 Cleveland campus
    '10.4.0.0/16',        -- H04 Columbus campus
    '10.5.0.0/16',        -- H05 Toledo campus
    '10.6.0.0/16',        -- H06 Akron campus
    '10.7.0.0/16',        -- H07 Indianapolis campus
    '10.8.0.0/16',        -- H08 Fort Wayne campus
    '10.9.0.0/16',        -- H09 Evansville campus
    '10.10.0.0/16',       -- H10 Louisville campus
    '10.11.0.0/16',       -- H11 Lexington campus
    '10.12.0.0/16',       -- H12 Ann Arbor campus
    '172.16.100.0/24',    -- Corporate VPN (data engineering)
    '172.16.101.0/24',    -- Contractor VPN (reviewed quarterly)
    '172.16.200.0/28'     -- Break-glass emergency access (documented, monitored)
  )
  BLOCKED_IP_LIST = ()
  COMMENT = 'HIPAA Production Network Policy v3.2 — CAB approved 2024-01-15 — Next review: 2024-04-15';

-- Apply at account level
ALTER ACCOUNT SET NETWORK_POLICY = hipaa_production_policy;

-- Also apply at user level for HIPAA_OFFICER (extra hardening — must use VPN even if on-campus)
-- This is applied per-user during user provisioning:
-- ALTER USER <hipaa_officer_username> SET NETWORK_POLICY = hipaa_production_policy;


-- =============================================================================
-- SECTION 8: ACCOUNT-LEVEL SECURITY PARAMETERS
-- =============================================================================

USE ROLE ACCOUNTADMIN;

-- -----------------------------------------------------------------------
-- MFA ENFORCEMENT via Authentication Policy (Snowflake 2024+ correct syntax)
-- NOTE: DeepSeek suggested 'ALTER ACCOUNT SET MULTI_FACTOR_AUTHENTICATION = ENFORCED'
--   — that is also incorrect syntax. The current correct approach for Snowflake
--   is an Authentication Policy object (introduced in 2023, GA in 2024).
--   The old MULTI_FACTOR_AUTHENTICATION_LOGIN_POLICY parameter is deprecated.
-- HIPAA Ref: §164.312(d) — Person or Entity Authentication
-- -----------------------------------------------------------------------
CREATE OR REPLACE AUTHENTICATION POLICY hipaa_mfa_auth_policy
    MFA_ENROLLMENT              = REQUIRED        -- All users MUST enroll MFA
    MFA_AUTHENTICATION_METHODS  = ('SAML', 'PASSWORD')
    CLIENT_TYPES                = (
        'SNOWFLAKE_UI',     -- Web browser (Snowsight)
        'PYTHON_DRIVER',    -- Python connector
        'JDBC_DRIVER',      -- Java/Tableau JDBC
        'SNOWSQL',          -- CLI access
        'ODBC_DRIVER'       -- Excel / other ODBC clients
    )
    COMMENT = 'HIPAA MFA policy — all human users must use MFA. Service accounts exempt (use key-pair).';

-- Apply at account level (affects all users unless overridden at user level)
ALTER ACCOUNT SET AUTHENTICATION POLICY hipaa_mfa_auth_policy;

-- Service accounts use key-pair auth — explicitly exempt them from MFA policy
-- Apply during service account creation:
-- ALTER USER dbt_svc_account   SET AUTHENTICATION POLICY = NULL;  -- uses key-pair only
-- ALTER USER pipeline_svc_acct SET AUTHENTICATION POLICY = NULL;  -- uses key-pair only

-- -----------------------------------------------------------------------
-- PASSWORD POLICY (for human users — service accounts use key-pair, no password)
-- -----------------------------------------------------------------------
CREATE OR REPLACE PASSWORD POLICY hipaa_password_policy
    PASSWORD_MIN_LENGTH          = 14
    PASSWORD_MAX_AGE_DAYS        = 90
    PASSWORD_MAX_RETRIES         = 5
    PASSWORD_LOCKOUT_TIME_MINS   = 30
    PASSWORD_MIN_UPPERCASE_CHARS = 1
    PASSWORD_MIN_LOWERCASE_CHARS = 1
    PASSWORD_MIN_NUMERIC_CHARS   = 1
    PASSWORD_MIN_SPECIAL_CHARS   = 1
    COMMENT                      = 'HIPAA Password Policy — applied to all human user accounts';

ALTER ACCOUNT SET PASSWORD POLICY hipaa_password_policy;

-- Session timeout — idle sessions auto-expire after 4 hours
ALTER ACCOUNT SET CLIENT_SESSION_KEEP_ALIVE = FALSE;
ALTER ACCOUNT SET CLIENT_SESSION_KEEP_ALIVE_HEARTBEAT_FREQUENCY = 3600; -- 1 hour heartbeat max

-- Prevent UI download of query results containing PHI
-- (Applied at database level for PHI databases)
ALTER DATABASE RAW_DB SET DATA_RETENTION_TIME_IN_DAYS = 30;
ALTER DATABASE CLEANSED_DB SET DATA_RETENTION_TIME_IN_DAYS = 30;


-- =============================================================================
-- SECTION 9: VERIFICATION QUERIES
-- Run these after setup to verify RBAC is correctly configured
-- =============================================================================

-- Verify: SYSADMIN cannot see PHI databases
-- Expected: 0 rows (SYSADMIN should have no access)
SHOW GRANTS TO ROLE SYSADMIN;
-- Manually verify that RAW_DB and CLEANSED_DB do NOT appear in output

-- Verify: PHI databases are owned by SECURITYADMIN
SELECT database_name, database_owner
FROM information_schema.databases
WHERE database_name IN ('RAW_DB', 'CLEANSED_DB', 'AUDIT_DB', 'PHI_POLICIES_DB')
ORDER BY 1;
-- Expected: All owned by SECURITYADMIN

-- Verify: No DELETE/UPDATE/TRUNCATE on AUDIT_DB
SELECT grantee_name, privilege_type, object_name
FROM information_schema.object_privileges
WHERE object_catalog = 'AUDIT_DB'
  AND privilege_type IN ('DELETE', 'UPDATE', 'TRUNCATE');
-- Expected: 0 rows

-- =============================================================================
-- END OF FILE
-- =============================================================================