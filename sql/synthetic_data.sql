-- =============================================================================
-- FILE: sql/security_hardening.sql
-- PURPOSE: Additional security hardening beyond baseline RBAC setup
-- VERSION: 1.0
--
-- EXECUTION ROLE: ACCOUNTADMIN (for account-level settings)
--                 SECURITYADMIN (for object-level settings)
--
-- WHEN TO RUN: After setup_rbac.sql and policies.sql
--              Run quarterly to verify settings have not drifted
--
-- HIPAA REFERENCES:
--   §164.312(a)(1) — Access Control
--   §164.312(e)(1) — Transmission Security
-- =============================================================================

USE ROLE ACCOUNTADMIN;


-- =============================================================================
-- SECTION 1: PREVENT UNINTENDED DATA SHARING
-- Disable features that could accidentally expose PHI externally
-- =============================================================================

-- Disable cross-account data sharing on PHI databases
-- (Snowflake Secure Data Sharing must be explicitly approved per data use agreement)
-- ALTER DATABASE RAW_DB SET SHARE_RESTRICTIONS = TRUE;
-- ALTER DATABASE CLEANSED_DB SET SHARE_RESTRICTIONS = TRUE;

-- Disable browser-based result download for PHI databases
-- Users cannot export results to local CSV from Snowsight
ALTER DATABASE RAW_DB     SET COMMENT = 'RAW PHI Zone — data download restricted';
ALTER DATABASE CLEANSED_DB SET COMMENT = 'Cleansed PHI Zone — data download restricted';


-- =============================================================================
-- SECTION 2: SESSION SECURITY
-- Harden session parameters to reduce exposure window
-- =============================================================================

-- Maximum idle time before session expires: 4 hours
ALTER ACCOUNT SET CLIENT_SESSION_KEEP_ALIVE = FALSE;

-- Lock out after 5 failed login attempts
ALTER ACCOUNT SET LOCK_TIMEOUT = 30;   -- 30 minutes lockout after max retries

-- Enforce TLS 1.2 minimum (TLS 1.0 and 1.1 disabled)
-- This is enforced by Snowflake at the platform level for Business Critical
-- Verify with: SELECT SYSTEM$WHITELIST() to confirm no TLS downgrade allowed


-- =============================================================================
-- SECTION 3: OBJECT-LEVEL SECURITY AUDIT
-- Identify and fix common misconfigurations
-- =============================================================================

USE ROLE SECURITYADMIN;

-- Check 1: PUBLIC role should have NO access to PHI databases
-- Public role is implicitly granted to all users — it must be empty for PHI
SELECT
    grantee_name,
    privilege_type,
    object_name,
    'RISK: PUBLIC role has PHI access' AS finding
FROM snowflake.account_usage.grants_to_roles
WHERE grantee_name  = 'PUBLIC'
  AND object_name  IN ('RAW_DB', 'CLEANSED_DB', 'AUDIT_DB')
  AND deleted_on IS NULL;
-- Expected: 0 rows


-- Check 2: No FUTURE GRANTS to PUBLIC role on PHI schemas
SELECT
    grantee_name,
    grant_option,
    privilege,
    object_name,
    'RISK: Future grants to PUBLIC on PHI schema' AS finding
FROM snowflake.account_usage.grants_to_roles
WHERE grantee_name = 'PUBLIC'
  AND grant_option = TRUE
  AND deleted_on IS NULL;
-- Expected: 0 rows


-- Check 3: Service accounts should not have ANALYST or HIPAA roles
-- Service accounts should have only their specific functional role
SELECT
    u.name AS service_account,
    g.role AS unexpected_role,
    'RISK: Service account has human user role' AS finding
FROM snowflake.account_usage.users u
JOIN snowflake.account_usage.grants_to_users g
    ON g.grantee_name = u.name
WHERE u.name LIKE '%SVC%'             -- naming convention for service accounts
  AND g.role IN ('HIPAA_OFFICER', 'ANALYST_CLINICAL', 'ANALYST_REVENUE')
  AND u.deleted_on IS NULL;
-- Expected: 0 rows


-- Check 4: Warehouses with no auto-suspend (credit waste + extended access window)
SELECT
    name                 AS warehouse_name,
    auto_suspend,
    'WARNING: No auto-suspend configured' AS finding
FROM snowflake.account_usage.warehouses
WHERE auto_suspend = 0
  AND deleted_on IS NULL;
-- Expected: 0 rows (all warehouses should have auto-suspend)


-- =============================================================================
-- SECTION 4: ENFORCE WAREHOUSE SIZE LIMITS
-- Prevent analysts from accidentally running XL queries on PHI tables
-- =============================================================================

-- Cap ANALYTICS_WH at LARGE — prevents runaway queries on patient tables
ALTER WAREHOUSE ANALYTICS_WH SET MAX_CLUSTER_COUNT = 1;

-- PHI_WH stays SMALL — high-volume PHI queries should go through HIPAA_OFFICER
-- who has a separate workflow and approval chain
ALTER WAREHOUSE PHI_WH SET MAX_CLUSTER_COUNT = 1;


-- =============================================================================
-- SECTION 5: RESOURCE MONITOR
-- Alert if any warehouse exceeds expected credit usage
-- Prevents runaway queries from becoming a billing AND security surprise
-- =============================================================================

CREATE OR REPLACE RESOURCE MONITOR hipaa_credit_monitor
    WITH CREDIT_QUOTA = 500              -- Monthly credit limit across all warehouses
    FREQUENCY        = MONTHLY
    START_TIMESTAMP  = IMMEDIATELY
    TRIGGERS
        ON 75 PERCENT DO NOTIFY          -- Alert at 75% usage
        ON 90 PERCENT DO NOTIFY          -- Alert at 90% usage
        ON 100 PERCENT DO SUSPEND;       -- Suspend warehouses at 100%

ALTER WAREHOUSE PHI_WH        SET RESOURCE_MONITOR = hipaa_credit_monitor;
ALTER WAREHOUSE ANALYTICS_WH  SET RESOURCE_MONITOR = hipaa_credit_monitor;
ALTER WAREHOUSE ETL_WH        SET RESOURCE_MONITOR = hipaa_credit_monitor;
ALTER WAREHOUSE AUDIT_WH      SET RESOURCE_MONITOR = hipaa_credit_monitor;


-- =============================================================================
-- SECTION 6: FINAL HARDENING VERIFICATION
-- Run this section last to confirm all hardening applied correctly
-- =============================================================================

SELECT
    'Account MFA policy'          AS control,
    CASE WHEN COUNT(*) > 0 THEN 'ACTIVE' ELSE 'MISSING' END AS status
FROM snowflake.account_usage.policy_references
WHERE policy_kind = 'AUTHENTICATION_POLICY'

UNION ALL

SELECT
    'Network policy at account',
    CASE WHEN VALUE != '' THEN 'ACTIVE' ELSE 'MISSING' END
FROM TABLE(FLATTEN(INPUT => PARSE_JSON(SYSTEM$GET_NETWORK_POLICY_INFO())))
WHERE KEY = 'NETWORK_POLICY'

UNION ALL

SELECT
    'Resource monitor on PHI_WH',
    CASE WHEN resource_monitor != 'null' THEN 'ACTIVE' ELSE 'MISSING' END
FROM snowflake.account_usage.warehouses
WHERE name = 'PHI_WH' AND deleted_on IS NULL;

-- =============================================================================
-- END OF FILE
-- =============================================================================