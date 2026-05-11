# Operational Runbook — Healthcare HIPAA Snowflake Platform

> This runbook documents common operational procedures for the HIPAA-compliant
> Snowflake platform. Every procedure includes the exact commands, expected
> outputs, and escalation steps. Keep this document updated after every
> incident that reveals a gap.

---

## 1. Access Review (Quarterly)

**When:** Every quarter (Jan, Apr, Jul, Oct — first Monday)
**Who:** HIPAA Officer + Data Platform Lead
**Time required:** ~2 hours

### Step 1: Export active user list

```sql
USE ROLE SECURITYADMIN;

SELECT
    u.name                  AS username,
    u.display_name,
    u.email,
    u.last_success_login,
    u.has_mfa,
    DATEDIFF('day', u.last_success_login, CURRENT_DATE()) AS days_since_login,
    LISTAGG(g.role, ', ') WITHIN GROUP (ORDER BY g.role) AS roles_assigned
FROM snowflake.account_usage.users u
LEFT JOIN snowflake.account_usage.grants_to_users g
    ON g.grantee_name = u.name
WHERE u.deleted_on IS NULL
GROUP BY 1,2,3,4,5,6
ORDER BY days_since_login DESC NULLS FIRST;
```

### Step 2: Flag accounts for review

Any account matching these criteria needs immediate action:

| Condition | Action |
|-----------|--------|
| `last_success_login` > 60 days | Disable account, notify manager |
| `has_mfa = FALSE` | Force MFA enrollment within 48h |
| Role assigned but never logged in | Remove role, re-provision when needed |

### Step 3: Revoke access for departed employees

```sql
-- Verify employee is no longer active in HR system before running
ALTER USER <username> SET DISABLED = TRUE;

-- Document in access review log
INSERT INTO audit_db.public.security_policy_changes
    (changed_by_user, changed_by_role, change_type, object_type,
     object_name, business_justification, ticket_reference)
VALUES
    (CURRENT_USER(), CURRENT_ROLE(), 'USER_DISABLED', 'USER',
     '<username>', 'Quarterly access review — employee departed', '<JIRA_TICKET>');
```

---

## 2. Adding a New Hospital

**When:** A new hospital joins the network
**Who:** SECURITYADMIN
**Time required:** ~30 minutes

```sql
USE ROLE SECURITYADMIN;

-- Step 1: Create hospital admin role
CREATE ROLE IF NOT EXISTS HOSPITAL_ADMIN_H13
    COMMENT = 'Hospital H13 <HospitalName> — Masked PHI for own hospital';

-- Step 2: Grant role hierarchy
GRANT ROLE ANALYST_BASE TO ROLE HOSPITAL_ADMIN_H13;
GRANT ROLE HOSPITAL_ADMIN_H13 TO ROLE SECURITYADMIN;

-- Step 3: Grant warehouse access
GRANT USAGE ON WAREHOUSE ANALYTICS_WH TO ROLE HOSPITAL_ADMIN_H13;

-- Step 4: Add hospital mapping (this is all that's needed for row-access policy)
INSERT INTO phi_policies_db.phi.hospital_role_map
    (snowflake_role, hospital_id, effective_from, granted_by, business_reason, ticket_ref)
VALUES
    ('HOSPITAL_ADMIN_H13', 'H13', CURRENT_DATE(), CURRENT_USER(),
     'New hospital H13 onboarding', '<JIRA_TICKET>');

-- Step 5: Add to network policy (update IP range)
-- ALTER NETWORK POLICY hipaa_production_policy
--     SET ALLOWED_IP_LIST = (...existing..., '10.13.0.0/16');
```

**Verify:**
```sql
-- Test: H13 role should see only H13 patients
USE ROLE HOSPITAL_ADMIN_H13;
SELECT DISTINCT hospital_id FROM cleansed_db.clinical.patients;
-- Expected: only H13
```

---

## 3. Responding to a DLP Alert

**When:** `breach_suspect_log` has OPEN entries > 24 hours
**Who:** On-call Security Analyst
**SLA:** Must be reviewed within 24 hours of detection

### Step 1: Check open alerts

```sql
USE ROLE SECURITYADMIN;

SELECT * FROM audit_db.public.v_open_breach_suspects
ORDER BY anomaly_score DESC;
```

### Step 2: Investigate the suspicious session

```sql
-- Get all queries from the flagged session
SELECT
    query_id,
    query_text,
    database_name,
    rows_produced,
    execution_status,
    start_time
FROM snowflake.account_usage.query_history
WHERE session_id = '<SESSION_ID_FROM_ALERT>'
ORDER BY start_time;
```

### Step 3: Classify and close

```sql
-- Mark as cleared (no breach)
UPDATE audit_db.public.breach_suspect_log
SET
    status            = 'CLEARED',
    investigation_notes = '<your notes here>',
    closed_at         = CURRENT_TIMESTAMP(),
    closed_by         = CURRENT_USER()
WHERE suspect_id = '<SUSPECT_ID>';

-- OR: Escalate as confirmed breach
UPDATE audit_db.public.breach_suspect_log
SET
    status                      = 'CONFIRMED_BREACH',
    hipaa_notification_required = TRUE,
    notification_deadline       = DATEADD('day', 60, CURRENT_DATE()),
    investigation_notes         = '<breach details>',
    assigned_to                 = 'hipaa-officer@org.com'
WHERE suspect_id = '<SUSPECT_ID>';
```

> If `hipaa_notification_required = TRUE`, the 60-day HHS OCR notification
> clock starts immediately. Escalate to HIPAA Officer and Legal within 1 hour.

---

## 4. Break-Glass ACCOUNTADMIN Access

**When:** Emergency only — normal access methods unavailable
**Who:** Two authorized break-glass users (dual authorization required)
**Documentation:** Every use must be logged immediately after

### Procedure

1. Retrieve credentials from physical vault (location: IT Security Cabinet #3)
2. Both authorized persons must be present or on a recorded call
3. Log into Snowflake — this triggers automatic PagerDuty P1 alert
4. Perform only the minimum necessary action
5. Log out immediately
6. Document in audit table within 1 hour:

```sql
INSERT INTO audit_db.public.phi_access_log
    (event_type, user_name, role_name, database_name, schema_name,
     table_name, compliance_flag, compliance_notes)
VALUES
    ('BREAK_GLASS_ACCESS', '<your_username>', 'ACCOUNTADMIN',
     'N/A', 'N/A', 'N/A', 'REVIEW',
     'Break-glass access. Reason: <reason>. Authorized by: <name>. Ticket: <ticket>');
```

---

## 5. Policy Deployment (Production)

**When:** After any change to masking policies, RBAC, or row-access policies
**Who:** SECURITYADMIN (with CAB approval for production)

```bash
# 1. Deploy on QA first
snowsql -a <qa_account> -u <qa_user> -f sql/policies.sql

# 2. Run validation on QA
snowsql -a <qa_account> -u <qa_user> -f sql/validation_queries.sql

# 3. If QA passes, deploy production (requires second approver)
snowsql -a <prod_account> -u <prod_user> -f sql/policies.sql

# 4. Validate production immediately after
snowsql -a <prod_account> -u <prod_user> -f sql/validation_queries.sql
```

---

## 6. Audit Report for HIPAA Auditors

**When:** Annual audit or OCR investigation
**Who:** HIPAA Officer

```sql
USE ROLE HIPAA_OFFICER;
USE WAREHOUSE AUDIT_WH;

-- 1. PHI access summary last 12 months
SELECT * FROM audit_db.public.v_phi_access_summary
WHERE first_access >= DATEADD('month', -12, CURRENT_DATE())
ORDER BY total_rows_affected DESC;

-- 2. Security policy changes last 12 months
SELECT * FROM audit_db.public.v_policy_change_timeline
WHERE changed_at >= DATEADD('month', -12, CURRENT_DATE())
ORDER BY changed_at DESC;

-- 3. All break-glass access events
SELECT * FROM audit_db.public.phi_access_log
WHERE event_type = 'BREAK_GLASS_ACCESS'
ORDER BY event_time DESC;

-- 4. Confirmed breach incidents
SELECT * FROM audit_db.public.breach_suspect_log
WHERE status = 'CONFIRMED_BREACH'
ORDER BY detected_at DESC;
```

---

*Runbook owner: Security Architecture Team | Review cycle: Every 6 months*