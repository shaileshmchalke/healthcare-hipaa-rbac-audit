# HIPAA Technical Safeguards — Implementation Mapping

> This document maps every HIPAA Technical Safeguard requirement (45 CFR §164.312)
> and De-identification Standard (45 CFR §164.514) to its concrete technical
> implementation in this Snowflake platform. This table is the primary evidence
> document presented to HHS OCR auditors and SOC2 assessors.
>
> **Last updated:** 2024-01-15 | **Next review:** 2024-07-15  
> **Owner:** HIPAA Privacy Officer | **Approved by:** CISO

---

## §164.312 — Technical Safeguards

### (a)(1) — Access Control

*"Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to those persons or software programs that have been granted access rights."*

| Sub-requirement | §164.312 Ref | Implementation | File / Evidence |
|----------------|-------------|----------------|-----------------|
| Unique user identification | (a)(2)(i) | Each user has individual Snowflake login via SSO/Okta. Service accounts named per system (`dbt_svc`, `pipeline_svc`). **No shared accounts.** | `SHOW USERS` output + Okta audit log |
| Emergency access procedure | (a)(2)(ii) | `ACCOUNTADMIN` break-glass account sealed in physical vault. Use triggers PagerDuty P1 alert. Dual-person authorization required. | `audit_db.public.phi_access_log` where `event_type = 'BREAK_GLASS_ACCESS'` |
| Automatic logoff | (a)(2)(iii) | Snowflake session idle timeout: 4 hours. All warehouses: auto-suspend 10 minutes idle. | `SHOW PARAMETERS LIKE 'CLIENT_SESSION%' IN ACCOUNT` |
| Encryption / decryption | (a)(2)(iv) | Snowflake Transparent Data Encryption (AES-256) at rest. TLS 1.2+ in transit enforced. Customer-managed keys via Azure Key Vault (Tri-Secret Secure). | Azure Key Vault audit logs + Snowflake encryption documentation |
| Role-based access control | (a)(1) | 7-level RBAC hierarchy. `SYSADMIN` has zero access to PHI databases (owned by `SECURITYADMIN`). SCIM-based provisioning from Azure AD. | `sql/setup_rbac.sql`, `SHOW GRANTS TO ROLE SYSADMIN` → 0 PHI rows |
| PHI column protection | (a)(1) | Dynamic Data Masking on 12 PHI column types. Role-based exemptions. Enforced at query time — cannot be bypassed by `SELECT *`. | `sql/policies.sql`, `information_schema.policy_references` |

---

### (b) — Audit Controls

*"Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI."*

| Control | Implementation | Retention | Evidence |
|---------|---------------|-----------|----------|
| PHI access audit log | `AUDIT_DB.PUBLIC.phi_access_log` — captures all DML/DDL on PHI tables, security events, anomalies. Append-only (no DELETE/UPDATE grants). | 90 days Snowflake + 7 years S3 WORM (Object Lock COMPLIANCE mode) | Row count query on audit table + S3 bucket policy screenshot |
| SELECT query audit | Snowflake native `QUERY_HISTORY` (90-day rolling window, 6-month in `ACCOUNT_USAGE`) | 6 months (Account Usage schema) | `SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY WHERE DATABASE_NAME IN ('RAW_DB','CLEANSED_DB')` |
| Login / authentication audit | `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY` + `AUDIT_DB.PUBLIC.v_login_audit` view with compliance enrichment | 365 days (Account Usage) | `v_login_audit` view — failed logins, off-hours, single-factor warnings |
| Security policy change log | `AUDIT_DB.PUBLIC.security_policy_changes` — every DDL on masking policies, row-access policies, role grants | 7 years via S3 archival | `v_policy_change_timeline` view — ticket references, approvals |
| Anomaly detection | DLP monitoring task runs every 15 minutes. Flags: bulk exports (>50K rows), off-hours access, repeated auth failures. | `breach_suspect_log` — 7 years | `v_open_breach_suspects` — all open flags must be reviewed within 24h |
| Immutability verification | `SELECT * FROM information_schema.object_privileges WHERE object_catalog='AUDIT_DB' AND privilege_type IN ('DELETE','UPDATE','TRUNCATE')` | Verified weekly by validation task | Expected: 0 rows — any result is a critical finding |

---

### (c)(1) — Integrity Controls

*"Implement policies and procedures to protect ePHI from improper alteration or destruction."*

| Control | Implementation | File |
|---------|---------------|------|
| Data integrity on ingest | Hash verification on PHI loads via pipeline checksums. Snowflake Time Travel for 30-day data recovery. | ETL pipeline (external) |
| Row-level isolation | Row Access Policy `patient_hospital_isolation` — prevents cross-hospital data access. Hospital A cannot see Hospital B patients even in a shared table. | `sql/policies.sql` |
| Immutable audit records | No UPDATE/DELETE/TRUNCATE grants on `AUDIT_DB` tables. Verified weekly. | `sql/audit_tables.sql`, `sql/validation_queries.sql` CHECK 5A |
| DEV environment data | DEV uses Zero-Copy Clone + synthetic data replacement (FAKER pattern). Real PHI never in DEV. | Architecture decision in README ADR-006 |

---

### (d) — Person / Entity Authentication

*"Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed."*

| Control | Implementation | File |
|---------|---------------|------|
| Multi-factor authentication | `hipaa_mfa_auth_policy` (Authentication Policy object, Snowflake 2024). All human users: MFA required. | `sql/setup_rbac.sql` Section 8 |
| Key-pair for service accounts | All service accounts (`dbt_svc`, `pipeline_svc`, `audit_writer_svc`) use RSA key-pair authentication. No password. | User provisioning runbook |
| ACCOUNTADMIN hardware key | Break-glass `ACCOUNTADMIN` requires YubiKey hardware token. Use triggers P1 alert. | Physical security policy |
| SSO integration | All human logins via Okta SSO. Snowflake local passwords disabled for human users. | Okta → Snowflake SCIM configuration |

---

### (e)(1) — Transmission Security

*"Implement technical security measures to guard against unauthorized access to ePHI that is being transmitted over an electronic communications network."*

| Control | Implementation |
|---------|---------------|
| Azure Private Link | All Snowflake traffic routed through Azure backbone — no public internet routing. Configured per hospital VNet. |
| IP Whitelist | `hipaa_production_policy` network policy: 12 hospital campus ranges + corporate VPN only. Public internet access blocked. |
| TLS enforcement | Snowflake enforces TLS 1.2 minimum on all connections. TLS 1.0/1.1 disabled at account level. |
| Public endpoint disabled | Snowflake account configured with Private Link — public endpoint inaccessible. Stolen credentials cannot be used from coffee shop/home network. |

---

## §164.514 — De-identification Standards

### (b) — Safe Harbor Method (18 Identifiers Removed)

Applied to `MARTS_DB` (analytics zone). All 18 HIPAA identifiers are masked, tokenized, or aggregated.

| HIPAA Identifier | MARTS_DB Treatment | CLEANSED_DB Treatment |
|-----------------|-------------------|----------------------|
| Names | Removed | Masked (role-based) — first initial for ANALYST |
| Geographic subdivisions smaller than state | State only | ZIP first 3 digits for ANALYST |
| Dates (except year) | Year only | Year only for ANALYST; full for HOSPITAL_ADMIN |
| Ages over 89 | Aggregated as "90+" | Year-of-birth capped at 1930 |
| Phone numbers | Removed | `***-***-****` for ANALYST |
| Fax numbers | Removed | Removed |
| Email addresses | Removed | `***@***.***` for ANALYST |
| SSNs | Removed | FPE token for ANALYST, real for HIPAA_OFFICER |
| Medical record numbers | Tokenized | SHA2 token for ANALYST, real for HOSPITAL_ADMIN |
| Health plan beneficiary numbers | Removed | Tokenized |
| Account numbers | Removed | `ACCT-<token>` for ANALYST |
| Certificate / license numbers | Removed | Removed |
| VIN / serial numbers | N/A | N/A |
| Device identifiers | Removed | Removed |
| Web URLs | Removed | Removed |
| IP addresses | Removed | Removed |
| Biometric identifiers | Not stored | Not stored |
| Full-face photographs | Not stored | Not stored |
| Any other unique identifying numbers | Tokenized | Tokenized |

### (b)(2)(i) — Age 90+ Special Requirement

> *"Ages 90 and over shall be aggregated into a single category of age 90 or older."*

**Implementation in `mask_dob` for `DS_ROLE`:**
```sql
WHEN CURRENT_ROLE() = 'DS_ROLE'
    THEN DATE_FROM_PARTS(
             CASE WHEN YEAR(dob_val) < 1930 THEN 1930  -- 90+ cap
                  ELSE YEAR(dob_val) END, 1, 1)
```
Patients born before 1930 (age 95+ as of 2025) all appear as `1930-01-01`.

### (e) — Limited Data Sets

For approved research use cases, a limited data set (LDS) can be produced from `MARTS_DB`:
- Direct identifiers removed per Safe Harbor
- Indirect identifiers (ZIP first 3, year-of-birth, state) retained
- Requires Data Use Agreement (DUA) before release
- Produced by `HIPAA_OFFICER` only — not by ANALYST or DS_ROLE

---

## SOC2 Type II Control Mapping

| SOC2 Criteria | Control | Implementation |
|---------------|---------|----------------|
| CC6.1 — Logical access controls | RBAC hierarchy, least privilege | `sql/setup_rbac.sql` |
| CC6.2 — New access provisioning | SCIM + Azure AD groups | SCIM configuration docs |
| CC6.3 — Access removal | SCIM deprovisioning (15 min SLA) | `security_policy_changes` + Okta audit |
| CC6.6 — Logical access restrictions | DDM, Row Access Policy, Network Policy | `sql/policies.sql` |
| CC6.7 — Transmission controls | Private Link, TLS 1.2+, IP whitelist | `sql/setup_rbac.sql` Section 7 |
| CC7.2 — System monitoring | DLP task, breach_suspect_log, v_login_audit | `sql/audit_tables.sql` |
| CC7.3 — Incident evaluation | 24h SLA on breach_suspect_log OPEN items | `v_open_breach_suspects` |
| A1.2 — Availability monitoring | Warehouse auto-suspend, Snowflake SLA | Snowflake account SLA docs |

---

*Document owner: Security Architecture Team | Classification: INTERNAL — Do not distribute outside organization*