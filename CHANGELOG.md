# Changelog

All notable changes to this project are documented in this file.  
Format: [Semantic Versioning](https://semver.org/) — `MAJOR.MINOR.PATCH`

---

## v3.2.0 — 2025-01-15

### Changed
- Switched SSN masking from SHA-256 to **Format-Preserving Encryption (FPE)** tokenization
  - Root cause: SHA-256 hashed `123-45-6789` and `123456789` differently per table, breaking all patient↔claim joins
  - Fix: Canonical input format + deterministic salt-based token ensures cross-table join consistency
- Added `hospital_id` clustering key on `RAW_DB.EHR.patient_events` (2.1B rows)
  - Root cause: Row-access policy subquery caused 40% query performance regression
  - Fix: Clustering enables micro-partition pruning before policy evaluation; performance restored to baseline

### Fixed
- NULL handling added to all 12 masking policies (`WHEN col IS NULL THEN NULL` guard)
- RAW_DB tables (`patient_demographics`, `claims`) now have row-access policy applied
- S3 archival task now uses `PARTITION BY (year, month)` for correct 7-year folder structure
- MFA enforcement updated to use `Authentication Policy` object (Snowflake 2024 GA syntax)

### Security
- GitHub Actions workflow updated to use RSA key-pair authentication (removed `SNOWSQL_PWD`)
- `cleanup.sql` DROP order corrected: policies unset → policies dropped → databases dropped

---

## v3.1.0 — 2024-11-01

### Fixed
- Reduced custom audit log volume from **180GB/day → 2.4GB/day** ($22K/month → $3.2K/month)
  - Root cause: Logging every SELECT on PHI tables was not required by HIPAA §164.312(b)
  - Fix: Custom audit captures DML/DDL/security events only; SELECT audit via native `QUERY_HISTORY`
- DLP monitoring task interval changed from 1 minute → 15 minutes (credit cost reduction)
- Added `CONVERT_TIMEZONE` → `AT TIME ZONE` for off-hours detection (performance improvement)

### Added
- `breach_suspect_log` table for anomaly tracking with 24-hour SLA
- `v_open_breach_suspects` view with SLA status indicator
- DLP alert: contractor bulk-exporting 340K records at 2 AM detected and investigated

---

## v3.0.0 — 2024-09-15

### Added
- **Policy-as-Code** implementation (`policies_example.yaml`)
  - Root cause: Developer manually unmasked SSNs in QA for debugging, forgot to re-apply (4-day exposure)
  - Fix: All policies defined in YAML; GitHub Actions deploys and validates on every merge
- Post-deploy validation script (`sql/validation_queries.sql`) runs automatically in CI/CD
- Drift detection: weekly task compares live policies against YAML definition

---

## v2.0.0 — 2024-06-01

### Added
- **Row Access Policy** for hospital-level patient data isolation (`patient_hospital_isolation`)
  - 12 hospitals isolated in a single shared table — no per-hospital schemas needed
  - `hospital_role_map` table enables time-bounded, auditable access grants
- **SCIM provisioning** via Azure AD integration
  - Before: orphan roles persisted avg 47 days after employee departure
  - After: automatic deprovisioning within 15 minutes of HR system update
- Separate `AUDIT_DB` owned by `SECURITYADMIN` (immutable — no DELETE/UPDATE grants)
- S3 WORM archival task for 7-year HIPAA retention compliance

### Changed
- PHI databases (`RAW_DB`, `CLEANSED_DB`) ownership transferred from `SYSADMIN` → `SECURITYADMIN`
  - This is the most critical architectural change — data engineers can no longer query raw PHI

---

## v1.0.0 — 2024-01-15

### Added
- Initial RBAC hierarchy: 7 role levels (ACCOUNTADMIN → ANALYST)
- Dynamic Data Masking for 12 PHI field types (SSN, DOB, Name, MRN, Phone, Email, Address, ZIP, ICD-10, Medication, NPI, Account Number)
- Network policy with hospital IP whitelisting (12 campus ranges + VPN)
- Snowflake `QUERY_HISTORY`-based SELECT audit trail
- Basic compliance checklist mapping to HIPAA §164.312 and §164.514