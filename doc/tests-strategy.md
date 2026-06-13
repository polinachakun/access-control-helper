# Tests Strategy

## Overview

The test suite validates the full pipeline end-to-end:

`.tf` → parser → resolver → IR → Alloy spec → analyzer → reporter

| Test type | Location | Count |
|-----------|----------|-------|
| Scenario-based e2e tests | `tests/e2e_scenarios_test.go` | 12 scenarios (14 folders) |
| Reporter snapshot tests | `tests/reporter_snapshot_test.go` | 5 golden files |
| Package-level unit tests | `tests/unit/` | 11 test files |
| Deployable live parity | `evaluation/manual_verification/` | 10 configurations |

---

## Structure

```
tests/
├── scenarios/                  # e2e scenario folders
│   ├── <name>/
│   │   ├── input.tf            # Terraform fixture
│   │   └── expect.json         # Semantic expectations
│   └── error_demos/            # 4 invalid-input fixtures (unit tests only)
├── unit/                       # Package-level unit tests
├── testdata/snapshots/         # 5 golden files for report formatting
├── e2e_scenarios_test.go       # Auto-discovers and runs all scenario folders
└── reporter_snapshot_test.go
```

---

## Scenario-Based Tests

`e2e_scenarios_test.go` auto-discovers all folders under `tests/scenarios/`, runs the full pipeline on each `input.tf`, and compares output against `expect.json`. Each `expect.json` specifies per-triple `decision`, `denied_at`, and per-layer statuses (see `doc/project-description.md` → Output vocabulary).

**Motivating example**: scenario 8, three sub-cases sharing the same Terraform configuration with one variable changed (tag value or VPCE condition):

| Sub-case | Folder | What it tests |
|----------|--------|---------------|
| 8a | `vpce_and_abac_deny` | VPCE deny fires → DENY at L1 regardless of other policies |
| 8b | `abac_tag_mismatch` | VPCE satisfied; tags differ → no grant at L4 or L5 |
| 8c | `abac_tag_match` | VPCE satisfied; tags match → ALLOW via L4 |

**Remaining scenarios:**

| # | Folder | What it tests |
|---|--------|---------------|
| 1 | `identity_allow_only` | Identity-based allow only, no bucket policy |
| 2 | `explicit_deny_wins` | Explicit deny in bucket policy overrides identity allow |
| 3 | `permission_boundary_blocks` | Permission boundary blocks identity-based allow at L6 |
| 4 | `scp_blocks_allow` | SCP blocks otherwise-allowed access at L3 |
| 5 | `rcp_blocks_allow` | RCP blocks otherwise-allowed access at L2 |
| 6 | `scp_restricts_account_wide` | SCP applies to all roles including admin |
| 7 | `service_principal_allow` | AWS service principal granted via bucket policy |
| 9 | `scp_and_boundary_combined` | SCP and permission boundary apply independently |
| 10 | `rcp_and_scp_combined` | RCP and SCP both present |
| 11 | `notaction_identity` | `NotAction` in identity policy denies the excluded action at L5 |
| 12 | `bucket_policy_grants_same_account` | Resource-based allow via bucket policy, no identity grant |

### Error demos

`error_demos/` contains 4 `.tf` files that demonstrate pipeline error behaviour manually (`go run . <file> /tmp/out.als`). They are not part of the automated test suite.

| File | Pipeline behaviour |
|------|--------------------|
| `malformed_policy.tf` | Non-fatal warning; malformed bucket policy skipped, pipeline continues |
| `no_buckets.tf` | Fatal error: no S3 buckets found |
| `no_roles.tf` | Fatal error: no IAM roles or users found |
| `no_principals_statement.tf` | Non-fatal warning; role policy with no principal statement skipped |

---

## Reporter Snapshot Tests

Five golden files in `tests/testdata/snapshots/` cover all formatting branches in `reporter.go`:

| File | Verdict type |
|------|-------------|
| `allow.golden.txt` | ALLOW |
| `deny_layer1.golden.txt` | DENY at explicit deny layer (L1) |
| `deny_layer45.golden.txt` | DENY at missing grant path (L4/5) |
| `deny_layer6.golden.txt` | DENY at bounding layer (L6) |
| `incomplete_warning.golden.txt` | INCOMPLETE ANALYSIS warning header |

---

## Package-Level Unit Tests

`tests/unit/` covers all major packages:

| File | What it tests |
|------|---------------|
| `ir_policy_test.go` | JSON policy parsing, condition classification |
| `ir_builder_test.go` | IR construction from resolved resources |
| `config_validate_test.go` | `Config.Validate()` structural checks |
| `managed_policies_test.go` | AWS managed policy action resolution |
| `parser_schema_test.go` | HCL schema and resource type classification |
| `policy_document_datasource_test.go` | `aws_iam_policy_document` data source parsing |
| `generator_model_test.go` | Alloy ID conversion, action level classification |
| `generator_predicates_test.go` | Predicate generation and triple assertion structure |
| `analyzer_test.go` | Alloy CLI output parsing (SAT/UNSAT) |
| `reporter_test.go` | Result building and report formatting |
| `pipeline_integration_test.go` | Full pipeline on fixture inputs |

---

## Deploy Scenarios and Live Parity

`evaluation/manual_verification/` contains 10 deployable Terraform configurations covering the same semantic categories as the test scenarios:

| Deploy folder | Test scenario |
|--------------|---------------|
| `01_identity_allow_only` | `identity_allow_only` |
| `02_explicit_deny_wins` | `explicit_deny_wins` |
| `03_permission_boundary_blocks` | `permission_boundary_blocks` |
| `04_scp_blocks_allow` | `scp_blocks_allow` |
| `05_rcp_blocks_allow` | `rcp_blocks_allow` |
| `06_scp_restricts_account_wide` | `scp_restricts_account_wide` |
| `07_service_principal_allow` | `service_principal_allow` |
| `08_vpce_and_abac_deny` + `08b_abac_tag_mismatch` + `08с_abac_tag_match` | Motivating example (3 sub-scenarios) |
| `09_scp_and_boundary_combined` | `scp_and_boundary_combined` |
| `10_notaction_identity` | `notaction_identity` |

`validate_all.sh` generates `aws iam simulate-principal-policy` commands for each scenario, ready for execution in a sandbox AWS account.

Live parity evidence (AWS CLI output, console screenshots) is stored in `evaluation/manual_verification/screenshots/`.

