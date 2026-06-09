# tests

## Running tests

```bash
# All e2e + snapshot tests (no Alloy JAR needed for generation checks)
go test ./tests/

# All unit tests (no Alloy JAR needed)
go test ./tests/unit/

# Everything
go test ./tests/... 

# Specific e2e test
go test ./tests/ -run TestScenarios_Generation
go test ./tests/ -run TestScenarios_Verification          # requires Alloy JAR
go test ./tests/ -run TestScenarios_Verification/identity_allow_only

# Regenerate expect.json after intentionally changing a scenario
go test ./tests/ -update -run TestScenarios_Verification/identity_allow_only

# Specific unit test file
go test ./tests/unit/ -run TestBuilder_
go test ./tests/unit/ -run TestPipeline_               # requires Alloy JAR

# Snapshot tests
go test ./tests/ -run TestReportSnapshot_
```

> `TestScenarios_Verification` and `TestPipeline_*` require the Alloy JAR at
> `tools/org.alloytools.alloy.dist.jar` and Java 11+. All other tests run without it.

---

## Structure

```
tests/
├── e2e_scenarios_test.go          End-to-end: runs the full pipeline for every scenario
│                                  in scenarios/ and compares output to expect.json.
│                                  TestScenarios_Generation — parse+codegen only, no JAR.
│                                  TestScenarios_Verification — full Alloy run, requires JAR.
│
├── reporter_snapshot_test.go      Snapshot tests for the human-readable report format.
│                                  Compares output against *.golden.txt files in testdata/snapshots/.
│
├── scenarios/                     E2e test fixtures. Each subfolder is one scenario:
│   │                              input.tf  — Terraform config to analyse
│   │                              expect.json — expected decisions per (principal, bucket, action)
│   │
│   ├── identity_allow_only/       Identity policy alone grants access (L5 happy path)
│   ├── explicit_deny_wins/        Explicit Deny in bucket policy overrides identity Allow (L1)
│   ├── permission_boundary_blocks/Permission boundary narrows effective permissions (L6)
│   ├── scp_blocks_allow/          SCP blocks action even when identity allows it (L3)
│   ├── rcp_blocks_allow/          RCP blocks action on the resource side (L2)
│   ├── scp_restricts_account_wide/SCP applies to all roles in the account including admin (L3)
│   ├── scp_and_boundary_combined/ SCP + boundary both restrict independently (L3 + L6)
│   ├── rcp_and_scp_combined/      RCP + SCP together (L2 + L3)
│   ├── vpce_and_abac_deny/        Bucket policy denies unless via VPCE + tag match (L1)
│   ├── bucket_policy_grants_same_account/ Bucket policy grants same-account role (L4)
│   ├── service_principal_allow/   Bucket policy grants a service principal (L4)
│   ├── notaction_identity/        NotAction in identity policy implicitly denies excluded action (L5)
│   └── error_demos/               Invalid .tf files used to test parser error handling
│                                  (no expect.json — these are expected to fail gracefully)
│
├── testdata/
│   ├── alloy/
│   │   └── identity_allow_only.als    Pre-generated Alloy spec used by analyzer and
│   │                                  pipeline unit tests (avoids running the full generator).
│   └── snapshots/
│       ├── allow.golden.txt           Expected report output for ALLOW decision
│       ├── deny_layer1.golden.txt     Expected report output for DENY at Layer 1
│       ├── deny_layer45.golden.txt    Expected report output for DENY at Layer 4/5
│       ├── deny_layer6.golden.txt     Expected report output for DENY at Layer 6
│       └── incomplete_warning.golden.txt  Expected output for incomplete-analysis warning
│
└── unit/                          Unit tests for individual internal packages.
    ├── analyzer_test.go           Tests Alloy JAR invocation and output parsing
    ├── config_validate_test.go    Tests IR config validation rules
    ├── generator_model_test.go    Tests AlloyID, ActionToAlloyID, ExpandAnalyzableActions, etc.
    ├── generator_predicates_test.go Tests predicate/assertion generation and naming
    ├── ir_builder_test.go         Tests IR construction from parsed Terraform resources
    ├── ir_policy_test.go          Tests IAM policy JSON parsing and statement helpers
    ├── managed_policies_test.go   Tests AWS managed policy ARN → S3 actions mapping
    ├── parser_schema_test.go      Tests HCL schema security-relevance classification
    ├── pipeline_integration_test.go Tests full IR → Alloy → reporter pipeline (requires JAR)
    ├── policy_document_datasource_test.go Tests aws_iam_policy_document data source parsing
    └── reporter_test.go           Tests access decision formatting and layer status logic
```
