# Tests Strategy

## Purpose

This document defines the testing strategy for `access-control-helper`.

The goal of the test suite is to validate the full analysis pipeline:

`Terraform -> parser -> resolver -> IR -> Alloy -> analyzer -> reporter`

The suite must provide confidence in two complementary dimensions:

1. **Implementation correctness**  
   The tool must correctly parse Terraform, build the internal model, generate Alloy, interpret Alloy results, and produce the expected access-control report.

2. **Scenario correctness**  
   The Terraform fixtures used in tests must represent realistic AWS S3 access-control situations, and the expected results must reflect the access-control model implemented by this project.

This strategy is intended to scale from a few scenarios to many scenarios (at least 100) without turning the repository into a collection of fragile, ad hoc golden files.

---

## Testing Goals

The test suite should provide confidence that:

- Terraform fixtures are valid and runnable as Terraform configurations.
- The parser and resolver correctly derive the intended configuration state.
- The IR correctly represents principals, buckets, policies, actions, resources, and conditions.
- The Alloy generator produces the expected formal model.
- Alloy checks the intended access properties for each `(principal, bucket, action)` triple.
- The reporter reconstructs final decisions and layer-by-layer statuses correctly.
- The tool distinguishes correctly between:
  - explicit deny,
  - missing grant paths,
  - resource/action mismatches,
  - permission-boundary restrictions,
  - and other relevant policy-layer effects.

---

## Current Scope

At the moment, the repository contains a `tests/` folder with four scenario-based tests.

This is a good starting point, but the current structure does not scale well if the number of scenarios grows significantly. In particular:

- generated Alloy outputs should not be stored as numbered files in the repository,
- semantic expectations should not be expressed only through text snapshots,
- and it should be possible to add new scenarios without duplicating test logic.

This document defines the target structure and implementation plan.

---

## Guiding Principles

The following principles guide the design of the test suite:

1. **Test the full pipeline, not isolated text output only.**  
   The main value of the project lies in the full transformation from Terraform to a formal access-control decision.

2. **Separate semantic truth from textual formatting.**  
   Structured expectations should define whether a scenario is correct. Golden files should only protect human-readable formatting.

3. **Keep scenarios easy to add.**  
   Adding a new scenario should require adding a new scenario folder, not writing a new custom test runner.

4. **Prefer generated temporary artifacts over committed generated files.**  
   Generated `.als` files should be written to temporary directories during test execution.

5. **Make test failures diagnostic.**  
   A failed test should explain whether the problem lies in semantics, formatting, parsing, or scenario validity.

---

## Recommended Test Structure

All scenario-based tests should live under `tests/`.

Recommended layout:

```text
tests/
  scenarios/
    <scenario-name-1>/
      input.tf
      expect.json
      report.golden.txt   # optional
    <scenario-name-2>/
      input.tf
      expect.json
      report.golden.txt   # optional
  e2e_scenarios_test.go
  reporter_snapshot_test.go
```

### Rules

- `input.tf` is the Terraform fixture for the scenario.
- `expect.json` is the semantic oracle for the scenario.
- `report.golden.txt` is optional and should be used only when the human-readable report format must be protected by a snapshot test.

---


## Scenario Naming

Scenarios should use descriptive names instead of generic folder names such as `scenario1`, `scenario2`, and so on.

Recommended naming style:

- `explicit_deny_vpce`
- `abac_not_granted`
- `abac_explicit_deny`
- `permission_boundary_blocks_allow`
- `scp_blocks_allow`
- `bucket_vs_object_resource_match`

The scenario name should communicate the semantic property being tested.

---

## Scenario Format

Each scenario folder should contain the following files.

### `input.tf`

The Terraform fixture that defines the scenario.

Requirements:

- it must be valid Terraform,
- it should be focused and self-contained,
- and it should model one key access-control behavior or one carefully chosen interaction between multiple behaviors.

### `expect.json`

This file contains the semantic expectation for the scenario.

It should store the expected result in structured form rather than as plain report text.

Expected contents include:

- principal,
- bucket,
- action,
- final decision,
- denial layer, if any,
- layer-by-layer statuses.

Example:

```json
{
  "name": "abac_explicit_deny",
  "queries": [
    {
      "principal": "developer",
      "bucket": "data",
      "action": "s3:GetObject",
      "decision": "DENY",
      "denied_at": "Layer 1",
      "layers": {
        "L1": "DENY",
        "L2": "PASS",
        "L3": "PASS",
        "L4": "NOT GRANTED",
        "L5": "PASS",
        "L6": "PASS",
        "L7": "PASS"
      }
    }
  ]
}
```

This is the main semantic source of truth.

### `report.golden.txt`

Optional snapshot of the human-readable report output.

Use this only when the formatting of the report itself needs protection against regressions.

---

## Main End-to-End Scenario Tests

Create `tests/e2e_scenarios_test.go`.

This file should implement a scenario runner that:

1. discovers all scenario folders under `tests/scenarios/`,
2. reads `input.tf`,
3. runs the full project pipeline,
4. writes the generated Alloy specification to a temporary `.als` file,
5. executes Alloy,
6. builds the resulting structured report data,
7. compares the result against `expect.json`.

### The end-to-end tests must verify:

- final decision (`ALLOW` / `DENY`),
- denial layer (`Layer 1`, `Layer 4/5`, etc.),
- layer-by-layer statuses,
- consistency across all queries generated from the scenario.

### Important principle

The main end-to-end tests must compare against **structured expectations**, not only raw text output.

---

## Reporter Snapshot Tests

Create `tests/reporter_snapshot_test.go`.

This file should contain a smaller number of representative snapshot tests for the human-readable report.

### Purpose

These tests protect:

- report layout,
- layer ordering,
- summary formatting,
- result wording.

### Rules

- Do not create a report snapshot for every scenario.
- Use snapshots only for a small set of representative scenarios.
- Keep semantic correctness in `expect.json`, not in the snapshot file.

---

## Terraform Validation for Fixtures

Every `input.tf` scenario should also be validated as Terraform.

For each scenario fixture, the test suite should run:

- `terraform fmt -check`
- `terraform init -backend=false`
- `terraform validate`

---

## Required Scenario Categories

The suite should eventually include at least the following categories.

### Explicit Deny

- explicit deny via VPCE condition overrides allow
- explicit deny via tag mismatch overrides identity allow
- explicit deny on one action but not another

### Grant Paths

- identity-based allow only
- resource-based allow only
- neither grant path applies
- ABAC allow matches
- ABAC allow does not match

### S3 Resource Matching

- `s3:GetObject` allowed while `s3:ListBucket` denied
- `s3:ListBucket` allowed while `s3:GetObject` denied
- bucket ARN vs object ARN matching works correctly

### Bounding Policies

- permissions boundary blocks identity-based allow
- SCP blocks otherwise-allowed access
- RCP blocks otherwise-allowed access
- session policy blocks otherwise-allowed access

### Multi-Statement Correctness

- multiple statements must not be flattened incorrectly
- different resources and actions must remain distinct
- separate principals must not be mixed across statements

---

## Regression and Metamorphic Tests

In addition to ordinary scenario tests, the suite should include regression tests for important invariants.

Examples:

- adding an unrelated resource must not change the result,
- renaming a Terraform resource label must not change the result,
- adding an extra allow must not override an explicit deny,
- removing an unused policy must not change the result,
- changing an ABAC tag from mismatch to match must change the result in the expected direction.

These tests help validate the stability of the model and reduce the risk of accidental regressions.

---

## Package-Level Tests

Scenario tests are necessary but not sufficient.

Focused package-level tests should also exist for critical components.

### `internal/ir/policy.go`

Test:

- `Principal = "*"`
- `Principal = { AWS = ... }`
- `Action` as string and array
- `Condition` parsing
- single statement vs statement array
- bucket ARN vs object ARN handling

### `internal/ir/builder.go`

Test:

- statements are not flattened incorrectly,
- role tags are propagated correctly,
- policy attachments populate role actions,
- permission boundaries are linked correctly,
- ABAC-relevant flags are represented correctly in the IR.

### `internal/generator/*`

Test:

- access assertions are created for each `(principal, bucket, action)` triple,
- bucket-level and object-level actions are distinguished correctly,
- generated Alloy facts match the expected IR,
- Layer 4 / Layer 5 logic is encoded as intended.

### `internal/reporter/reporter.go`

Test:

- `ALLOW` formatting,
- `DENY at Layer 1`,
- `NOT GRANTED` remains distinct from `DENY`,
- grant-path failures are represented correctly,
- summary and detailed report remain consistent.

---

## CI Requirements

The continuous integration pipeline should run:

- `go test ./...`
- end-to-end scenario tests
- reporter snapshot tests
- `terraform fmt -check` for all fixtures
- `terraform validate` for all fixtures

This keeps the project safe against regressions in both logic and fixture quality.

---

## Optional Live Parity Validation Against AWS

The standard test suite validates the project against its own modeled semantics.

To gain stronger confidence that the model matches real AWS behavior, the project should also support an **optional live parity suite**.

Suggested file:

```text
tests/live_parity_test.go
```

This suite should run only when explicitly enabled, for example via environment variables and a sandbox AWS account.

### For each selected canonical scenario:

1. run `terraform apply`,
2. assume the relevant role with `sts assume-role`,
3. issue real S3 API requests such as:
   - `list-objects-v2`
   - `head-object`
   - `get-object`
   - `put-object`
   - `delete-object`
4. compare:
   - actual AWS result,
   - tool result.

### Important note

This live suite is not intended for normal CI.

It is intended for:

- validation against AWS as an external oracle,
- thesis evaluation,
- and manual confidence-building for canonical scenarios.

---

## Criteria for Completion

The testing strategy can be considered implemented when:

- the current four scenarios have been migrated into the new structure,
- each scenario has `input.tf` and `expect.json`,
- end-to-end scenario discovery and execution are automatic,
- generated `.als` files are temporary and not stored as permanent artifacts,
- report snapshots are separated from semantic expectations,
- Terraform fixture validation is integrated,
- and adding a new scenario requires only adding a new folder, not duplicating test code.

---

## Implementation Guidance

When implementing this strategy, follow these principles:

- do not duplicate production logic inside tests,
- keep helpers reusable and scenario-driven,
- make failure messages highly diagnostic,
- implement the test infrastructure first,
- migrate the existing four scenarios next,
- then expand coverage to additional semantic categories.

The result should be a test suite that is:

- scalable,
- maintainable,
- semantically meaningful,
- and useful both for engineering validation and thesis-quality evaluation.

