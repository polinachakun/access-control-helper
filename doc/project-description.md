# AWS S3 Access Control Helper — Project Description

## What the tool does

`access-control-helper` is a static analysis tool that answers access-control queries of the form *"can principal X perform action Z on bucket Y?"* directly from Terraform source code, without deploying to AWS.

**Pipeline:** `.tf` files → HCL parser → resolver → IR → Alloy spec → Alloy model checker → layer-aware report

The tool not only produces an `ALLOW` / `DENY` / `CONDITIONAL_ALLOW` verdict but identifies which policy layer blocks the request or which grant path does not apply.

---

## Problem and research position

AWS policy evaluation logic considers up to seven policy categories in sequence (explicit deny → RCPs → SCPs → resource-based → identity-based → permission boundaries → session policies). The final decision depends on the combination of all applicable policies, not on each category independently. Debugging a denial across these categories in live infrastructure is time-consuming.

The tool addresses this through **pre-deployment static analysis**: it constructs a local semantic model from interacting Terraform resources and uses Alloy-based formal verification to check access properties. This sits between two existing approaches:

- static IaC linters (pre-deployment but rule-based, not multi-resource semantic),
- dedicated policy analyzers (semantic but require live infrastructure or isolated policy documents).

---

## AWS policy evaluation order

```
L1  Explicit Deny check        → DENY if any policy has explicit Deny
L2  Organizations RCPs         → must have Allow, else DENY
L3  Organizations SCPs         → must have Allow, else DENY
L4  Resource-based policies    → ALLOW possible (union with L5 within same account)
L5  Identity-based policies    → must have Allow (or L4 already granted), else DENY
L6  IAM Permissions Boundaries → must have Allow, else DENY
L7  Session Policies           → must have Allow if present, else DENY → ALLOW
```

Key semantic rules the tool encodes:
- Within the same account, L4 and L5 grant paths are **union** — either one is sufficient.
- Cross-account principals require **both** L4 and L5 to grant (intersection); detected via assume-role ARN patterns.
- A failed `Condition` in an Allow statement is **not** an explicit deny — the statement simply does not apply.
- S3 actions apply at different resource levels: some target the bucket itself, others target objects within it. Policies must match accordingly.
- Actions not mentioned in any policy are **implicitly denied** (AWS default).

---

## Architecture

```
 Terraform (.tf)
      │
      ▼
 ┌──────────┐
 │  Parser  │  HCL parsing of 10 resource types
 └────┬─────┘
      ▼
 ┌──────────┐
 │ Resolver │  Cross-reference resolution, ARN interpolations, dependency DAG
 └────┬─────┘
      │  internal representation
      ▼
 ┌──────────────┐
 │  Generator   │  IR → Alloy signatures, facts, per-triple assertions (8 per triple)
 └────┬─────────┘
      │  .als spec
      ▼
 ┌──────────┐
 │ Analyzer │  Alloy CLI runner, SAT/UNSAT output parser
 └────┬─────┘
      ▼
 ┌──────────┐
 │ Reporter │  Access verdicts + layer-by-layer diagnostics
 └──────────┘
```

---

## Project structure

```
access-control-helper/
├── main.go / run.go               # CLI entry point and pipeline execution
├── internal/
│   ├── parser/                    # HCL parser + body schemas
│   ├── resolver/                  # Cross-reference resolver + dependency DAG
│   ├── ir/
│   │   ├── types.go               # Config, S3Bucket, IAMRole, ServicePrincipal, ...
│   │   ├── policy.go              # IAM policy JSON parser (Action, NotAction, Condition, ...)
│   │   ├── builder.go             # Builds Config IR — core, linkResources, detectCrossAccount
│   │   ├── builder_s3.go          # S3 bucket/policy builder and statement expansion
│   │   ├── builder_iam.go         # IAM role/user/policy builders and attachments
│   │   ├── builder_helpers.go     # Attribute accessors and ref helpers
│   │   ├── blockpath.go           # Determines which layer denied access
│   │   └── managed_policies.go    # Resolves aws_iam_policy attachments to roles
│   ├── preflight/hcl_syntax.go    # HCL syntax pre-check
│   ├── generator/                 # Alloy spec generation (model, predicates, template)
│   ├── analyzer/analyzer.go       # Alloy CLI runner
│   └── reporter/reporter.go       # Human-readable report formatter
├── tests/
│   ├── scenarios/                 # 14 e2e scenarios (input.tf + expect.json)
│   ├── unit/                      # Package-level unit tests
│   ├── testdata/snapshots/        # Golden files for 4 report verdict types
│   ├── e2e_scenarios_test.go      # Auto-discovery scenario runner
│   └── reporter_snapshot_test.go
├── evaluation/
│   ├── robustness/                # TerraDS dataset evaluation
│   │   ├── evaluate.py            # Phases 1–3 evaluation script
│   │   └── results/               # Phase JSON results + plots
│   ├── scalability/               # Go benchmark + plots for scaling analysis
│   └── manual_verification/       # 10+ deployable Terraform scenarios for live parity
│       └── validate_all.sh        # Generates aws iam simulate-principal-policy commands
└── doc/
```

---

## Key design decisions

| Decision | Rationale                                                                                                                                                              |
|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Alloy as sole evaluation engine | Authorization logic is relational; Alloy's SAT-based model checker eliminates need for a parallel Go evaluator and provides formal correctness guarantees within scope |
| Per-triple analysis | Each `(principal, bucket, action)` triple gets 8 Alloy assertions (L1–L7 + combined), enabling per-layer diagnostics from SAT/UNSAT results alone                      |
| No live AWS calls | Operates on Terraform source pre-deployment; no credentials or deployed infrastructure required                                                                        |
| Layer-aware reporting | Three distinct outcomes with different remediation: distinguishes explicit deny vs missing grant path vs condition failure                                             |
| Wildcard action analysis | When a policy grants `s3:*`, the tool determines whether actions not explicitly analyzed would still be blocked by a bounding layer (SCP, RCP, or permission boundary) |

---

## Implemented capabilities

**Terraform input:**
- 10 resource types: `aws_s3_bucket`, `aws_s3_bucket_policy`, `aws_s3_bucket_public_access_block`, `aws_iam_role`, `aws_iam_role_policy`, `aws_iam_role_policy_attachment`, `aws_iam_user`, `aws_iam_user_policy`, `aws_iam_policy`, `aws_organizations_policy`
- HCL syntax pre-check (preflight) before main pipeline
- Managed policy attachment resolution (`aws_iam_policy` via `aws_iam_role_policy_attachment`)

**Policy semantics:**
- Explicit deny (L1), RCP (L2), SCP (L3), resource-based (L4), identity-based (L5), permission boundary (L6), session policy (L7)
- Session policy (L7) always passes in Terraform analysis: session policy content is a runtime `sts:AssumeRole` parameter, not present in Terraform source; shown as `NOT APPLICABLE` in reports
- Bucket-scoped identity grants (`IdentityAllowActionsPerBucket`) and boundary scoping per bucket
- `NotAction` in Allow/Deny statements (correctly modeled as implicit deny for excluded actions at L5)
- ABAC tag conditions (`aws:PrincipalTag/environment`) — tag-match and tag-mismatch produce distinct L4 outcomes
- VPCE deny conditions (`aws:sourceVpce` with `StringNotEquals`)
- Service principals (`lambda.amazonaws.com` etc.) in bucket policies
- Unrecognized condition operators → `CONDITIONAL_ALLOW` (noted but not modeled)

**S3 actions:**
- Any explicit S3 action in the configuration is analyzed; `actionLevelFacts` in `generator/action_levels.go` classifies all known S3 actions by resource level (bucket vs object ARN)
- Actions absent from configuration → implicit deny (no triple generated, consistent with AWS default)
- Wildcard actions (`s3:*`) → full Alloy `Action` universe; the tool determines whether unlisted actions would be blocked by explicit deny (L1), RCP (L2), SCP (L3), or permission boundary (L6)

**Validation and diagnostics:**
- `Config.Validate()` — structural checks (no buckets, no principals, empty policy attachments, public exposure risk)
- Unsupported resource-type classification: security-relevant types trigger `IncompleteWarning`; non-security types silently ignored

**Toolchain:** 
- Go 1.21, `github.com/hashicorp/hcl/v2` (Terraform parsing),
- Alloy 6 (`alloytools.org`, formal verification),
- Python 3 + SQLite (dataset evaluation),
- Python matplotlib (benchmark plots).

---

## Output vocabulary

### Final verdict (per triple)

| Verdict | Meaning |
|---------|---------|
| `ALLOW` | All evaluation layers passed; access is granted |
| `DENY` | At least one layer blocked or no grant path exists |
| `CONDITIONAL_ALLOW` | A bucket policy Allow statement matches but carries unrecognized conditions; access depends on runtime context not available in Terraform source |

### Layer status (per layer, per triple)

| Status | Applies to | Meaning |
|--------|-----------|---------|
| `PASS` | L1, L2, L3, L4, L5, L6, L7 | Layer did not block; for L4/L5: a grant was found |
| `DENY` | L1, L2, L3, L6 | This layer explicitly blocked access |
| `NOT GRANTED` | L4, L5 | No applicable Allow statement found at this layer |
| `NOT APPLICABLE` | L7 | Session policy layer not relevant (always the case in Terraform analysis) |

### Denied at (location of the blocking layer)

| Value | Cause |
|-------|-------|
| `Layer 1` | Explicit Deny statement in bucket policy or identity policy |
| `Layer 2` | RCP does not allow the action |
| `Layer 3` | SCP does not allow the action |
| `Layer 4/5` | No grant from either resource-based or identity-based policy |
| `Layer 4` | Identity policy grants but resource policy does not (cross-account only) |
| `Layer 5` | Resource policy grants but identity policy does not (cross-account only) |
| `Layer 6` | Permission boundary does not allow the action |
