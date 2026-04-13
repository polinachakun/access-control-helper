# Architecture & Test Scenarios

## Component Architecture

### 1. Intermediate Representation (`internal/ir/`)

The central data model is a  Go representation of AWS policy constructs.

```
Config
├── Buckets:        []*S3Bucket
├── BucketPolicies: []*BucketPolicy
├── Roles:          []*IAMRole
├── RolePolicies:   []*RolePolicy
├── Users:          []*IAMUser
├── UserPolicies:   []*UserPolicy
├── Policies:       []*IAMPolicy
└── OrgPolicies:    []*OrgPolicy

S3Bucket
├── TFName: string
├── Tags:   map[string]string
├── EnvTag: string              (extracted from tags)
└── HasBPA: bool                (has aws_s3_bucket_public_access_block)

BucketPolicy
├── TFName:          string
├── BucketRef:       string     (reference to bucket, e.g. "aws_s3_bucket.data")
├── Policy:          *IAMPolicyDocument
├── DenyVpceID:      string     (VPCE ID from explicit deny condition)
├── AllowPrincipals: []string
├── AllowActions:    []string
├── DenyActions:     []string
├── DenyPrincipals:  []string
└── HasABAC:         bool       (has PrincipalTag condition)

IAMRole
├── TFName:            string
├── Name:              string
├── EnvTag:            string
├── Tags:              map[string]string
├── HasRolePolicy:     bool
├── RolePolicyActions: []string
├── HasBoundary:       bool
├── BoundaryRef:       string
├── BoundaryActions:   []string
├── HasSessionPolicy:  bool
└── AssumeRolePolicy:  *IAMPolicyDocument

OrgPolicy
├── TFName:       string
├── Name:         string
├── PolicyType:   string  ("SERVICE_CONTROL_POLICY" or "RESOURCE_CONTROL_POLICY")
├── Policy:       *IAMPolicyDocument
├── AllowActions: []string
└── DenyActions:  []string

IAMPolicyDocument
├── Version:    string
├── ID:         string
└── Statements: []*Statement

Statement
├── SID:        string
├── Effect:     string  ("Allow" or "Deny")
├── Actions:    []string
├── NotActions: []string
├── Resources:  []string
├── Principals: []Principal
└── Conditions: []Condition

Principal { Type, Value string }
Condition { Operator, Key string; Values []string }
```

**Policy parsing** (`ir/policy.go`): Parses JSON IAM policy documents. Handles both single statements and statement arrays. Normalizes Action/NotAction, Resource/NotResource, Principal. Extracts ABAC conditions (`aws:PrincipalTag/*`) and VPCE conditions (`aws:sourceVpce`).

**IR builder** (`ir/builder.go`): 3-pass construction — basic resources, policy resources, then linkage. Links bucket policies to buckets, role policies to roles, handles permission boundaries and policy attachments.

### 2. Parser (`internal/parser/`)

Reads HCL Terraform files using `github.com/hashicorp/hcl/v2` and `github.com/zclconf/go-cty`.

**Supported resource types (10):**

| Terraform Resource | Maps To |
|---|---|
| `aws_s3_bucket` | `S3Bucket` |
| `aws_s3_bucket_policy` | `BucketPolicy` |
| `aws_s3_bucket_public_access_block` | Sets `S3Bucket.HasBPA` |
| `aws_iam_role` | `IAMRole` |
| `aws_iam_role_policy` (inline) | `RolePolicy` |
| `aws_iam_role_policy_attachment` | Links `IAMRole` → `IAMPolicy` |
| `aws_iam_policy_attachment` | Links `IAMRole` → `IAMPolicy` |
| `aws_iam_user` | `IAMUser` |
| `aws_iam_user_policy` | `UserPolicy` |
| `aws_iam_policy` | `IAMPolicy` |
| `aws_organizations_policy` | `OrgPolicy` (SCP or RCP) |

**Parser output:** a `ParseResult` struct containing raw HCL resources, locals, and variables.

**Parsing strategy:**
1. Walk all `.tf` files in input directory (or parse a single file)
2. Collect all resource blocks by type
3. Cross-references are resolved by the Resolver, not the Parser
4. Inline JSON policy documents are parsed with `encoding/json` in `ir/policy.go`

**Not supported:** data sources (parsed but ignored), modules (skipped), complex nested blocks beyond 1 level.

### 3. Resolver (`internal/resolver/`)

Resolves cross-references between Terraform resources using HCL expression evaluation.

- `resolver.go`: Evaluates HCL expressions using `cty` library, extracts resource references (e.g. `aws_s3_bucket.my_bucket.id`), supports standard HCL functions (`jsonencode`, `jsondecode`, `lower`, `upper`, `replace`) and custom functions (`lookup`, `tostring`, `tolist`, `toset`, `tomap`)
- `graph.go`: Builds a dependency DAG, performs topological sort with cycle detection, returns resources in resolution order

**Output:** `map[string]*ResolvedResource` with evaluated attributes.

### 4. Generator (`internal/generator/`)

Converts the `Config` IR → an Alloy specification (`.als` file) using Go `text/template`.

**Alloy Specification Structure:**

```alloy
// AUTO-GENERATED from: scenario1.tf

// ── Scalar domains
abstract sig TagValue {}
one sig TAG_DEV, TAG_PROD extends TagValue {}

abstract sig VpceId {}
one sig VPCE_OTHER extends VpceId {}

abstract sig Action {}
one sig S3_GetObject extends Action {}

abstract sig Bool {}
one sig True, False extends Bool {}

// ── Resource hierarchy
abstract sig Resource { dependsOn: set Resource }

sig S3Bucket extends Resource {
  envTag:            one TagValue,
  blockPublicAccess: one Bool
}

sig BucketPolicy extends Resource {
  bucket:         one S3Bucket,
  denyAllExcept:  lone VpceId,
  allowPrincipal: lone IAMRole,
  allowActions:   set Action,
  denyActions:    set Action,
  denyPrincipal:  lone IAMRole,
  abacCondition:  one Bool
}

abstract sig OrgRCP extends Resource {
  rcpAllowActions: set Action,
  rcpDenyActions:  set Action
}

abstract sig OrgSCP extends Resource {
  scpAllowActions: set Action,
  scpDenyActions:  set Action
}

sig IAMRole extends Resource {
  envTag:               one TagValue,
  hasRolePolicy:        one Bool,
  roleAllowActions:     set Action,
  hasBoundary:          one Bool,
  boundaryActions:      set Action,
  hasSessionPolicy:     one Bool,
  sessionPolicyActions: set Action
}

// ── Concrete resources
one sig bucket_my_bucket extends S3Bucket {}
one sig role_app_role extends IAMRole {}

fact ExactUniverse {
  S3Bucket     = bucket_my_bucket
  BucketPolicy = none
  OrgRCP       = none
  OrgSCP       = none
  IAMRole      = role_app_role
  Resource     = S3Bucket + BucketPolicy + OrgRCP + OrgSCP + IAMRole
}

// ── Configuration facts
fact ConfigFacts {
  bucket_my_bucket.envTag = TAG_PROD
  bucket_my_bucket.blockPublicAccess = False

  role_app_role.envTag = TAG_PROD
  role_app_role.hasRolePolicy = True
  role_app_role.roleAllowActions = S3_GetObject
  role_app_role.hasBoundary = False
  role_app_role.boundaryActions = none
  role_app_role.hasSessionPolicy = False
  role_app_role.sessionPolicyActions = none
}

// ── Request signature
sig Request {
  principal:  one IAMRole,
  action:     one Action,
  target:     one S3Bucket,
  sourceVpce: lone VpceId
}

// ── Evaluation predicates (7 layers)
pred explicitDenyVpce[req: Request] { ... }
pred explicitDenyAction[req: Request] { ... }
pred explicitDeny[req: Request] { ... }
pred rcpAllows[req: Request] { ... }
pred scpAllows[req: Request] { ... }
pred resourcePolicyAllows[req: Request] { ... }
pred identityPolicyAllows[req: Request] { ... }
pred permBoundaryAllows[req: Request] { ... }
pred sessionPolicyAllows[req: Request] { ... }
pred accessAllowed[req: Request] { ... }

// ── Per-triple assertions (8 per triple: combined + L1–L7)
assert AppRoleCanGetObjectOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_GetObject and
     req.target = bucket_my_bucket)
    implies accessAllowed[req]
}
// ... plus _L1 through _L7 variants

// ── Check commands
check AppRoleCanGetObjectOnMyBucket
  for exactly 1 S3Bucket, exactly 0 BucketPolicy, ...
```

**Generator design notes:**
- Each unique action, principal, and resource from Terraform becomes an Alloy `one sig`
- ARNs are sanitized to valid Alloy identifiers (`AlloyID()`: hyphens → underscores, non-alphanumeric removed)
- Action conversion: `s3:GetObject` → `S3_GetObject`, `s3:*` → `S3_All` (full action set)
- Tag conversion: `prod` → `TAG_PROD`
- Baseline values added when config is minimal (ensures at least one tag, VPCE, and action exist)
- Generates 8 assertions per (role, bucket, action) triple: 1 combined + 7 per-layer

#### Alloy Primer

Alloy is a declarative constraint language. Understanding the generated `.als` file requires knowing four constructs:

| Construct | What it does | Example |
|---|---|---|
| `sig` | Declares a type (set of atoms) with named fields | `sig IAMRole { envTag: one TagValue }` |
| `one sig` | A singleton — exactly one atom of this type exists | `one sig role_app_role extends IAMRole {}` |
| `fact` | A constraint always true in every model instance | `fact ConfigFacts { role_app_role.envTag = TAG_PROD }` |
| `pred` | A named boolean condition over parameters | `pred accessAllowed[req: Request] { not explicitDeny[req] and ... }` |
| `assert` | A claim that a predicate must hold for all inputs | `assert AppRoleCanGetObject { all req: Request \| ... }` |
| `check` | Instructs the Analyzer to search for a counterexample | `check AppRoleCanGetObject for exactly 1 S3Bucket, ...` |

**How the Analyzer works:** `check` converts the negation of the assertion into a SAT formula and searches for a satisfying assignment within the given scope. "No counterexample found" (UNSAT) means the access rule holds for every possible request in the model.

### 5. Analyzer (`internal/analyzer/`)

Runs the Alloy model checker via Java and parses its text output.

**Alloy invocation:**
```
java -jar tools/org.alloytools.alloy.dist.jar exec -f spec.als
```

The Alloy jar is located at `tools/org.alloytools.alloy.dist.jar` (checked next to binary, then relative to working directory). Java is found via `JAVA_HOME` or system `PATH`.

**Output parsing:** Uses regex to match lines like:
```
00. check AppRoleCanGetObjectOnMyBucket     0    UNSAT
01. check AppRoleCanGetObjectOnMyBucket_L1  0    UNSAT
```

- `UNSAT` → `Valid=true` (assertion holds, no counterexample)
- `SAT` → `Valid=false, HasCounterExample=true` (assertion violated)

**Output:** `[]CheckResult` — one per `check` command, with assertion name, validity, and raw output.

### 6. Reporter (`internal/reporter/`)

Takes `[]CheckResult` and `[]TripleKey` and renders a human-readable access analysis report to stdout.

**Report structure:**
1. **Summary table** — compact view: Principal | Action | Bucket | Decision
2. **Per-triple breakdown** — 7-layer status for each (principal, bucket, action) triple

**Layer status logic:**
- Layers 1, 2, 3, 6, 7 (blocking layers): `PASS` or `DENY`
- Layers 4 and 5 (OR-ed grant layers): `PASS` or `NOT GRANTED` — both must fail for an actual deny
- Denied-at description: first DENY scanning L1→L7; for grant layers, shown as "Layer 4/5" when both fail

**Output types:** `TripleResult` (per-triple decision with 7 `LayerInfo` entries), `LayerInfo` (name + status).

**Not implemented:** JSON and SARIF output formats.

---

## Alloy Model Design (Core)

The hardest part is encoding AWS's policy evaluation correctly. Key rules:

### Explicit Deny (Layer 1)

Two sub-predicates combined with OR:

```alloy
// Layer 1a: VPCE guard — bucket policy denies requests without the required VPCE.
pred explicitDenyVpce[req: Request] {
  some bp: BucketPolicy |
    bp.bucket        = req.target and
    bp.denyAllExcept != none      and
    req.sourceVpce  != bp.denyAllExcept
}

// Layer 1b: Explicit Deny statement in bucket policy matching action and principal.
pred explicitDenyAction[req: Request] {
  some bp: BucketPolicy |
    bp.bucket = req.target and
    req.action in bp.denyActions and
    (bp.denyPrincipal = none or bp.denyPrincipal = req.principal)
}

// Layer 1: Any explicit deny fires immediately.
pred explicitDeny[req: Request] {
  explicitDenyVpce[req] or explicitDenyAction[req]
}
```

### RCP and SCP (Layers 2–3)

```alloy
// Layer 2: Every RCP must allow the action; no RCP means pass-through.
pred rcpAllows[req: Request] {
  no OrgRCP or
  (all rcp: OrgRCP |
    req.action in rcp.rcpAllowActions and
    req.action not in rcp.rcpDenyActions)
}

// Layer 3: Every SCP must allow the action; no SCP means pass-through.
pred scpAllows[req: Request] {
  no OrgSCP or
  (all scp: OrgSCP |
    req.action in scp.scpAllowActions and
    req.action not in scp.scpDenyActions)
}
```

### Resource-Based Policy with ABAC (Layer 4)

```alloy
// Layer 4: Bucket policy allows principal + action, with optional ABAC tag match.
pred resourcePolicyAllows[req: Request] {
  some bp: BucketPolicy |
    bp.bucket         = req.target    and
    bp.allowPrincipal = req.principal and
    req.action in bp.allowActions     and
    (bp.abacCondition = True implies
       req.principal.envTag = req.target.envTag)
}
```

### Identity Policy + Permission Boundary (Layers 5–6)

```alloy
// Layer 5: IAM role has a policy that explicitly allows the action.
pred identityPolicyAllows[req: Request] {
  req.principal.hasRolePolicy = True and
  req.action in req.principal.roleAllowActions
}

// Layer 6: If a boundary is set, the action must appear in its allow set.
pred permBoundaryAllows[req: Request] {
  req.principal.hasBoundary = False or
  req.action in req.principal.boundaryActions
}
```

### Session Policy (Layer 7)

```alloy
// Layer 7: If a session policy is present, the action must appear in its allow set.
pred sessionPolicyAllows[req: Request] {
  req.principal.hasSessionPolicy = False or
  req.action in req.principal.sessionPolicyActions
}
```

### Final Access Decision

```alloy
// All 7 layers must pass — no explicit deny and at least one grant path.
pred accessAllowed[req: Request] {
  not explicitDeny[req] and
  rcpAllows[req] and
  scpAllows[req] and
  (resourcePolicyAllows[req] or identityPolicyAllows[req]) and
  permBoundaryAllows[req] and
  sessionPolicyAllows[req]
}
```

---

## Test Scenarios

### Scenario 1 — Simple Allow via IAM Policy

**Setup:**
- IAM Role `app-role` with identity policy allowing `s3:GetObject` on `my-bucket`
- S3 bucket `my-bucket` with no bucket policy

**Expected:** ALLOW at Layer 5 (identity policy)

**Terraform fixture:** `testdata/scenario1.tf`
```hcl
resource "aws_iam_role" "app_role" { name = "app-role" ... }

resource "aws_iam_policy" "s3_read" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.app_role.name
  policy_arn = aws_iam_policy.s3_read.arn
}

resource "aws_s3_bucket" "my_bucket" { bucket = "my-bucket" }
```

---

### Scenario 2 — Explicit Deny in Bucket Policy overrides IAM Allow

**Setup:**
- IAM Role `app-role` with identity policy allowing `s3:*`
- Bucket policy with explicit Deny on `s3:DeleteObject` for all principals
- Bucket policy allowing `s3:GetObject` for the role

**Expected:** DENY at Layer 1 for `s3:DeleteObject`, ALLOW for `s3:GetObject`

**Terraform fixture:** `testdata/scenario2.tf`

**Key assertion:**
```alloy
assert AppRoleCannotDeleteOnMyBucket {
  all req: Request |
    (req.principal = role_app_role and
     req.action = S3_DeleteObject and
     req.target = bucket_my_bucket)
    implies not accessAllowed[req]
}
```

---

### Scenario 3 — Access Blocked by Permission Boundary

**Setup:**
- IAM Role `restricted-role` with identity policy allowing `s3:*`
- Permission boundary on `restricted-role` that only allows `s3:GetObject`

**Expected:** DENY at Layer 6 for `s3:PutObject` (permission boundary), ALLOW for `s3:GetObject`

**Terraform fixture:** `testdata/scenario3.tf`

**Key point:** identity policy alone is insufficient; both identity policy AND boundary must allow.

---

### Scenario 4 (LISTING) — ABAC Tag Mismatch Denies Access

**Setup:**
- IAM Role `dev-role` with "environment=dev" tag
- S3 bucket `data-bucket` with "environment=prod" tag
- Bucket policy with `aws:PrincipalTag/environment` condition requiring tag match

**Expected:** DENY at Layer 4/5 (resource policy does not grant due to tag mismatch, and no other grant path)

**Terraform fixture:** `testdata/test.tf`

**Key point:** ABAC condition `bp.abacCondition = True implies req.principal.envTag = req.target.envTag` prevents cross-environment access.

---

### Scenario 5 — Bucket Policy Grants Cross-Account Access (No IAM Policy Needed)

**Setup:**
- IAM Role `cross-account-role` in account `111111111111`
- Bucket in account `222222222222`
- Bucket policy explicitly allows `cross-account-role`'s ARN

**Expected:** ALLOW via Layer 4 (resource-based policy) — identity-based policy not required for cross-account.

---

### Scenario 6 — SCP Blocks Access Org-Wide

**Setup:**
- AWS Organization SCP denying `s3:DeleteBucket` for all principals
- IAM Role with full `s3:*` identity policy

**Expected:** DENY at Layer 3 for `s3:DeleteBucket`

---

### Scenario 7 — Wildcard Resource in Policy

**Setup:**
- IAM policy with `Resource = "*"` allowing `s3:GetObject`
- Query against a specific bucket

**Expected:** ALLOW (wildcard matches all buckets)

**Test note:** generator must expand `"*"` to include all known `Resource` sigs in the Alloy spec.

---

### Scenario 8 — Implicit Deny (No Policy Covers the Action)

**Setup:**
- IAM Role with no policies attached
- S3 bucket with no bucket policy

**Expected:** IMPLICIT DENY (no Allow found anywhere, Layer 4/5 both NOT GRANTED)

---

### Scenario 9 — Inline Policy vs Managed Policy

**Setup:**
- `aws_iam_role_policy` (inline) and `aws_iam_policy` + attachment (managed) on same role
- Inline policy allows `s3:GetObject`, managed policy allows `s3:PutObject`

**Expected:** both actions ALLOW (union of all attached policies)

---

## Requirements & Test Scenarios: Per-Action Access Evaluation

The system must:
- For every (principal, bucket, action) triple, evaluate access according to all AWS S3 policy evaluation steps (explicit Deny, RCP, SCP, resource-based, identity-based, permission boundaries, session policies).
- Correctly model explicit Deny and Allow statements from Terraform policies, including Deny for specific actions (e.g., s3:DeleteObject) and Allow for others (e.g., s3:GetObject).
- Output, for each query, the final access decision (ALLOW or DENY) and the evaluation layer responsible (e.g., DENY at Layer 1 due to explicit Deny in bucket policy).
- Generate Alloy assertions for every (principal, bucket, action) triple, so that Alloy checks confirm the tool's reasoning for each action.

### Example Test Scenario

Given a Terraform file with a bucket policy that Denies s3:DeleteObject and Allows s3:GetObject for a principal:
- The generated Alloy model must DENY DeleteObject at Layer 1 (explicit Deny) and ALLOW GetObject if it passes all layers.
- The Alloy output must show which layer made the decision and why, matching the AWS evaluation logic.

---

## Table: AWS S3 Access Control Scenarios (Terraform → Alloy)

| AWS Evaluation Step | Terraform Resource(s) | Scenario Description | Expected Alloy Predicate | Example Outcome |
|---------------------|----------------------|---------------------|-------------------------------|-----------------|
| 1. Explicit Deny    | aws_s3_bucket_policy, aws_iam_policy, aws_organizations_policy | Policy with `Effect = "Deny"` for principal/action/resource | `explicitDeny[req]` (via `explicitDenyAction` or `explicitDenyVpce`) | DENY at Layer 1 |
| 1. Explicit Deny    | aws_s3_bucket_policy | No explicit Deny for action/principal | `not explicitDeny[req]` | Continue to next layer |
| 2. RCP              | aws_organizations_policy (RCP) | RCP does not allow action | `not rcpAllows[req]` | DENY at Layer 2 |
| 2. RCP              | aws_organizations_policy (RCP) | RCP allows action | `rcpAllows[req]` | Continue to next layer |
| 3. SCP              | aws_organizations_policy (SCP) | SCP does not allow action | `not scpAllows[req]` | DENY at Layer 3 |
| 3. SCP              | aws_organizations_policy (SCP) | SCP allows action | `scpAllows[req]` | Continue to next layer |
| 4. Resource-Based   | aws_s3_bucket_policy | Bucket policy allows action for principal (+ ABAC match) | `resourcePolicyAllows[req]` | ALLOW at Layer 4 (if principal is cross-account) |
| 4. Resource-Based   | aws_s3_bucket_policy | No bucket policy allows action | `not resourcePolicyAllows[req]` | Continue to next layer |
| 5. Identity-Based   | aws_iam_policy, aws_iam_role_policy | Identity policy allows action | `identityPolicyAllows[req]` | Continue to next layer |
| 5. Identity-Based   | aws_iam_policy, aws_iam_role_policy | No identity policy allows action | `not identityPolicyAllows[req]` | NOT GRANTED at Layer 5 |
| 6. Permission Boundary | aws_iam_role (permissions_boundary), aws_iam_policy | Permission boundary allows action | `permBoundaryAllows[req]` | Continue to next layer |
| 6. Permission Boundary | aws_iam_role (permissions_boundary), aws_iam_policy | Permission boundary does not allow action | `not permBoundaryAllows[req]` | DENY at Layer 6 |
| 7. Session Policy   | aws_iam_policy (session), sts:AssumeRoleWithPolicy | Session policy allows action | `sessionPolicyAllows[req]` | ALLOW at Layer 7 |
| 7. Session Policy   | aws_iam_policy (session), sts:AssumeRoleWithPolicy | Session policy does not allow action | `not sessionPolicyAllows[req]` | DENY at Layer 7 |
| ABAC Condition      | aws_s3_bucket_policy (with PrincipalTag condition) | Tag match required and tags don't match | `bp.abacCondition = True implies req.principal.envTag = req.target.envTag` | NOT GRANTED at Layer 4 |
| VPCE Guard          | aws_s3_bucket_policy (with sourceVpce condition) | Request from wrong VPCE | `explicitDenyVpce[req]` | DENY at Layer 1 |
| Implicit Deny       | (any, when no Allow found) | No policy allows action at any layer | L4 and L5 both NOT GRANTED | IMPLICIT DENY |
| Wildcard Action     | any policy | `Action = ["s3:*"]` | Generator converts to `S3_All`, returns full Action set | All actions covered |
| No Policy           | (none) | No relevant policy attached | No predicate matches | IMPLICIT DENY |

---

## Implementation Status

```
Phase 1 — Foundation                                    [COMPLETE]
  [x] Data model (ir/types.go) with Config, S3Bucket, IAMRole,
      BucketPolicy, OrgPolicy, IAMPolicyDocument, Statement
  [x] Terraform parser for 10 resource types (parser/parser.go, schema.go)
  [x] Alloy template generation (generator/template.go)

Phase 2 — Core Analysis                                 [COMPLETE]
  [x] Policy attachment resolution via dependency graph
      (resolver/graph.go + ir/builder.go)
  [x] Full Alloy spec with 7 evaluation layers
      (generator/predicates.go — 10 predicates including sub-predicates)
  [x] Alloy CLI integration & output parsing
      (analyzer/analyzer.go — regex-based SAT/UNSAT parsing)
  [x] Per-action access evaluation with layer-by-layer decision reporting
      (reporter/reporter.go — TripleResult with 7 LayerInfo entries)

Phase 3 — Coverage                                      [PARTIAL]
  [x] aws_organizations_policy (SCP + RCP) parsing and Alloy modeling
  [x] Permission boundary parsing and Alloy modeling (Layer 6)
  [x] ABAC conditions (aws:PrincipalTag/*) in bucket policy evaluation (Layer 4)
  [x] VPCE conditions (aws:sourceVpce) in explicit deny evaluation (Layer 1)
  [ ] General IAM conditions (StringEquals on non-tag keys, ArnLike, IpAddress, etc.)
  [ ] Cross-account analysis
  [ ] User identity policies in Alloy model (parsed in IR but not generated)
  [ ] Session policy action extraction (flag exists, actions always empty)
  [ ] NotAction / NotResource evaluation (parsed but not used)
  [ ] Partial wildcard matching (s3:Get* — only s3:* is handled)

Phase 4 — UX & Testing                                  [PENDING]
  [ ] JSON and SARIF output formats
  [ ] CI mode (exit code 1 on DENY findings)
  [ ] Unit tests (no _test.go files exist)
  [ ] Integration tests with testdata scenarios
```

---

## Dependencies (go.mod)

```
github.com/hashicorp/hcl/v2          v2.19.1   # HCL parsing
github.com/zclconf/go-cty            v1.14.1   # HCL value types
```
