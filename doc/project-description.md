# AWS S3 Access Control Helper

## Overview

`access-control-helper` is a static analysis tool for AWS S3 access control validation. It parses Terraform infrastructure-as-code files, transforms the resource definitions into a formal Alloy specification, and uses the Alloy model checker to verify whether specific principals (roles, users) can or cannot reach S3 buckets — and at which policy evaluation step access is granted or denied.

The tool answers: **"Can principal X access S3 bucket Y with action Z, and why?"**

---

## Problem Statement

AWS access control is layered. A single `s3:GetObject` call passes through up to seven policy evaluation layers before AWS grants or denies the request. When access is misconfigured, debugging the exact denial reason across IAM roles, bucket policies, SCPs, and permission boundaries is time-consuming and error-prone.

This tool automates that reasoning statically — without making any live AWS API calls — by encoding the AWS policy evaluation logic as an Alloy formal model and feeding it the parsed Terraform state.

---

## AWS S3 Policy Evaluation Order

AWS evaluates policies in a strict sequential order. The first explicit `Deny` wins. An `Allow` must survive all layers.

```
1. Deny Evaluation (Explicit Deny Check)              → DENY immediately if any policy has explicit Deny
2. AWS Organizations RCPs (Resource Control Policies) → must have Allow, else DENY
3. AWS Organizations SCPs (Service Control Policies)  → must have Allow, else DENY
4. Resource-Based Policies                            → ALLOW possible (principal-type dependent)
5. Identity-Based Policies                            → must have Allow, else DENY
6. IAM Permissions Boundaries                         → must have Allow, else DENY
7. Session Policies                                   → must have Allow, else DENY → ALLOW
```

The tool encodes each layer as an Alloy predicate, then asserts reachability through all layers for a given `(principal, resource, action)` triple.

---

## Core Concepts

| Concept | Description |
|---|---|
| **Principal** | An IAM entity: Role, User, Group, or AWS Service |
| **Resource** | An S3 Bucket or S3 Object (ARN-identified) |
| **Action** | An S3 API action (`s3:GetObject`, `s3:PutObject`, etc.) |
| **Policy** | A collection of `Statement`s attached to a principal or resource |
| **Statement** | A single Allow/Deny rule with Actions, Resources, Conditions |
| **Permission Boundary** | A policy that caps the maximum permissions of an IAM entity |
| **SCP** | AWS Organizations Service Control Policy |

---

## Toolchain

| Tool | Role |
|---|---|
| **Go** | Core application: parsing, transformation, orchestration |
| **HashiCorp HCL** (`github.com/hashicorp/hcl/v2`) | Parsing `.tf` Terraform files |
| **Alloy** (`https://alloytools.org/`) | Formal model checking of policy evaluation logic |
| **Alloy CLI / API** | Running `.als` specs and capturing counterexamples |

---

## High-Level Architecture

```
 Terraform Files (.tf)
         │
         ▼
 ┌───────────────┐
 │  HCL Parser   │  Reads aws_iam_role, aws_iam_policy, aws_s3_bucket,
 │               │  aws_s3_bucket_policy, aws_iam_role_policy_attachment
 └───────┬───────┘
         │  Internal Model (Go structs)
         ▼
 ┌───────────────┐
 │  Transformer  │  Converts Go model → Alloy signatures, facts, predicates
 └───────┬───────┘
         │  Alloy Specification (.als)
         ▼
 ┌───────────────┐
 │  Alloy Runner │  Executes alloy CLI, captures SAT/UNSAT + counterexamples
 └───────┬───────┘
         │  Raw Alloy output
         ▼
 ┌───────────────┐
 │   Reporter    │  Formats findings: which step caused the deny/allow
 └───────────────┘
         │
         ▼
  Human-readable report
```

---

## Input Format

The tool accepts standard Terraform resource definitions:

```hcl
resource "aws_iam_role" "example" {
  name = "example-role"
  assume_role_policy = jsonencode({ ... })
}

resource "aws_iam_policy" "s3_read" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::my-bucket/*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.example.name
  policy_arn = aws_iam_policy.s3_read.arn
}

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_policy" "my_bucket_policy" {
  bucket = aws_s3_bucket.my_bucket.id
  policy = jsonencode({ ... })
}
```

---

## Output Format

```
Access Analysis Report
======================

Query: Can role "example-role" perform s3:GetObject on bucket "my-bucket"?

Layer 1 - Deny Evaluation:     PASS (no explicit deny found)
Layer 2 - RCP:                 PASS (no RCP restrictions)
Layer 3 - SCP:                 PASS (no SCP restrictions)
Layer 4 - Resource Policy:     PASS (bucket policy allows)
Layer 5 - Identity Policy:     PASS (IAM policy allows s3:GetObject)
Layer 6 - Permission Boundary: PASS (no boundary set)
Layer 7 - Session Policy:      PASS (no session policy)

Result: ALLOW
```

Or on denial:

```
Layer 1 - Deny Evaluation:  DENY
  → Found explicit Deny in bucket policy for principal "example-role"
  → Statement: sid="BlockExternalAccess", Effect=Deny, Action=s3:*

Result: DENY at Layer 1
```

---

## Project Structure

```
access-control-helper/
├── main.go                        # CLI entry point & pipeline wiring
├── go.mod
├── internal/
│   ├── model/
│   │   └── model.go               # Core data types (Principal, Policy, Resource)
│   ├── parser/
│   │   └── terraform.go           # HCL Terraform parser
│   ├── transformer/
│   │   └── alloy.go               # Internal model → Alloy spec generator
│   ├── analyzer/
│   │   └── analyzer.go            # Alloy CLI runner & output parser
│   └── reporter/
│       └── reporter.go            # Human-readable output formatter
├── examples/
│   └── simple/
│       └── main.tf                # Example Terraform fixtures
└── doc/
    ├── project-description.md     # This file
    └── architecture-and-tests.md  # Architecture decisions & test scenarios
```

---

## Key Design Decisions

1. **Alloy over custom graph traversal** — Alloy's relational model naturally maps to the multi-layered evaluation graph. Writing custom traversal logic would be harder to reason about and validate.

2. **Static analysis only** — No AWS API calls. The tool works entirely from Terraform source, making it safe to run in CI without credentials.

3. **Layer-by-layer reporting** — Rather than just ALLOW/DENY, the tool reports which layer made the decision and why, directly guiding remediation.

4. **Terraform as source of truth** — Most AWS infrastructure is managed via Terraform. Parsing `.tf` directly means no intermediate state file dependency, though `terraform show -json` output is also a supported input.

---

## Requirements: Per-Action Access Evaluation

The tool must, for every (principal, bucket, action) triple:
- Evaluate access according to all AWS S3 policy evaluation steps (explicit Deny, RCP, SCP, resource-based, identity-based, permission boundaries, session policies).
- Correctly model explicit Deny and Allow statements from Terraform policies, including Deny for specific actions (e.g., s3:DeleteObject) and Allow for others (e.g., s3:GetObject).
- Output, for each query, the final access decision (ALLOW or DENY) and the evaluation layer responsible (e.g., DENY at Layer 1 due to explicit Deny in bucket policy).
- Generate Alloy assertions for every (principal, bucket, action) triple, so that Alloy checks confirm the tool's reasoning for each action.

### Example Requirement

Given a Terraform file with a bucket policy that Denies s3:DeleteObject and Allows s3:GetObject for a principal:
- The generated Alloy model must DENY DeleteObject at Layer 1 (explicit Deny) and ALLOW GetObject if it passes all layers.
- The Alloy output must show which layer made the decision and why, matching the AWS evaluation logic.
