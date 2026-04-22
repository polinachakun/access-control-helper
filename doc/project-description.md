# AWS S3 Access Control Helper

## Overview

`access-control-helper` is a static analysis tool for validating AWS S3 access control from Terraform source code. It parses Terraform `.tf` files, resolves references and interpolations, builds an internal authorization model, translates that model into Alloy, and uses the Alloy Analyzer to check whether a given principal can access a bucket with a given S3 action.

The tool answers two practical questions:

- **Can principal X perform action Z on bucket Y?**
- **If not, what policy layer blocks the request, or which expected grant path does not apply?**

The purpose of the tool is not only to produce an `ALLOW` or `DENY` verdict, but also to expose misconfigurations that contribute to the result, such as explicit deny statements, missing identity-based grants, permission-boundary restrictions, or conditional bucket-policy grants that do not apply.

---

## Problem Statement

AWS access control is layered. A single `s3:GetObject` call passes through up to seven policy evaluation layers before AWS grants or denies the request. When access is misconfigured, debugging the exact denial reason across IAM roles, bucket policies, SCPs, and permission boundaries is time-consuming and error-prone.

This project addresses that problem through static pre-deployment analysis:

- it operates directly on Terraform source code,
- it builds a local semantic model of the access-control configuration,
- it translates that model into Alloy,
- and Alloy checks concrete access properties through formal model checking rather than through ad hoc rule matching.

No live AWS API calls are required.


---
## Research Goal

The goal of the project is to bridge the gap between:

- static IaC analyzers, which operate pre-deployment but rely on hardcoded rules and cannot reason semantically across multiple resources, and
- semantic policy analyzers, which can reason about authorization but typically require deployed infrastructure or isolated policy documents rather than Terraform source as input.

The tool combines:
- pre-deployment operation,
- Terraform source as input,,
- local model construction from interacting Terraform resources, 
- semantic access evaluation through formal reasoning using Alloy.
---

## Current Scope

The current implementation focuses on **AWS S3 access control scenarios derived from Terraform configurations**. It currently models:

- S3 buckets,
- S3 bucket policies,
- IAM roles,
- inline and attached IAM role policies,
- permissions boundaries,
- AWS Organizations SCPs and RCPs,
- selected ABAC-style conditions such as environment-tag matching,
- and per-action evaluation for supported S3 actions.

The tool is designed around **role → bucket → action** queries and reports results per `(principal, bucket, action)` triple.

---
## AWS S3 Policy Evaluation Order (CHECK IF IT IS CORRECT)

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

The overall decision follows AWS semantics:

- an explicit Deny takes precedence,
- access must survive each applicable layer,
- and a request is allowed only if the required permissions are available and not blocked by later constraints.

The tool encodes each layer as an Alloy predicate, then asserts reachability through all layers for a given `(principal, resource, action)` triple.

---

---

## AWS Policy Evaluation Semantics Relevant to This Tool

AWS policy evaluation is layered, but the semantics are more subtle than a simple linear “must allow at every step” pipeline.

The key rules relevant to this project are:

1. **Any applicable explicit `Deny` overrides all allows.** :contentReference[oaicite:4]{index=4}

2. **Within the same account, identity-based and resource-based policies are combined by union.**  
   If an action is allowed by an identity-based policy, a resource-based policy, or both, then the action can be allowed unless another policy type blocks it. :contentReference[oaicite:5]{index=5}

3. **Permissions boundaries and session policies restrict effective permissions.**  
   For IAM roles, permissions granted through policy evaluation are still limited by applicable permissions boundaries and session policies. :contentReference[oaicite:6]{index=6}

4. **A failed `Condition` in an `Allow` statement is not an explicit deny.**  
   It means the statement does not apply, so the expected allow is not granted. :contentReference[oaicite:7]{index=7}

5. **S3 actions must match the correct resource type.**  
   For example, `s3:ListBucket` is bucket-level and requires the bucket ARN, while `s3:GetObject` is object-level and requires the object ARN (`bucket/*`). :contentReference[oaicite:8]{index=8}

This project therefore treats AWS evaluation as a combination of:

- **blocking checks** such as explicit deny, SCP/RCP restrictions, permissions boundaries, and session policies, and
- **grant paths** such as resource-based and identity-based permissions.

---

## Policy Evaluation View Used by the Tool

For each `(principal, bucket, action)` triple, the tool evaluates the following logical structure:

1. **Deny evaluation** — detect applicable explicit deny conditions.
2. **Organizations constraints** — evaluate RCP and SCP effects if present.
3. **Grant paths**
    - resource-based bucket-policy grant,
    - identity-based IAM grant.
4. **Bounding constraints**
    - permissions boundary,
    - session policy.

This means that the tool distinguishes between:

- a request that is denied because a blocking layer explicitly rejects it, and
- a request that is denied because an expected grant path does not apply.

That distinction is especially important for ABAC-style bucket policies, where a tag mismatch may prevent an `Allow` statement from applying without creating an explicit deny.


## Core Concepts

| Concept | Description |
|---|---|
| **Principal** | An IAM entity: Role, User, Group, or AWS Service |
| **Resource** | An S3 Bucket or S3 Object (ARN-identified) |
| **Action** | An S3 API action (`s3:GetObject`, `s3:PutObject`, etc.) |
| **Policy** | A collection of `Statement`s attached to a principal or resource |
| **Statement** | A single Allow/Deny rule with Actions, Resources, Conditions |
| **Grant Path** | A policy path that can grant access, such as a resource-based or identity-based policy |
| **Blocking Layer** | A policy layer that can independently block access, such as explicit deny or a permissions boundary |
| **ABAC Condition** | A condition based on attributes or tags, such as `aws:PrincipalTag/environment` |

---

## Toolchain

| Tool | Role |
|---|---|
| **Go** | Core application: parsing, transformation, orchestration |
| **HashiCorp HCL** (`github.com/hashicorp/hcl/v2`) | Parsing `.tf` Terraform files |
| **Alloy** (`https://alloytools.org/`) | Formal model checking of policy evaluation logic |
| **Alloy CLI / API** | Running `.als` specs and capturing counterexamples |

---

## About Alloy

**Alloy** is a declarative, constraint-based modeling language and model checker developed at MIT. A model is built from three primitives:

- **Signatures (`sig`)** — define types and their fields, similar to structs but with relational semantics. `one sig` declares a singleton (a concrete resource instance).
- **Facts** — constraints that must always hold in every instance of the model. Used here to assign concrete Terraform configuration values to each resource.
- **Predicates (`pred`) and Assertions (`assert`)** — predicates are named, reusable conditions; assertions state that a predicate must hold for all possible inputs within the scope.

The **Alloy Analyzer** converts the model to a SAT formula and exhaustively searches for a *counterexample* — an input that violates an assertion — within a user-specified scope (e.g. `for exactly 1 S3Bucket, exactly 1 IAMRole`). If no counterexample is found, the assertion is proven correct within that scope.

**Why Alloy in this tool:**

The central challenge in this project is not parsing Terraform, but correctly reasoning about the interaction of multiple policies, resources, and evaluation layers. This reasoning is naturally relational:

- principals are linked to policies,
- policies contain statements,
- statements refer to actions and resources,
- conditions may depend on attributes stored in other resources,
- the final decision depends on an ordered combination of all these relationships.

Alloy is well suited to this kind of problem because it allows the authorization logic to be expressed declaratively rather than procedurally. Instead of implementing access decisions as step-by-step control flow, the tool defines the structural relationships and constraints that characterize when access must be allowed or denied.

This makes the project primarily a formal model extraction and checking approach for Terraform-based AWS S3 access control.

---

## High-Level Architecture

```
 Terraform Files (.tf)
         │
         ▼
 ┌───────────────┐
 │  HCL Parser   │  Reads Terraform resource blocks
 │               │  
 └───────┬───────┘
          │
         ▼
 ┌───────────────┐
 │  Resolver     │  Resolves links, interpolations, and dependencies 
 │               │  
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
 │   Reporter    │  Interprets results as access verdicts  and layer-specific  explanations    
 └───────────────┘
         │
         ▼
  Human-readable report
```
---

## Project Structure

```
access-control-helper/
├── main.go                        # CLI entry point & pipeline wiring
├── go.mod
├── internal/
│   ├── parser/
│   │   ├── parser.go              # HCL Terraform parser (9 resource types)
│   │   └── schema.go              # HCL body schemas per resource type
│   ├── resolver/
│   │   ├── resolver.go            # Cross-reference resolution (ARN interpolations)
│   │   └── graph.go               # Dependency DAG + topological sort
│   ├── ir/
│   │   ├── types.go               # Domain model: Config, S3Bucket, IAMRole, etc.
│   │   ├── policy.go              # IAM policy document parsing (JSON)
│   │   └── builder.go             # Builds Config IR from resolved resources
│   ├── generator/
│   │   ├── generator.go           # Alloy spec generation orchestrator
│   │   ├── template.go            # Alloy template strings and boilerplate
│   │   ├── predicates.go          # Alloy predicate & per-layer assertion generation
│   │   └── model.go               # Alloy signature and fact generation
│   ├── analyzer/
│   │   └── analyzer.go            # Alloy CLI runner & output parser
│   └── reporter/
│       └── reporter.go            # Human-readable output formatter (from Alloy results)
├── testdata/                      # Terraform fixtures and generated .als files
└── doc/
    ├── project-description.md     # This file
    └── architecture-and-tests.md  # Architecture decisions & test scenarios
```

---

## Key Design Decisions

1. **Static, pre-deployment reasoning**  —  The tool works directly on Terraform source and does not depend on live AWS credentials or deployed infrastructure.

2. **Alloy as the evaluation engine** — Alloy's relational model naturally maps to the multi-layered evaluation graph. All access decisions are produced by the Alloy model checker through formal verification, eliminating the need for a parallel Go-based evaluator.

2. **Per-triple analysis** — For each (principal, bucket, action) triple, the tool generates 8 Alloy assertions: one combined (`accessAllowed`) and one per evaluation layer (L1–L7). This allows the reporter to reconstruct which layer denied access purely from Alloy SAT/UNSAT results.
  
3. **Per-triple analysis** —  The tool generates checks per (principal, bucket, action) triple, which makes results concrete and testable.
  
4. **Per-layer diagnostics** —  The report distinguishes between blocking failures and missing grant paths rather than returning only a single ALLOW/DENY bit.

5. **PResource-aware S3 evaluation** — The tool models the correct resource types for each S3 action, such as bucket-level vs object-level actions, and correctly evaluates bucket policies that may apply only to certain actions or resources.

---

## What Is Already Implemented

The current implementation already supports the following ideas central to the project:

1. Terraform parsing and reference resolution, 
2. IR construction for interacting AWS resources, 
3. policy parsing into normalized statements, 
4. Alloy generation with configuration facts and access assertions,
5. per-action checks, 
6. explicit deny handling, 
7. bucket-level vs object-level resource matching, 
8. ABAC-style tag-sensitive resource-policy evaluation, 
9. human-readable reporting of per-layer results.

