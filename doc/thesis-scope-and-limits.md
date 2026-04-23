# Thesis Scope, Current Coverage, and Limits

## Purpose of This Document

This document defines the intended scope of the thesis project, clarifies what is already implemented in the current prototype, identifies what is only partially covered, and explicitly states what should remain out of scope for a 30-credit Master's thesis.

Its purpose is to keep the project focused, prevent uncontrolled scope growth, and provide a clear boundary between:

- what the thesis already contributes,
- what still needs to be completed,
- and what should be positioned as future work rather than forced into the current implementation.

---

## Thesis Focus

The thesis does **not** aim to model the full AWS authorization engine.

Instead, it focuses on a **pre-deployment validation approach for a carefully selected subset of AWS S3 access control scenarios derived from Terraform configurations**.

The core research focus is:

- operating directly on Terraform source code before deployment,
- constructing a local semantic model of the relevant infrastructure,
- evaluating access-control behavior across multiple interacting resources,
- and using Alloy-based formal checking to determine whether a given access request is allowed or denied.

The intended contribution is therefore not “complete AWS coverage,” but a **validated formal prototype for an important and realistic subset of AWS S3 access control**.

---

## Recommended Thesis Claim

A suitable and realistic thesis claim is:

> This thesis develops a pre-deployment formal validation approach for a selected subset of AWS S3 access control scenarios defined in Terraform. The approach builds a local semantic model of relevant AWS resources and evaluates concrete access queries using Alloy-based formal verification.

This is a strong and defensible claim for a 30-credit Master's thesis.

---

## What Is Already Implemented

The current prototype already covers a substantial and meaningful subset of the target problem.

### End-to-End Pipeline

The project already implements the full analysis chain:

- Terraform parsing,
- reference and dependency resolution,
- intermediate representation (IR) construction,
- Alloy model generation,
- Alloy-based checking,
- and layer-aware report generation.

This is an important milestone because the project is already more than a concept or design sketch: it is a working end-to-end prototype.

### Terraform Resource Coverage

The current implementation already includes support for the key Terraform resources needed for the core S3 access-control use cases, including:

- `aws_s3_bucket`
- `aws_s3_bucket_policy`
- `aws_s3_bucket_public_access_block`
- `aws_iam_role`
- `aws_iam_role_policy`
- `aws_iam_role_policy_attachment`
- `aws_iam_user`
- `aws_iam_user_policy`
- `aws_iam_policy`
- `aws_organizations_policy`

### Policy Parsing and IR Support

The project already supports meaningful policy parsing capabilities, including:

- `Action`
- `NotAction`
- `Principal`
- `Condition`
- single-statement and multi-statement policies
- normalized bucket-policy statement handling

The IR is already capable of representing:

- S3 buckets,
- bucket policies,
- IAM roles,
- IAM policies,
- role policy attachments,
- organization policies,
- permission boundaries,
- and selected condition-related metadata.

### Access-Control Semantics Already Covered

The current implementation already supports several important semantic features:

- explicit deny handling,
- resource-based grant paths,
- identity-based grant paths,
- permission boundaries,
- SCP / RCP restrictions,
- selected ABAC-style tag matching,
- multi-statement bucket-policy handling,
- and bucket-level vs object-level S3 resource matching.

### Reporting and Diagnostics

The prototype already produces layer-aware reports for concrete `(principal, bucket, action)` queries.

This is important because the project does not only compute `ALLOW` / `DENY`, but also attempts to explain the result through policy-layer reasoning.

### Testing Direction

A testing strategy is already being defined around:

- scenario-based end-to-end tests,
- structured semantic expectations,
- reporter snapshot tests,
- and Terraform fixture validation.

This is already the right direction for thesis-quality validation.

---

## What Is Partially Covered

Some important concepts already exist in the prototype, but should currently be treated as **partial support**, not fully completed features.

### Cross-Account Access

Cross-account reasoning is present conceptually in the model, but it should not yet be treated as fully supported unless the full extraction and evaluation path is completed and validated.

At the moment, cross-account behavior is better described as:

- modeled in principle,
- partially represented in the formal model,
- but not yet mature enough to be claimed as fully supported.

### Session Policies

Session policies appear in the layered model, but their extraction and evaluation are not yet complete enough to be considered a finished capability.

This means the layer exists structurally, but the feature should still be treated as partial.

### IAM Users

IAM users are present in the parser and IR, but the project remains primarily **role-centric** in its current evaluation logic.

For that reason, user support should currently be described as partial rather than complete.

### Public Access Block Semantics

Bucket public-access-block data is represented in the model, but the effective impact of these settings on final access decisions is not yet fully integrated into the semantic evaluation.

So this should also be described as partially covered.

---

## What Is Not Yet Covered

If the goal were to cover all major AWS S3 access-control cases, the current prototype would still need significant extensions.

The following areas are not yet fully covered.

### Full Principal Model

The current prototype does not yet comprehensively distinguish all principal forms relevant to AWS access control, such as:

- IAM users,
- IAM roles,
- assumed-role sessions,
- federated sessions,
- service principals,
- account principals,
- and anonymous/public principals.

These distinctions matter because AWS does not treat all principal forms identically.

### Full IAM Policy Language

The current implementation does not yet cover the full IAM policy language. Important unsupported or incomplete areas include:

- `NotResource`
- `NotPrincipal`
- broader policy-variable handling
- the full range of AWS condition operators and modifiers
- nuanced missing-key semantics in conditions

This is a major area of possible future extension.

### Broader S3 Access-Control Surface

The current prototype focuses on the most central S3 policy interactions, but does not yet cover the wider S3 access-control ecosystem, including:

- Object Ownership behavior,
- ACL-related semantics,
- Access Points,
- Multi-Region Access Points,
- VPC endpoint policies as a separate policy source,
- and KMS-related access interactions.

### Full S3 Action Matrix

AWS S3 defines over 60 IAM actions across two resource levels:

**Object-level actions** (applied to `arn:aws:s3:::bucket/*`):
`s3:GetObject`, `s3:GetObjectAcl`, `s3:GetObjectVersion`, `s3:GetObjectVersionAcl`,
`s3:GetObjectTagging`, `s3:GetObjectVersionTagging`, `s3:PutObject`, `s3:PutObjectAcl`,
`s3:PutObjectTagging`, `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:DeleteObjectTagging`,
`s3:RestoreObject`, `s3:AbortMultipartUpload`, `s3:ListMultipartUploadParts`

**Bucket-level actions** (applied to `arn:aws:s3:::bucket`):
`s3:ListBucket`, `s3:ListBucketVersions`, `s3:ListBucketMultipartUploads`,
`s3:CreateBucket`, `s3:DeleteBucket`, `s3:GetBucketPolicy`, `s3:PutBucketPolicy`,
`s3:DeleteBucketPolicy`, `s3:GetBucketAcl`, `s3:PutBucketAcl`,
`s3:GetBucketVersioning`, `s3:PutBucketVersioning`, `s3:GetBucketTagging`,
`s3:PutBucketTagging`, `s3:GetEncryptionConfiguration`, `s3:PutEncryptionConfiguration`,
`s3:GetBucketPublicAccessBlock`, `s3:PutBucketPublicAccessBlock`,
`s3:GetBucketLogging`, `s3:PutBucketLogging`, `s3:GetBucketNotification`,
`s3:PutBucketNotification`

The current prototype models **4 actions**:

| Action | Resource level | Represents |
|---|---|---|
| `s3:GetObject` | object | read access |
| `s3:PutObject` | object | write access |
| `s3:DeleteObject` | object | delete access |
| `s3:ListBucket` | bucket | list access |

These four were chosen because they cover all four fundamental access patterns (read, write, delete, list) and exercise all 7 policy evaluation layers in distinct ways. They are sufficient to validate the core thesis contribution — multi-layer, multi-resource formal access-control reasoning — without requiring a complete action catalog.

A complete S3 access-control analyzer would require a broader and systematically maintained matrix of:

- all S3 actions,
- required resource types per action,
- action/resource compatibility rules,
- and possibly dependent permissions (e.g. `s3:GetObject` implicitly needed for `s3:CopyObject`).

Extending the action catalog beyond the current 4 is listed as future work.

### Full Terraform Language Support

The parser and resolver are already useful for the selected problem scope, but the prototype does not yet attempt to support the full expressiveness of Terraform.

Significant uncovered Terraform areas include:

- modules,
- variables,
- locals,
- `for_each`,
- `count`,
- dynamic blocks,
- conditionals,
- more advanced function usage,
- and data-source-driven configurations.

A full treatment of Terraform semantics would be a substantial project on its own.

---

## Recommended Scope Boundary for a 30-Credit Master's Thesis

For a 30-credit thesis, the project should **not** attempt to cover the full AWS authorization engine or the full Terraform language.

A realistic and strong thesis scope is:

- same-account access control,
- IAM roles as the primary principal type,
- S3 buckets and bucket policies,
- identity-based role permissions,
- explicit deny handling,
- resource-based and identity-based grant paths,
- permission boundaries,
- SCP / RCP,
- selected ABAC-style tag-based conditions,
- bucket-level vs object-level resource matching,
- multi-statement correctness,
- and a diagnostic report explaining the result.

This is already a meaningful and nontrivial contribution.

If implemented well and evaluated rigorously, this is fully appropriate for a 30-credit Master's thesis.

---

## What Should Be Completed Before Thesis Submission

The remaining work should focus on **correctness, clarity, and validation**, not on uncontrolled feature expansion.

### 1. Strengthen Correctness

The current subset should be made as robust as possible.

This includes:

- removing silent failure paths,
- ensuring Alloy failures are surfaced correctly,
- strengthening scenario-based regression tests,
- and ensuring that the implemented semantics remain consistent across representative cases.

### 2. Clearly Freeze Supported Scope

The thesis should explicitly define what is supported.

This includes a clear statement that the project currently focuses on:

- same-account S3 access control,
- role-centric evaluation,
- selected IAM / S3 semantics,
- and selected Terraform resource patterns.

### 3. Build a Strong Evaluation

The evaluation should demonstrate that the supported subset works well.

A strong evaluation for this thesis would include:

- a structured suite of representative scenarios,
- explanation of scenario categories,
- correctness validation of expected access decisions,
- and ideally a small live AWS parity validation for a limited set of canonical cases.

### 4. Document Limitations Clearly

The thesis should contain an explicit limitations section describing what is not yet covered.

This is not a weakness. It is necessary for a precise and credible research contribution.

---

## What Should Be Treated as Future Work

The following areas are suitable future-work items and should not be forced into the thesis unless time clearly permits:

- full cross-account support,
- complete IAM-user and session-principal semantics,
- full condition-operator coverage,
- Object Ownership and ACL semantics,
- Access Points and broader S3 policy surfaces,
- broader S3 action coverage,
- and deeper Terraform-language support.

These are valuable directions, but they should not distract from finishing a strong and well-evaluated core contribution.

---

## Practical Research Positioning

The thesis should therefore be positioned as:

- a **formal prototype**,
- for **pre-deployment validation**,
- of a **selected subset of AWS S3 access control**,
- derived directly from **Terraform configurations**,
- with emphasis on **multi-resource reasoning** and **layer-aware diagnostics**.

This is already a substantial and convincing Master's-level contribution.

---

## Summary

The current project already contains enough implemented substance for a strong 30-credit Master's thesis.

The key is not to cover “all AWS cases,” but to:

- define a clear semantic boundary,
- complete the current subset carefully,
- validate it rigorously,
- and present unsupported areas honestly as future work.

The correct thesis strategy is therefore:

- **do not expand endlessly**,
- **stabilize the supported subset**,
- **evaluate it well**,
- and **make the scope explicit**.

That is the right balance between research ambition, engineering realism, and the expected scope of a Master's thesis.

