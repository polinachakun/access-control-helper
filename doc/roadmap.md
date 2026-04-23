# Roadmap and Priority Plan

## Purpose of This Document

This document defines a practical roadmap for the next stages of the `access-control-helper` project.

Its purpose is to:

- identify the highest-priority next steps,
- prevent uncontrolled scope growth,
- clarify the minimum line that must be reached for a strong thesis,
- and define the stopping point beyond which adding more features is less valuable than strengthening evaluation and presentation.

The roadmap is written with the constraints of a **30-credit Master's thesis** in mind. The goal is therefore not to model the full AWS authorization engine, but to deliver a strong, validated, research-grade prototype with a clearly defined scope.

---

## Core Strategy

The project should not optimize for maximum feature count.

Instead, it should optimize for the following qualities:

- a clearly defined scope,
- strong correctness within that scope,
- convincing evaluation,
- and a precise limitations section.

In other words:

> a well-validated and clearly scoped subset is more valuable than a broad but unstable prototype.

This principle should guide all prioritization decisions.

---

## Priority Overview

The recommended order of work is:

1. **Stabilize the core engine**
2. **Freeze the supported semantic subset**
3. **Build the full testing infrastructure**
4. **Construct a strong evaluation suite**
5. **Add a small live AWS parity validation**
6. **Write the thesis around the validated system**

This order is intentional. New features should not be prioritized ahead of correctness, testability, and evaluation.

---

## Phase 1 — Stabilize the Core Engine

### Goal

Make the existing end-to-end pipeline fully trustworthy within the current supported subset.

### Why this comes first

Without a stable core, every later experiment, scenario, or evaluation result becomes questionable.

### Must-do tasks

- remove silent failure paths,
- ensure Alloy execution failures are surfaced as real errors,
- prevent the reporter from turning internal failures into fake policy decisions,
- ensure generator, analyzer, and reporter remain consistent,
- verify action/resource handling for simple and mixed S3 scenarios,
- eliminate cases where invalid Alloy still produces a misleading report.

### Deliverable of this phase

A stable and trustworthy pipeline:

`Terraform -> IR -> Alloy -> analyzer -> reporter`

This is a **mandatory phase**.

---

## Phase 2 — Freeze the Supported Semantic Subset

### Goal

Explicitly define what the thesis supports and what it does not support.

### Recommended supported scope

The supported scope should remain focused on:

- same-account access control,
- IAM roles as the primary principal type,
- S3 buckets and bucket policies,
- identity-based role permissions,
- explicit deny,
- resource-based and identity-based grant paths,
- permission boundaries,
- SCP / RCP,
- selected ABAC-style tag conditions,
- bucket-level vs object-level resource matching,
- and multi-statement correctness.

### What should not be promised at this stage

- full AWS authorization-engine semantics,
- full IAM language coverage,
- full Terraform language coverage,
- complete cross-account support,
- full Object Ownership / ACL / Access Point support,
- or all possible principal types.

### Deliverable of this phase

A frozen and thesis-ready statement of supported semantics and explicit scope boundaries.

This is also a **mandatory phase**.

---

## Phase 3 — Build the Real Testing Infrastructure

### Goal

Move from a few manually managed scenario tests to a scalable and rigorous test system.

### Must-do tasks

- restructure `tests/` around scenario folders,
- use `input.tf + expect.json + optional report.golden.txt`,
- implement automatic scenario discovery,
- generate `.als` files only in temporary directories,
- use structured expectations instead of relying only on report snapshots,
- validate Terraform fixtures with:
  - `terraform fmt -check`
  - `terraform init -backend=false`
  - `terraform validate`
- add focused package-level tests for parser, IR, generator, analyzer, and reporter.

### Deliverable of this phase

A robust, scalable test suite that supports both engineering validation and thesis evaluation.

This phase is **mandatory**.

---

## Phase 4 — Build a Strong Evaluation Suite

### Goal

Create a representative and defensible evaluation that demonstrates the correctness and value of the supported subset.

### Minimum recommended evaluation scope

At least **8–12 canonical scenarios**, covering categories such as:

- explicit deny overrides allow,
- identity-only allow,
- resource-only allow,
- no applicable grant path,
- ABAC no-match,
- ABAC explicit deny,
- permission-boundary restriction,
- SCP / RCP restriction,
- bucket-vs-object mismatch,
- and multi-statement correctness.

### What the evaluation must show

- expected access outcome,
- actual tool outcome,
- correctness of the layer explanation,
- and coverage of the main semantic categories in scope.

### Deliverable of this phase

A strong and structured evaluation chapter for the thesis.

This phase is **mandatory**.

---

## Phase 5 — Add a Small Live AWS Parity Validation

### Goal

Increase confidence that the implemented model matches real AWS behavior on representative cases.

### Scope recommendation

Keep this small and focused.

A realistic target is **3–5 canonical scenarios** deployed in a sandbox AWS account.

### Suggested steps

- deploy the Terraform fixture,
- assume the relevant role,
- issue real S3 API requests,
- compare the AWS result with the tool result.

### Why this matters

This does not need to be large in scale to be valuable.
Even a small live parity subset significantly strengthens the credibility of the evaluation.

### Deliverable of this phase

A limited but convincing parity validation against real AWS behavior.

This phase is **highly desirable**, but not strictly mandatory if time is limited.

---

## Phase 6 — Write the Thesis Around the Validated System

### Goal

Build the written thesis around the system that has actually been implemented and validated.

### Important principle

The writing should reflect the validated scope, not an aspirational future system.

### The thesis should clearly contain

- the problem statement,
- the research gap,
- the supported scope,
- the formal modeling approach,
- the implementation,
- the evaluation,
- the limitations,
- and the future-work boundary.

### Deliverable of this phase

A coherent thesis whose claims match the implemented and evaluated system.

This phase is **mandatory**.

---

## Minimum Line for a Strong Thesis

The project should be considered strong enough for a high-quality Master's thesis if it reaches the following minimum line:

1. a stable and trustworthy core pipeline,
2. a clearly frozen supported scope,
3. a scenario-based evaluation with roughly **8–10 strong representative cases**,
4. a scalable test infrastructure,
5. a clear limitations section,
6. and a compelling motivating example plus system-design explanation.

If this line is reached, the thesis can already be strong.

---

## Line for Maximum Grade Potential

The project reaches the strongest grade potential if, in addition to the minimum line, it also includes:

- a particularly rigorous and well-structured test suite,
- a well-explained supported subset,
- strong semantic scenario coverage,
- small but credible live AWS parity validation,
- and a clear explanation of why the chosen subset is meaningful despite not covering all AWS cases.

In practice, maximum grade potential will come more from:

- rigor,
- clarity,
- validation quality,
- and research framing,

than from a much broader feature set.

---

## What Should Not Be Prioritized

The following should **not** be prioritized unless all core phases are already complete and there is clearly remaining time:

- full IAM-user and session-principal semantics,
- full cross-account coverage,
- complete IAM condition-language support,
- ACL / Object Ownership / Access Point support,
- full S3 action coverage,
- full Terraform language support,
- or a large-scale live AWS benchmarking setup.

These are valid research directions, but they are not necessary for a strong 30-credit thesis.

---

## Practical Stopping Line

A clear stopping line is needed to avoid endless expansion.

The project should stop adding new feature areas once the following are all true:

- the core engine is stable,
- the supported subset is clearly defined,
- around 10 strong canonical scenarios are covered,
- the report is reliable and understandable,
- the testing infrastructure is in place,
- the limitations are clearly documented,
- and there is at least some external or strongly structured evidence that the modeled semantics are correct.

Once this line is reached, further effort should go into:

- polishing,
- evaluation,
- writing,
- figures,
- limitations,
- and argumentation.

Not into expanding the semantic scope.

---

## Recommended Short-Term Execution Order

A practical short-term order of work is:

### Priority 1

Stabilize the core:

- analyzer error handling,
- generator correctness,
- reporter consistency,
- no silent failure modes.

### Priority 2

Restructure and strengthen the test suite:

- scenario folders,
- `expect.json`,
- fixture validation,
- regression tests,
- package-level tests.

### Priority 3

Build the canonical evaluation set:

- 8–12 scenarios,
- clear semantic categories,
- expected vs actual results.

### Priority 4

Add a small live AWS parity subset:

- 3–5 canonical scenarios,
- real AWS result comparison.

### Priority 5

Freeze scope and finish the thesis write-up around the validated subset.

---

## Final Recommendation

The project is already large enough to support a strong 30-credit Master's thesis.

The main challenge is no longer to add as many features as possible.
The main challenge is to:

- stabilize what already exists,
- validate it rigorously,
- define the scope precisely,
- and present the result as a clear and well-justified research contribution.

The right strategy is therefore:

- **do not expand endlessly**,
- **finish the supported subset well**,
- **evaluate it strongly**,
- and **make the limits explicit**.

That is the path most likely to maximize the final thesis quality and grade.
