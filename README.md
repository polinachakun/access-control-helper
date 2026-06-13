# access-control-helper

Static analysis tool that answers **"can principal X perform action Z on bucket Y?"** directly from Terraform source code without deployment and AWS credentials.

**Pipeline:** `.tf` files → HCL parser → resolver → IR → Alloy spec → Alloy model checker → layer-aware report

The tool produces an `ALLOW` / `DENY` verdict and identifies which AWS policy layer blocks or grants the request.

---

## Requirements

| Dependency | Version |
|---|---|
| Go | 1.21+ |
| Java | 11+ |
| Alloy JAR | `tools/org.alloytools.alloy.dist.jar` |

---

## Usage

```bash
# Build
go build -o access-control-helper .

# Print Alloy spec to stdout (no Alloy run)
./access-control-helper <path/to/terraform>

# Run full analysis and write spec to file
./access-control-helper <path/to/terraform> output.als
```

---

## Project structure

```
access-control-helper/
├── main.go / run.go           CLI entry point and pipeline execution
├── internal/
│   ├── parser/                HCL parser for 10 resource types
│   ├── resolver/              Cross-reference resolver, ARN interpolation
│   ├── ir/                    Internal representation: types, policy, builder
│   ├── generator/             IR → Alloy spec generation
│   ├── analyzer/              Alloy CLI runner and output parser
│   └── reporter/              Human-readable report formatter
├── tests/                     E2e scenarios, unit tests, snapshots  →  tests/README.md
├── evaluation/                Robustness, scalability, manual verification  →  evaluation/README.md
├── tools/                     Alloy JAR
└── doc/                       Architecture and design notes
```

---

## Tests

```bash
# All e2e + snapshot tests (no Alloy JAR needed for generation checks)
go test ./tests/

# Unit tests only
go test ./tests/unit/

# Full pipeline with Alloy verification (requires JAR)
go test ./tests/ -run TestScenarios_Verification

# Specific scenario
go test ./tests/ -run TestScenarios_Verification/identity_allow_only

# Regenerate expect.json after intentionally changing a scenario
go test ./tests/ -update -run TestScenarios_Verification/identity_allow_only
```

See [`tests/README.md`](tests/README.md) for test structure and scenario descriptions.

---

## Evaluation

Three evaluation tracks in [`evaluation/`](evaluation/README.md):

| Track | What it measures |
|---|---|
| **Robustness** | Parse and analysis success rate on 62,406 real-world Terraform repos (TerraDS dataset) |
| **Scalability** | Alloy analysis time vs configuration size (benchmark + plots) |
| **Manual verification** | 12 scenarios deployed to real AWS — tool output vs `aws iam simulate-principal-policy` (100% match) |

```bash
# Quick start: dataset coverage (no tarballs needed)
python3 evaluation/robustness/evaluate.py phase1

# Full pipeline sample
python3 evaluation/robustness/evaluate.py phase3 --sample 100
```

See [`evaluation/README.md`](evaluation/README.md) for full commands and results.

---

## Policy layers

| Layer | Policy type | Effect when absent |
|---|---|---|
| L1 | Explicit Deny | — |
| L2 | Resource Control Policy (RCP) | DENY |
| L3 | Service Control Policy (SCP) | DENY |
| L4 | Resource-based policy | DENY (cross-account only) |
| L5 | Identity-based policy | DENY |
| L6 | Permission Boundary | DENY |
| L7 | Session Policy | NOT APPLICABLE (runtime only) |

Within same account, L4 and L5 are a **union**.

---

## Documentation

| File | Contents |
|---|---|
| [`doc/project-description.md`](doc/project-description.md) | Architecture, design decisions, full capability list |
| [`doc/scope-and-limits.md`](doc/scope-and-limits.md) | What is and is not in scope |
| [`doc/tests-strategy.md`](doc/tests-strategy.md) | Testing approach and coverage rationale |
