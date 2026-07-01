# access-control-helper

Static analysis tool that answers **"can principal X perform action Z on bucket Y?"** directly from Terraform source code without deployment and AWS credentials.

**Pipeline:** `.tf` files → HCL parser → resolver → IR → Alloy spec → Alloy model checker → layer-aware report

The tool produces an `ALLOW` / `DENY` / `CONDITIONAL_ALLOW` verdict and identifies which AWS policy layer blocks or grants the request.

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

# Run full analysis (spec auto-saved to output/)
./access-control-helper <path/to/terraform>

# Run full analysis and write spec to specific file
./access-control-helper <path/to/terraform> output.als

# Print Alloy spec to stdout only (no Alloy run, no Java needed)
./access-control-helper <path/to/terraform> -
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

See [`tests/README.md`](tests/README.md) for commands, test structure, and scenario descriptions.

---

## Evaluation

| Track | What it measures |
|---|---|
| **Robustness** | Parse and analysis success rate on 62,406 real-world Terraform repos (TerraDS dataset) |
| **Scalability** | Alloy analysis time vs configuration size (benchmark + plots) |
| **Manual verification** | 12 scenarios deployed to real AWS — tool output vs `aws iam simulate-principal-policy` (100% match) |

See [`evaluation/README.md`](evaluation/README.md) for commands and results.

---

## Policy layers

| Layer | Policy type |
|---|---|
| L1 | Explicit Deny |
| L2 | Resource Control Policy (RCP) |
| L3 | Service Control Policy (SCP) |
| L4 | Resource-based policy |
| L5 | Identity-based policy |
| L6 | Permission Boundary |
| L7 | Session Policy |

Within the same account, L4 and L5 are a **union** — either one is sufficient to grant access.

### Layer status per verdict

Each layer in the report carries one of four statuses:

| Status | Applies to | Meaning |
|---|---|---|
| `PASS` | L1–L7 | Layer did not block; for L4/L5: a grant was found |
| `DENY` | L1, L2, L3, L6 | Layer explicitly blocked access |
| `NOT GRANTED` | L4, L5 | No applicable Allow statement found — including when no policy exists at this layer |
| `NOT APPLICABLE` | L7 | Session policy is a runtime parameter, not present in Terraform source |

---

## Documentation

| File | Contents |
|---|---|
| [`doc/project-description.md`](doc/project-description.md) | Architecture, design decisions, full capability list |
| [`doc/scope-and-limits.md`](doc/scope-and-limits.md) | What is and is not in scope |
| [`doc/tests-strategy.md`](doc/tests-strategy.md) | Testing approach and coverage rationale |
