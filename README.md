# access-control-helper

Static analysis tool for validating AWS S3 access control from Terraform source code.

**Pipeline:** `.tf` files → parser → resolver → IR → Alloy spec → Alloy model checker → report

---

## Requirements

- Go 1.21+
- Java 11+ (for Alloy verification)
- `tools/org.alloytools.alloy.dist.jar` (Alloy JAR)

---

## Usage

```bash
# Build
go build -o access-control-helper .

# Print Alloy spec to stdout (no Alloy run)
./access-control-helper <path/to/terraform>

# Run full analysis and write spec
./access-control-helper <path/to/terraform> output.als
```

---

## Tests

### Run all tests

```bash
go test ./tests/
```

- `TestScenarios_Generation` — always runs, no Alloy JAR needed. Verifies parse → IR → spec generation succeeds for every scenario.
- `TestScenarios_Verification` — requires Alloy JAR. Runs full pipeline and compares against `expect.json`. Skips automatically if JAR is absent.

```bash
go test ./tests/unit/    # unit tests (no Alloy needed)
```

### Run a specific scenario

```bash
go test ./tests/ -run TestScenarios_Verification/identity_allow_only
```

### Regenerate expect.json after changing a scenario

```bash
go test ./tests/ -update -run TestScenarios_Verification/identity_allow_only
```

> Use `-update` only when you intentionally changed expected behavior.

---

## Scenarios

Each scenario lives in `tests/scenarios/<name>/` and contains two files:

```
tests/scenarios/my_scenario/
├── input.tf       # Terraform config to analyze
└── expect.json    # expected decisions per (principal, bucket, action)
```

### expect.json structure

```json
{
  "schema_version": 1,
  "name": "my_scenario",
  "queries": [
    {
      "principal": "app-role",
      "bucket": "my-bucket",
      "action": "S3_GetObject",
      "decision": "ALLOW",
      "denied_at": null,
      "layers": {
        "L1": "PASS",
        "L2": "PASS",
        "L3": "PASS",
        "L4": "PASS",
        "L5": "PASS",
        "L6": "PASS",
        "L7": "NOT APPLICABLE"
      }
    }
  ]
}
```

**`decision`**: `ALLOW` or `DENY`

**`denied_at`**: `"Layer 5"` (or null for ALLOW)

**Layer meanings:**

| Layer | Policy type               | Possible values                          |
|-------|---------------------------|------------------------------------------|
| L1    | Explicit Deny             | `PASS`, `DENIED`                         |
| L2    | Resource Control Policy   | `PASS`, `DENIED`                         |
| L3    | Service Control Policy    | `PASS`, `DENIED`                         |
| L4    | Resource Policy           | `PASS`, `NOT GRANTED`                    |
| L5    | Identity Policy           | `PASS`, `NOT GRANTED`                    |
| L6    | Permission Boundary       | `PASS`, `NOT GRANTED`                    |
| L7    | Session Policy            | `PASS`, `NOT GRANTED`, `NOT APPLICABLE`  |

### How to add a new scenario

1. Create `tests/scenarios/<name>/input.tf` with a Terraform config.
2. Run with `-update` to auto-generate `expect.json`:
   ```bash
   go test ./tests/ -update -run TestScenarios_Verification/<name>
   ```
3. Review the generated `expect.json` — verify the decisions are correct.
4. Commit both files.

---

## Dataset Evaluation

Evaluation against the [TerraDS](https://zenodo.org/record/7694141) dataset (62,406 real-world Terraform repos).

**Requirements:** Python 3.9+, SQLite DB and tarballs extracted from the dataset zip.

```bash
# Dataset paths (configure at top of eval/evaluate.py)
DB_PATH   = /tmp/TerraDS.sqlite
TERRADS_TAR = /tmp/TerraDS.tar.gz
```

### Phases

| Phase | What it does | Requires |
|-------|-------------|----------|
| `phase1` | Coverage: how many real configs fall within the tool's scope | SQLite only |
| `phase2` | Parse success: tool runs without crashing (no Alloy) | SQLite + tarballs |
| `phase3` | Full Alloy analysis: end-to-end success rate | SQLite + tarballs + Alloy JAR |
| `summary` | Aggregates key metrics and percentages from all phases | Existing phase JSON files |

```bash
python3 eval/evaluate.py phase1
python3 eval/evaluate.py phase2 --sample 100
python3 eval/evaluate.py phase3 --sample 100
python3 eval/evaluate.py summary   # no DB needed
```

### Module selection strategy

Phase 2 and 3 support three ways to pick modules from the in-scope population:

| Flag | Behaviour | When to use |
|------|-----------|-------------|
| `--strategy random` | Deterministic shuffle (seed=42) — **default** | Reproducible baseline; same seed = same modules every run |
| `--strategy stars` | Top-N by GitHub star count (most popular repos first) | Representative sample of widely-used configs |
| `--strategy recent` | Top-N by latest commit date (most recently updated repos first) | Sample of actively maintained configs |

```bash
# Random sample of 100 (default, reproducible)
python3 eval/evaluate.py phase2 --sample 100

# Top 100 most popular repos by stars
python3 eval/evaluate.py phase2 --sample 100 --strategy stars

# Top 100 most recently updated repos
python3 eval/evaluate.py phase2 --sample 100 --strategy recent
```

> The thesis evaluation uses `--strategy stars --sample 100` as the primary run and `--strategy random --sample 100` (seed=42) as the reproducibility baseline.

### Results

Phase results are saved to `eval/results/`:

| File | Contents |
|------|----------|
| `phase1_results.json` | Scope coverage counts and percentages |
| `phase2_results.json` | Parse/IR outcomes per module |
| `phase3_results.json` | Alloy analysis outcomes per module |
| `eval_summary.json` | All key metrics in one place |

### Reading eval_summary.json

```json
{
  "phase1_coverage": {
    "candidate_modules": 5514,
    "in_scope_count": 1051,
    "in_scope_pct": 19.1
  },
  "phase2_parse": {
    "outcomes_pct": { "success": 78.0, "timeout": 12.0, ... }
  },
  "phase3_alloy": {
    "outcomes_pct": { "success": 82.0, "alloy_error": 9.0, ... },
    "total_triples_analyzed": 752,
    "mean_alloy_time_s": 13.1
  }
}
```

**`in_scope_pct`** — share of S3+IAM modules that contain only resource types the tool supports.

**`phase3_alloy.outcomes_pct.success`** — share of in-scope modules where the tool completed full Alloy analysis without error.

When using `--strategy random`, the sample is deterministic (seed=42): phase2 and phase3 always pick the same modules, making results reproducible.

---

## Manual Verification (AWS deploy)

Real Terraform configs for deploying each scenario to AWS and validating decisions with `aws iam simulate-principal-policy`. See [`deploy/README.md`](deploy/README.md) for details.

```bash
# Policy Simulator scenarios (L1/L4/L5/L6)
./deploy/validate_all.sh 01 mysuffix

# SCP/RCP scenarios (L2/L3) — requires AWS Organizations
./deploy/validate_all.sh 04 mysuffix <account-id-or-ou-id>
```

---

## Scalability Tests

```bash
# Run scalability benchmark (can take up to 2h)
go test ./eval/scalability/ -v -timeout 2h -run TestScalabilityTriples

# Plot results
cd eval/scalability && python3 plot.py --latest
```
