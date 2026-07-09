# Evaluation

```
evaluation/
├── robustness/                  TerraDS dataset evaluation
│   ├── evaluate.py              Dataset evaluation script (phases 1–3)
│   ├── plot_funnel.py           Funnel plot: dataset → analyzed modules
│   └── results/                 Phase result files + generated plots
├── scalability/                 Performance scaling benchmark
│   ├── benchmark_test.go        Go benchmark: varies principals / buckets / actions
│   ├── plot.py                  Generates plots from CSV results
│   └── results/                 CSV data + generated plots
└── manual_verification/         Real AWS scenarios — correctness validation
    └── screenshots/             Evidence: tool output vs AWS console, 100% match
```

---

## Robustness (`robustness/`)

Runs the tool against real-world Terraform repos from the TerraDS corpus (62,406 repos).

**Prerequisites:** Python 3.9+, standard library only. Java + Alloy JAR required for Phase 3.

**Dataset:** [TerraDS v1 on Zenodo](https://zenodo.org/records/14217386)

```bash
# Download and extract to ~/TerraDS/ (persistent, not /tmp)
mkdir -p ~/TerraDS
wget https://zenodo.org/records/14217386/files/14217386.zip
unzip 14217386.zip TerraDS.sqlite -d ~/TerraDS/
unzip 14217386.zip TerraDS.tar.gz -d ~/TerraDS/
```

The script looks for files in `~/TerraDS/` by default. Override with:
```bash
export TERRADS_DIR=/path/to/your/terrads
```

### Commands

```bash
make build

# Phase 1 — characterise the dataset (SQLite only, ~5s, no extraction)
python3 evaluation/robustness/evaluate.py phase1

# Phase 2 — spec-generation success on a random sample (no Alloy needed)
python3 evaluation/robustness/evaluate.py phase2 --sample 100 --out evaluation/robustness/results/phase2_results.json

# Phase 3 — full Alloy analysis, random sample (seed=42)
python3 evaluation/robustness/evaluate.py phase3 --sample 100 --out evaluation/robustness/results/phase3_final.json

# Phase 3 — full Alloy analysis, top-100 most recently updated repos
python3 evaluation/robustness/evaluate.py phase3 --sample 100 --strategy recent --out evaluation/robustness/results/phase3_recent100.json

# All phases in sequence
python3 evaluation/robustness/evaluate.py all --sample 100 --sample3 100
```

All phases use `random.seed(42)` — results are deterministic.

### Results

```
evaluation/robustness/results/
├── phase2_results.json          Parse/spec-gen outcomes, n=100, seed=42
├── phase3_final.json            Full Alloy outcomes, n=100, random seed=42
├── phase3_recent100.json        Full Alloy outcomes, n=100, top-100 by recency
├── phase3_clean.json            Older n=30 run — includes per-module decisions
├── phase2_pilot.json            Early pilot n=20, kept for reference
├── plot_funnel.png              Generated funnel plot
├── baseline_random_seed42/      Archived baseline run
└── recent_top100/               Archived top-100 run
```

The `.als` files generated during Phase 3 are gitignored — intermediate artifacts.

### Funnel plot

Shows how many modules remain at each pipeline stage — from the full TerraDS corpus down to successfully Alloy-analyzed configurations.

```bash
python3 evaluation/robustness/plot_funnel.py

# Custom output path
python3 evaluation/robustness/plot_funnel.py --out evaluation/robustness/results/plot_funnel.png
```

**Dependencies:** `matplotlib`, `numpy`
```bash
pip install matplotlib numpy
```

### Real-world module complexity

Per-module counts extracted from the Phase 2/3 result logs (`stderr_snippet` / `decisions` fields) show that real TerraDS modules are small:

| Metric | Min | Median | Mean | Max |
|--------|-----|--------|------|-----|
| Buckets/module | 1 | 1 | 1.16 | 3 |
| Principals/module | 1 | 1 | 1.3–1.4 | 5 |
| Actions/module | 4 | 4 | 4.9 | 11 |
| Alloy checks/module | 32 | 48 | 60.2 | 168 |

(Buckets/principals from `phase2_results.json`, n=50; principals/actions/decisions from `phase3_clean.json`, n=27 modules with recorded decisions.)

Median end-to-end analysis time was **6.7s** (random 100-module sample) and **23.9s** (recent-100 sample), max 85.8s — well under the 217s worst case from the scalability benchmark below. That worst case (6 principals × 5 buckets × 2 actions) is a synthetic stress configuration, not representative of real-world module size.

---

## Scalability (`scalability/`)

Measures how Alloy analysis time scales with configuration size using synthetic Terraform configs.

### Commands

```bash
# Run benchmark (saves CSV with current date in filename)
go test ./evaluation/scalability/ -v -timeout 30m -tags scalability

# Run only one benchmark
go test ./evaluation/scalability/ -v -timeout 30m -tags scalability -run TestScalabilityTriples

# Generate plots from the newest CSVs in results/
python3 evaluation/scalability/plot.py --latest

# Or specify CSV files explicitly
python3 evaluation/scalability/plot.py \
  evaluation/scalability/results/triples_<date>.csv \
  evaluation/scalability/results/dimensions_<date>.csv
```

Plots are saved to `evaluation/scalability/results/`: `plot_triples.png`, `plot_dimensions.png`, `plot_heatmap.png`, `plot_overview.png`.

**Dependencies:** `matplotlib`, `numpy`, `pandas`, `scipy`
```bash
pip install matplotlib numpy pandas scipy
```

---

## Manual verification (`manual_verification/`)

12 Terraform scenarios deployed to real AWS and verified against `aws iam simulate-principal-policy`. Every ALLOW/DENY decision produced by the tool matched the actual AWS IAM result — **100% correctness across all scenarios**. Screenshots in `manual_verification/screenshots/`.

### Prerequisites

- Terraform ≥ 1.5
- AWS credentials with IAM + S3 (+ Organizations for SCP/RCP scenarios) access
- `aws` CLI configured for the target account

### Commands

```bash
# Deploy scenario and print validation commands
./evaluation/manual_verification/validate_all.sh 01

# With a custom suffix to avoid name conflicts
./evaluation/manual_verification/validate_all.sh 04 mytest123

# SCP/RCP scenarios require an OU or account target ID
./evaluation/manual_verification/validate_all.sh 04 mytest123 ou-ab12-xxxxxxxx

# Clean up after validation
cd evaluation/manual_verification/01_identity_allow_only && terraform destroy -var=suffix=<same-suffix>
```

### Scenarios

| # | Folder | What it tests |
|---|--------|--------------|
| 01 | `01_identity_allow_only` | Identity policy alone is sufficient to grant access |
| 02 | `02_explicit_deny_wins` | Explicit Deny in bucket policy overrides a broad identity Allow |
| 03 | `03_permission_boundary_blocks` | Permission boundary narrows effective permissions below what identity policy grants |
| 04 | `04_scp_blocks_allow` | SCP at org level blocks an action even when identity policy allows it |
| 05 | `05_rcp_blocks_allow` | RCP on the resource side blocks an action even when identity policy allows it |
| 06 | `06_scp_restricts_account_wide` | SCP applies account-wide — restricts all roles including admin |
| 07 | `07_service_principal_allow` | Bucket policy grants access to a service principal (`lambda.amazonaws.com`) |
| 08 | `08_vpce_and_abac_deny` | Bucket policy denies access unless request comes via VPC endpoint and matches tag condition |
| 08b | `08b_abac_tag_mismatch` | ABAC condition present but principal tag does not match bucket tag — access denied |
| 08c | `08с_abac_tag_match` | ABAC condition present and principal tag matches bucket tag — access allowed |
| 09 | `09_scp_and_boundary_combined` | SCP and permission boundary restrict independently — both must pass |
| 10 | `10_notaction_identity` | `NotAction` in identity policy implicitly denies the excluded action |
