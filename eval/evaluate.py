#!/usr/bin/env python3
"""
Evaluation of access-control-helper against the TerraDS dataset.

Phases:
  phase1   Dataset characterisation (SQLite only, fast)
  phase2   Parse/IR success on extracted in-scope sample
  phase3   Full Alloy analysis on a subset of phase2 successes

Usage:
  python3 evaluate.py phase1
  python3 evaluate.py phase2 [--sample N] [--out results.json]
  python3 evaluate.py phase3 [--sample N] [--out results.json]
  python3 evaluate.py all

Paths are configured at the top of this file.
"""

import argparse
import json
import os
import random
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import defaultdict
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

DB_PATH = "/tmp/TerraDS.sqlite"
TERRADS_TAR = "/tmp/TerraDS.tar.gz"
TOOL_BINARY = str(Path(__file__).parent.parent / "access-control-helper")
RESULTS_DIR = Path(__file__).parent / "results"

SUPPORTED_MANAGED = {
    "aws_s3_bucket",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_public_access_block",
    "aws_iam_role",
    "aws_iam_role_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user",
    "aws_iam_user_policy",
    "aws_iam_policy",
    "aws_organizations_policy",
}

SECURITY_PREFIXES = (
    "aws_iam_",
    "aws_s3_",
    "aws_organizations_",
    "aws_ssoadmin_",
    "aws_identitystore_",
)

RANDOM_SEED = 42

# ── Database helpers ───────────────────────────────────────────────────────────


def open_db():
    if not os.path.exists(DB_PATH):
        sys.exit(f"SQLite DB not found at {DB_PATH}.\nExtract TerraDS.sqlite from the dataset zip first.")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_candidate_modules(conn):
    """Return {module_id: (repo_id, module_path)} for modules with S3 + IAM principal."""
    cur = conn.cursor()

    cur.execute(
        "SELECT DISTINCT ModuleId FROM Resources "
        "WHERE Type = 'aws_s3_bucket' AND ResourceType = 'Managed'"
    )
    s3_mods = {r[0] for r in cur.fetchall()}

    cur.execute(
        "SELECT DISTINCT ModuleId FROM Resources "
        "WHERE Type IN ('aws_iam_role','aws_iam_user') AND ResourceType = 'Managed'"
    )
    iam_mods = {r[0] for r in cur.fetchall()}

    candidates = s3_mods & iam_mods

    cur.execute(
        "SELECT m.Id, m.RepositoryId, m.Path FROM Modules m WHERE m.Id IN ({})".format(
            ",".join("?" * len(candidates))
        ),
        list(candidates),
    )
    return {r["Id"]: (r["RepositoryId"], r["Path"]) for r in cur.fetchall()}


def classify_modules(conn, candidates):
    """Split candidates into fully-in-scope vs has-gap dicts."""
    cur = conn.cursor()
    ids = list(candidates.keys())
    cur.execute(
        "SELECT ModuleId, Type FROM Resources "
        "WHERE ModuleId IN ({}) AND ResourceType = 'Managed' "
        "AND ({})".format(
            ",".join("?" * len(ids)),
            " OR ".join(f"Type LIKE '{p}%'" for p in SECURITY_PREFIXES),
        ),
        ids,
    )

    module_sec_types = defaultdict(set)
    for row in cur.fetchall():
        module_sec_types[row["ModuleId"]].add(row["Type"])

    in_scope = {}
    has_gap = {}
    for mid, (repo_id, path) in candidates.items():
        types = module_sec_types.get(mid, set())
        if types.issubset(SUPPORTED_MANAGED):
            in_scope[mid] = (repo_id, path, types)
        else:
            unsupported = types - SUPPORTED_MANAGED
            has_gap[mid] = (repo_id, path, types, unsupported)

    return in_scope, has_gap


# ── Phase 1 ───────────────────────────────────────────────────────────────────


def phase1(conn):
    print("=" * 70)
    print("PHASE 1 — Dataset Characterisation")
    print("=" * 70)

    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM Repositories")
    print(f"\nTotal repositories in TerraDS:  {cur.fetchone()[0]:,}")

    cur.execute("SELECT COUNT(*) FROM Modules")
    print(f"Total Terraform modules:         {cur.fetchone()[0]:,}")

    cur.execute("SELECT COUNT(*) FROM Resources")
    print(f"Total resource declarations:     {cur.fetchone()[0]:,}")

    cur.execute("SELECT COUNT(DISTINCT ModuleId) FROM Resources WHERE Type = 'aws_s3_bucket'")
    s3_mod_count = cur.fetchone()[0]
    print(f"\nModules with aws_s3_bucket:      {s3_mod_count:,}")

    candidates = get_candidate_modules(conn)
    print(f"Modules with S3 + IAM principal: {len(candidates):,}  ← evaluation population")

    in_scope, has_gap = classify_modules(conn, candidates)
    total = len(candidates)
    print(f"\n  Fully within supported scope:  {len(in_scope):,}  ({100*len(in_scope)/total:.1f}%)")
    print(f"  Have unsupported sec. types:   {len(has_gap):,}  ({100*len(has_gap)/total:.1f}%)")

    # Gap breakdown
    gap_type_counts = defaultdict(int)
    for _, _, _, unsupported in has_gap.values():
        for t in unsupported:
            gap_type_counts[t] += 1

    print("\nTop unsupported managed resource types causing coverage gaps:")
    print(f"  {'Resource type':<50} {'Modules':>8}  {'%':>6}")
    print(f"  {'-'*50} {'-'*8}  {'-'*6}")
    for t, cnt in sorted(gap_type_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"  {t:<50} {cnt:>8,}  {100*cnt/total:>5.1f}%")

    # Distribution of supported types in in-scope modules
    print(f"\nResource type distribution within in-scope modules ({len(in_scope):,}):")
    type_in_scope = defaultdict(int)
    for _, _, types in in_scope.values():
        for t in types:
            type_in_scope[t] += 1
    for t, cnt in sorted(type_in_scope.items(), key=lambda x: -x[1]):
        print(f"  {t:<50} {cnt:>6,}  ({100*cnt/len(in_scope):.0f}% of modules)")

    print()
    return in_scope, has_gap


# ── Tarball extraction ─────────────────────────────────────────────────────────


def autoformat_dir(dir_path):
    """Run terraform fmt on extracted files. Returns True if terraform is available."""
    tf_path = shutil.which("terraform")
    if not tf_path:
        return False
    subprocess.run([tf_path, "fmt", "-recursive", dir_path],
                   capture_output=True, timeout=15)
    return True


def extract_module(repo_id, module_path, dest_dir):
    """
    Extract one module's .tf files from the nested TerraDS tarball structure.
    Returns True on success, False if the repo archive is missing.
    """
    member_name = f"TerraDS/{repo_id}.tar.gz"
    try:
        outer = tarfile.open(TERRADS_TAR, "r:gz")
    except FileNotFoundError:
        sys.exit(f"TerraDS tar not found at {TERRADS_TAR}.\nExtract TerraDS.tar.gz from the dataset zip first.")

    try:
        member = outer.getmember(member_name)
    except KeyError:
        return False

    inner_fh = outer.extractfile(member)
    if inner_fh is None:
        return False

    inner = tarfile.open(fileobj=inner_fh, mode="r:gz")

    # Inner tars use "{repo_id}/{module_path}/file.tf" layout.
    repo_prefix = f"{repo_id}/"
    if module_path == ".":
        # All .tf files directly under the repo root (one level deep)
        match_prefix = repo_prefix
    else:
        match_prefix = f"{repo_prefix}{module_path.rstrip('/')}/"

    extracted_any = False
    for m in inner.getmembers():
        name = m.name
        if not name.startswith(match_prefix):
            continue
        if not name.endswith(".tf"):
            continue
        # Keep only direct children (no nested sub-directories from other modules)
        rel = name[len(match_prefix):]
        if "/" in rel:
            continue
        m.name = rel
        try:
            inner.extract(m, dest_dir, filter="data")
        except TypeError:
            inner.extract(m, dest_dir)  # Python < 3.12
        extracted_any = True

    inner.close()
    outer.close()
    return extracted_any


# ── Tool runner ───────────────────────────────────────────────────────────────


def run_tool_parse(input_path, timeout=30):
    """
    Run the tool in stdout mode (no Alloy). Returns (outcome, stderr, elapsed_s).
    outcome: 'success' | 'no_triples' | 'hcl_error' | 'ir_error' | 'resolve_error' | 'timeout'
    """
    start = time.monotonic()
    try:
        result = subprocess.run(
            [TOOL_BINARY, input_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "timeout", "", time.monotonic() - start
    elapsed = time.monotonic() - start

    stderr = result.stderr.strip()

    if result.returncode != 0:
        if "error: parse:" in stderr or "HCL syntax" in stderr:
            return "hcl_error", stderr, elapsed
        if "error: resolve:" in stderr:
            return "resolve_error", stderr, elapsed
        if "error: IR build:" in stderr:
            return "ir_error", stderr, elapsed
        return "ir_error", stderr, elapsed

    stdout = result.stdout.strip()
    if not stdout:
        return "no_triples", stderr, elapsed

    return "success", stderr, elapsed


def run_tool_alloy(input_path, output_path, timeout=120):
    """
    Run the full pipeline including Alloy.
    Returns (outcome, report_or_error_text, elapsed_s).
    outcome: 'success' | 'no_triples' | 'no_supported_s3_statements'
             | 'fmt_fail' | 'hcl_error' | 'ir_error' | 'alloy_error' | 'timeout'

    no_supported_s3_statements: config has S3 buckets and IAM principals but attached
        policies contain only non-S3 actions (e.g. EC2, CloudWatch). Not an error.
    """
    start = time.monotonic()
    try:
        result = subprocess.run(
            [TOOL_BINARY, input_path, output_path],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return "timeout", "", time.monotonic() - start
    elapsed = time.monotonic() - start

    stderr = result.stderr.strip()
    stdout = result.stdout.strip()

    if result.returncode != 0:
        if "HCL syntax check failed" in stderr or "terraform fmt" in stderr:
            return "fmt_fail", stderr, elapsed
        if "error: parse:" in stderr:
            return "hcl_error", stderr, elapsed
        if "error: IR build:" in stderr or "error: resolve:" in stderr:
            return "ir_error", stderr, elapsed
        return "alloy_error", stderr, elapsed

    if "STATUS: no_supported_s3_statements" in stdout:
        return "no_supported_s3_statements", stdout, elapsed

    return "success", stdout, elapsed


def parse_decisions(report_text):
    """
    Extract (principal, action, bucket, decision) from the human-readable report.
    Returns list of dicts.
    """
    decisions = []
    lines = report_text.splitlines()
    current = {}
    for line in lines:
        line = line.strip()
        if line.startswith("Query: can "):
            # "Query: can "app_role" perform GetObject on "my_bucket"?"
            current = {}
            try:
                parts = line[len("Query: can "):].rstrip("?")
                principal, rest = parts.split('" perform ', 1)
                current["principal"] = principal.strip('"')
                action, rest = rest.split(' on "', 1)
                current["action"] = action.strip()
                current["bucket"] = rest.rstrip('"')
            except ValueError:
                pass
        elif line.startswith("Result: ALLOW"):
            current["decision"] = "ALLOW"
            decisions.append(dict(current))
        elif line.startswith("Result: DENY"):
            current["decision"] = "DENY"
            if "at " in line:
                current["denied_at"] = line.split("at ", 1)[1]
            decisions.append(dict(current))
    return decisions


# ── Phase 2 ───────────────────────────────────────────────────────────────────


def phase2(conn, sample_size=100, output_file=None):
    print("=" * 70)
    print("PHASE 2 — Parse / IR Success on In-Scope Sample")
    print("=" * 70)

    if not os.path.exists(TERRADS_TAR):
        sys.exit(
            f"TerraDS tar not found at {TERRADS_TAR}.\n"
            "Extract it from the dataset zip:\n"
            "  unzip -p <dataset>.zip TerraDS.tar.gz > /tmp/TerraDS.tar.gz"
        )

    in_scope, _ = classify_modules(conn, get_candidate_modules(conn))
    print(f"\nIn-scope population: {len(in_scope):,} modules")

    rng = random.Random(RANDOM_SEED)
    sample_ids = rng.sample(sorted(in_scope.keys()), min(sample_size, len(in_scope)))
    print(f"Sample size: {len(sample_ids)} (seed={RANDOM_SEED})")

    outcomes = defaultdict(int)
    has_incomplete_warning = 0
    timings = []
    per_module = []

    for i, mid in enumerate(sample_ids, 1):
        repo_id, module_path, _types = in_scope[mid]
        print(f"  [{i:3}/{len(sample_ids)}] module={mid} repo={repo_id} path={module_path!r} ...", end=" ", flush=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            ok = extract_module(repo_id, module_path, tmpdir)
            if not ok:
                print("SKIP (archive missing)")
                outcomes["archive_missing"] += 1
                per_module.append({"module_id": mid, "repo_id": repo_id, "path": module_path, "outcome": "archive_missing"})
                continue

            tf_files = list(Path(tmpdir).rglob("*.tf"))
            if not tf_files:
                print("SKIP (no .tf files)")
                outcomes["no_tf_files"] += 1
                per_module.append({"module_id": mid, "repo_id": repo_id, "path": module_path, "outcome": "no_tf_files"})
                continue

            autoformat_dir(tmpdir)
            outcome, stderr, elapsed = run_tool_parse(tmpdir)
            timings.append(elapsed)

            incomplete = "INCOMPLETE ANALYSIS" in stderr
            if incomplete:
                has_incomplete_warning += 1

            print(f"{outcome.upper()}{' +incomplete_warn' if incomplete else ''} ({elapsed:.2f}s)")
            if outcome not in ("success", "no_triples") and stderr:
                # print first line of error
                first_err = stderr.splitlines()[0][:120]
                print(f"      {first_err}")

            outcomes[outcome] += 1
            per_module.append({
                "module_id": mid,
                "repo_id": repo_id,
                "path": module_path,
                "outcome": outcome,
                "incomplete_warning": incomplete,
                "elapsed_s": round(elapsed, 3),
                "stderr_snippet": stderr[:300] if stderr else "",
            })

    total = len(sample_ids)
    print(f"\n--- Phase 2 Results (n={total}) ---")
    for k, v in sorted(outcomes.items(), key=lambda x: -x[1]):
        print(f"  {k:<25} {v:>4}  ({100*v/total:.1f}%)")
    print(f"\n  Incomplete-analysis warnings: {has_incomplete_warning} ({100*has_incomplete_warning/total:.1f}%)")

    if timings:
        avg_t = sum(timings) / len(timings)
        print(f"  Mean parse time:  {avg_t:.3f}s")
        print(f"  Max  parse time:  {max(timings):.3f}s")

    results = {
        "phase": 2,
        "sample_size": total,
        "random_seed": RANDOM_SEED,
        "outcomes": dict(outcomes),
        "incomplete_warning_count": has_incomplete_warning,
        "mean_parse_time_s": round(sum(timings) / len(timings), 3) if timings else None,
        "per_module": per_module,
    }

    if output_file:
        Path(output_file).write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {output_file}")

    return results, per_module


# ── Phase 3 ───────────────────────────────────────────────────────────────────


def phase3(conn, sample_size=30, phase2_results=None, output_file=None):
    print("=" * 70)
    print("PHASE 3 — Full Alloy Analysis on Subset")
    print("=" * 70)

    in_scope, _ = classify_modules(conn, get_candidate_modules(conn))

    # Prefer phase2 successes; fall back to fresh sample
    if phase2_results:
        success_ids = [
            r["module_id"] for r in phase2_results
            if r["outcome"] == "success"
        ]
        rng = random.Random(RANDOM_SEED)
        sample_ids = rng.sample(success_ids, min(sample_size, len(success_ids)))
        print(f"\nUsing {len(sample_ids)} modules from phase2 successes")
    else:
        rng = random.Random(RANDOM_SEED)
        sample_ids = rng.sample(sorted(in_scope.keys()), min(sample_size, len(in_scope)))
        print(f"\nFresh sample of {len(sample_ids)} in-scope modules")

    outcomes = defaultdict(int)
    timings = []
    per_module = []

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    for i, mid in enumerate(sample_ids, 1):
        repo_id, module_path, _types = in_scope[mid]
        print(f"  [{i:2}/{len(sample_ids)}] module={mid} repo={repo_id} ...", end=" ", flush=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            ok = extract_module(repo_id, module_path, tmpdir)
            if not ok:
                print("SKIP")
                outcomes["archive_missing"] += 1
                continue

            als_path = str(RESULTS_DIR / f"module_{mid}.als")
            autoformat_dir(tmpdir)
            outcome, report, elapsed = run_tool_alloy(tmpdir, als_path)
            timings.append(elapsed)

            print(f"{outcome.upper()}  ({elapsed:.1f}s)")

            outcomes[outcome] += 1
            per_module.append({
                "module_id": mid,
                "repo_id": repo_id,
                "path": module_path,
                "outcome": outcome,
                "elapsed_s": round(elapsed, 1),
                "error_snippet": report[:200] if outcome != "success" else "",
            })

    total = len(sample_ids)
    print(f"\n--- Phase 3 Results (n={total}) ---")
    for k, v in sorted(outcomes.items(), key=lambda x: -x[1]):
        print(f"  {k:<20} {v:>3}  ({100*v/total:.1f}%)")

    if timings:
        print(f"\n  Mean Alloy analysis time: {sum(timings)/len(timings):.1f}s")
        print(f"  Max  Alloy analysis time: {max(timings):.1f}s")

    results = {
        "phase": 3,
        "sample_size": total,
        "outcomes": dict(outcomes),
        "mean_alloy_time_s": round(sum(timings) / len(timings), 1) if timings else None,
        "per_module": per_module,
    }

    if output_file:
        Path(output_file).write_text(json.dumps(results, indent=2))
        print(f"\nResults written to {output_file}")

    return results


# ── Entry point ────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("phase", choices=["phase1", "phase2", "phase3", "all"])
    parser.add_argument("--sample", type=int, default=20,
                        help="Sample size for phase2/phase3 (default: 20; use 100+ for thesis report)")
    parser.add_argument("--sample3", type=int, default=20,
                        help="Sample size for phase3 when running 'all' (default: 20)")
    parser.add_argument("--out", help="Output JSON file for results")
    args = parser.parse_args()

    conn = open_db()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.phase in ("phase1", "all"):
        in_scope, has_gap = phase1(conn)

    if args.phase in ("phase2", "all"):
        out = args.out or str(RESULTS_DIR / "phase2_results.json")
        p2_results, per_module = phase2(conn, sample_size=args.sample, output_file=out)

    if args.phase in ("phase3", "all"):
        out = args.out or str(RESULTS_DIR / "phase3_results.json")
        phase2_modules = per_module if args.phase == "all" else None
        sample3 = args.sample3 if args.phase == "all" else args.sample
        phase3(conn, sample_size=sample3, phase2_results=phase2_modules, output_file=out)

    conn.close()


if __name__ == "__main__":
    main()
