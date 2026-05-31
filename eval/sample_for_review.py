#!/usr/bin/env python3
"""
Pick 10 random successful modules from a phase3 results JSON,
extract their .tf files + copy the .als report + write a decisions summary.

Usage:
  python3 sample_for_review.py [phase3_results.json]

Output: eval/manual_review/<module_id>/
  *.tf              — original Terraform files
  report.als        — Alloy output from the tool
  decisions.json    — parsed (principal, action, bucket, decision) list
  meta.txt          — module id, repo, path, timing
"""

import json
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

_default     = Path(__file__).parent / "results" / "phase3_results.json"
RESULTS_JSON = Path(sys.argv[1]) if len(sys.argv) > 1 else _default
ALS_DIR      = Path(__file__).parent / "results"
TERRADS_TAR  = Path("/tmp/TerraDS.tar.gz")
OUT_DIR      = Path(__file__).parent / "manual_review"
TOOL_BINARY  = str(Path(__file__).parent.parent / "access-control-helper")
SEED         = 99
N            = 20


def extract_module_tf(repo_id, module_path, dest_dir):
    outer = tarfile.open(str(TERRADS_TAR), "r:gz")
    member_name = f"TerraDS/{repo_id}.tar.gz"
    try:
        member = outer.getmember(member_name)
    except KeyError:
        outer.close()
        return False

    inner_fh = outer.extractfile(member)
    inner = tarfile.open(fileobj=inner_fh, mode="r:gz")

    repo_prefix = f"{repo_id}/"
    match_prefix = repo_prefix if module_path == "." else f"{repo_prefix}{module_path.rstrip('/')}/"

    extracted = False
    for m in inner.getmembers():
        if not m.name.startswith(match_prefix):
            continue
        if not m.name.endswith(".tf"):
            continue
        rel = m.name[len(match_prefix):]
        if "/" in rel:
            continue
        m.name = rel
        try:
            inner.extract(m, dest_dir, filter="data")
        except TypeError:
            inner.extract(m, dest_dir)
        extracted = True

    inner.close()
    outer.close()
    return extracted


def run_tool_and_parse(tf_dir, als_path, timeout=120):
    """Run the full pipeline and return parsed decisions as a list of dicts."""
    try:
        result = subprocess.run(
            [TOOL_BINARY, str(tf_dir), str(als_path)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None, "timeout"

    if result.returncode != 0:
        return None, result.stderr.strip()

    decisions = []
    current = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Query: can "):
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

    return decisions, None


def main():
    if not TERRADS_TAR.exists():
        sys.exit(f"TerraDS tar not found at {TERRADS_TAR}")

    data = json.loads(RESULTS_JSON.read_text())
    successes = [m for m in data["per_module"] if m["outcome"] == "success"]
    print(f"Successful modules in phase3_final.json: {len(successes)}")

    rng = random.Random(SEED)
    sample = rng.sample(successes, min(N, len(successes)))

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for mod in sample:
        mid      = mod["module_id"]
        repo_id  = mod["repo_id"]
        path     = mod["path"]
        out_path = OUT_DIR / f"module_{mid}"
        out_path.mkdir(exist_ok=True)

        print(f"  module={mid}  repo={repo_id}  path={path!r} ...", end=" ", flush=True)

        ok = extract_module_tf(repo_id, path, str(out_path))
        if not ok:
            print("SKIP (archive missing)")
            shutil.rmtree(out_path)
            continue

        # Copy .als spec if it exists
        als_src = ALS_DIR / f"module_{mid}.als"
        if als_src.exists():
            shutil.copy(als_src, out_path / "spec.als")

        # Format before running tool (same as evaluate.py phase3)
        import shutil as _shutil
        tf_bin = _shutil.which("terraform")
        if tf_bin:
            subprocess.run([tf_bin, "fmt", "-recursive", str(out_path)],
                           capture_output=True, timeout=15)

        # Run tool to get decisions JSON
        with tempfile.NamedTemporaryFile(suffix=".als", delete=False) as tmp:
            tmp_als = tmp.name
        decisions, err = run_tool_and_parse(out_path, tmp_als)
        Path(tmp_als).unlink(missing_ok=True)

        if decisions is not None:
            (out_path / "decisions.json").write_text(json.dumps(decisions, indent=2))
            allow = sum(1 for d in decisions if d.get("decision") == "ALLOW")
            deny  = sum(1 for d in decisions if d.get("decision") == "DENY")
            decisions_note = f"{len(decisions)} decisions ({allow} ALLOW, {deny} DENY)"
        else:
            decisions_note = f"tool error: {err}"

        # Write meta info
        meta = (
            f"module_id : {mid}\n"
            f"repo_id   : {repo_id}\n"
            f"path      : {path}\n"
            f"elapsed_s : {mod['elapsed_s']}\n"
            f"decisions : {decisions_note}\n"
        )
        (out_path / "meta.txt").write_text(meta)

        tf_files = list(out_path.glob("*.tf"))
        print(f"OK  ({len(tf_files)} .tf files, {decisions_note})")

    print(f"\nDone. Review folders in:\n  {OUT_DIR}/")


if __name__ == "__main__":
    main()
