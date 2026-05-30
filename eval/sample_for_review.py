#!/usr/bin/env python3
"""
Pick 10 random successful modules from phase3_final.json,
extract their .tf files + copy the .als report + write a decisions summary.

Output: eval/manual_review/<module_id>/
  *.tf              — original Terraform files
  report.als        — Alloy output from the tool
  decisions.json    — parsed (principal, action, bucket, decision) list
  meta.txt          — module id, repo, path, timing
"""

import json
import random
import shutil
import sys
import tarfile
from pathlib import Path

RESULTS_JSON = Path(__file__).parent / "results" / "phase3_final.json"
ALS_DIR      = Path(__file__).parent / "results"
TERRADS_TAR  = Path("/tmp/TerraDS.tar.gz")
OUT_DIR      = Path(__file__).parent / "manual_review"
SEED         = 99   # change to get a different sample
N            = 10


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

        # Copy .als report if it exists
        als_src = ALS_DIR / f"module_{mid}.als"
        if als_src.exists():
            shutil.copy(als_src, out_path / "report.als")

        # Write decisions summary
        (out_path / "decisions.json").write_text(
            json.dumps(mod["decisions"], indent=2)
        )

        # Write meta info
        allow = sum(1 for d in mod["decisions"] if d.get("decision") == "ALLOW")
        deny  = sum(1 for d in mod["decisions"] if d.get("decision") == "DENY")
        meta = (
            f"module_id : {mid}\n"
            f"repo_id   : {repo_id}\n"
            f"path      : {path}\n"
            f"elapsed_s : {mod['elapsed_s']}\n"
            f"decisions : {len(mod['decisions'])} total  ({allow} ALLOW  {deny} DENY)\n"
        )
        (out_path / "meta.txt").write_text(meta)

        tf_files = list(out_path.glob("*.tf"))
        print(f"OK  ({len(tf_files)} .tf files,  {len(mod['decisions'])} decisions)")

    print(f"\nDone. Review folders in:\n  {OUT_DIR}/")


if __name__ == "__main__":
    main()
