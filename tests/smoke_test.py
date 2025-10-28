#!/usr/bin/env python3
"""Minimal smoke test for RepoGuard-AI.

This script creates a temporary git repository, commits an initial file, then commits a change
that includes a simple SQL-like vulnerable pattern. It then runs the `repoguard.py` scanner
against the repo (diff against HEAD~1) and prints the result file contents.

Run this from the project root (or from a venv's python):
  python tests/smoke_test.py
"""
import os
import shutil
import subprocess
import tempfile
import json
import sys
from pathlib import Path


def run(cmd, cwd=None):
    print(f"RUN: {cmd}")
    proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr)
        raise RuntimeError(f"Command failed: {cmd}")


def main():
    root = Path(__file__).resolve().parents[1]
    repoguard_src = root / "repoguard.py"
    config_src = root / "repoguard.yml"

    tmp = Path(tempfile.mkdtemp(prefix="repoguard-smoke-"))
    print("Created temp dir:", tmp)

    try:
        # copy the scanner and config into the temp repo
        shutil.copy(repoguard_src, tmp / "repoguard.py")
        shutil.copy(config_src, tmp / "repoguard.yml")

        # init git
        run("git init", cwd=tmp)
        run("git config user.email \"test@example.com\"", cwd=tmp)
        run("git config user.name \"RepoGuard Test\"", cwd=tmp)

        # initial commit
        (tmp / "app.py").write_text("print('hello')\n")
        run("git add .", cwd=tmp)
        run("git commit -m 'initial'", cwd=tmp)

        # modify file to add a vulnerable pattern
        vuln = "\nuser_id = get_user_input()\nconn.cursor().execute(f\"SELECT * FROM users WHERE id={user_id}\")\n"
        with open(tmp / "app.py", "a") as f:
            f.write(vuln)
        run("git add .", cwd=tmp)
        run("git commit -m 'add vulnerable SQL usage'", cwd=tmp)

        # run repoguard scanning diff against HEAD~1 using the same Python interpreter
        run(f"'{sys.executable}' repoguard.py --config repoguard.yml --base HEAD~1", cwd=tmp)

        # print results
        res_file = tmp / "repoguard_results.json"
        if res_file.exists():
            print("\n=== repoguard_results.json ===")
            print(res_file.read_text())
            # basic assertion: file should parse and have at least zero-length array
            data = json.loads(res_file.read_text())
            print(f"Findings: {len(data)}")
        else:
            raise RuntimeError("repoguard_results.json not found")

    finally:
        print("Cleaning up temp dir")
        shutil.rmtree(tmp)


if __name__ == "__main__":
    main()
