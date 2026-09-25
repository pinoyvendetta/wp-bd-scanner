#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_scan(*args):
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )


def test_help_smoke():
    proc = run_scan("wpbdscanner.py", "--help")
    assert proc.returncode == 0, proc.stderr
    assert "usage:" in proc.stdout.lower(), proc.stdout


def test_empty_dir_scan():
    with tempfile.TemporaryDirectory() as tmpdir:
        json_path = Path(tmpdir) / "out.json"
        proc = run_scan(
            "wpbdscanner.py",
            "-d",
            tmpdir,
            "-t",
            "2",
            "--json",
            str(json_path),
        )
        assert proc.returncode == 0, proc.stderr
        assert json_path.exists(), proc.stdout + proc.stderr

        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert "found" in data, data
        assert "results" in data, data
        assert isinstance(data["found"], int), data
        assert isinstance(data["results"], list), data


if __name__ == "__main__":
    test_help_smoke()
    test_empty_dir_scan()
    print("All scanner smoke tests passed.")
