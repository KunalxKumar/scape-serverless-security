"""SCAPE Local Verification Suite.

Runs all unit tests, smoke tests, calibration, evaluation, and ablation
in sequence. Automatically finds the correct Python interpreter that has
the required dependencies (pytest, numpy) installed.

Usage:
    python scripts/run_local_tests.py
"""

import subprocess
import sys
import os
import shutil
import time

# Project configuration
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def find_python_with_deps():
    """Find a Python interpreter that has pytest and numpy installed.

    Checks the current interpreter first, then falls back to well-known
    paths on Windows (Microsoft Store Python, standard installs, etc.).
    """
    candidates = [
        sys.executable,
        shutil.which("python") or "",
        shutil.which("python3") or "",
        # Microsoft Store Python (commonly has deps on this machine)
        os.path.expandvars(
            r"%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe"
        ),
        # Standard Windows install locations
        os.path.expandvars(
            r"%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
        ),
        os.path.expandvars(
            r"%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
        ),
    ]

    # De-duplicate while preserving order
    seen = set()
    unique = []
    for c in candidates:
        c = os.path.normpath(c) if c else ""
        if c and c not in seen:
            seen.add(c)
            unique.append(c)

    for python_path in unique:
        if not os.path.isfile(python_path):
            continue
        try:
            result = subprocess.run(
                [python_path, "-c", "import pytest; import numpy"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return python_path
        except Exception:
            continue

    return None


def run_command(cmd, name):
    print(f"\n>>> Running {name}...")
    print(f"Command: {' '.join(cmd)}")
    start_time = time.time()
    try:
        result = subprocess.run(
            cmd, cwd=PROJECT_ROOT, capture_output=True, text=True
        )
        duration = time.time() - start_time

        if result.returncode == 0:
            print(f"[SUCCESS] {name} completed in {duration:.2f}s")
            return True, result.stdout
        else:
            print(f"[FAILURE] {name} failed with exit code {result.returncode}")
            print("--- STDOUT ---")
            print(result.stdout)
            print("--- STDERR ---")
            print(result.stderr)
            return False, result.stderr
    except Exception as e:
        print(f"[ERROR] Exception occurred during {name}: {e}")
        return False, str(e)


def main():
    print("=" * 60)
    print("SCAPE LOCAL VERIFICATION SUITE")
    print("=" * 60)
    print(f"Project Root: {PROJECT_ROOT}")

    # --- Find a working Python ---
    print("\nSearching for a Python interpreter with pytest + numpy...")
    python_exe = find_python_with_deps()

    if python_exe is None:
        print(
            "\n[ERROR] No Python interpreter found with pytest and numpy.\n"
            "Please install them first:\n"
            "    pip install pytest numpy\n"
        )
        sys.exit(1)

    print(f"Using Python: {python_exe}")

    # --- Define test steps ---
    test_steps = [
        {
            "name": "Unit Tests (56 tests)",
            "cmd": [python_exe, "-m", "pytest", "tests/", "-v"],
        },
        {
            "name": "Smoke Test Fixes",
            "cmd": [python_exe, "scripts/smoke_test_fixes.py"],
        },
        {
            "name": "Threshold Calibration",
            "cmd": [
                python_exe, "evaluation/calibrate_thresholds.py",
                "--normal-logs", "data/normal_traffic.json", "--save",
            ],
        },
        {
            "name": "Full Performance Evaluation",
            "cmd": [
                python_exe, "evaluation/full_evaluation.py",
                "--attack-ratio", "0.05", "--clean-fpr",
            ],
        },
        {
            "name": "Ablation Study",
            "cmd": [python_exe, "evaluation/ablation.py"],
        },
    ]

    # --- Execute ---
    results = []
    overall_success = True

    for step in test_steps:
        success, output = run_command(step["cmd"], step["name"])
        results.append((step["name"], success))
        if not success:
            overall_success = False
            print("Stopping suite due to critical failure.")
            break

    # --- Summary ---
    print("\n" + "=" * 60)
    print("FINAL VERIFICATION SUMMARY")
    print("=" * 60)
    for name, success in results:
        status = "PASSED" if success else "FAILED"
        print(f"{name:<40} [{status}]")

    if overall_success:
        print("\nALL TESTS PASSED! SCAPE is ready for AWS deployment.")
        sys.exit(0)
    else:
        print(
            "\nSOME TESTS FAILED. "
            "Please fix the issues above before moving to AWS."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
