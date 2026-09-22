import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

python_cmd = sys.executable


def run_command(cmd, desc):
    print("\n" + "="*70)
    print(f"RUNNING: {desc}")
    print("="*70)
    print("$", " ".join(cmd), "\n")

    try:
        result = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=600
        )

        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "output": result.stdout,
            "stderr": result.stderr
        }

    except Exception as e:
        return {
            "success": False,
            "return_code": -1,
            "output": "",
            "stderr": str(e)
        }


def load_json(path):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except:
            return {}
    return {}


def main():
    print("\n" + "="*70)
    print("SCAPE COMPREHENSIVE TEST SUITE")
    print("="*70)

    os.makedirs(root / "results", exist_ok=True)

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "test_layers": {},
        "summary": {}
    }

    # ---------------------------
    # Layer 1: Unit tests
    # ---------------------------
    res = run_command(
        [python_cmd, "-m", "pytest", "tests", "-v", "--tb=short"],
        "Baseline Unit Tests"
    )
    results["test_layers"]["unit"] = res

    # ---------------------------
    # Layer 2: Coverage
    # ---------------------------
    res = run_command(
        [
            python_cmd, "-m", "pytest", "tests",
            "--cov=src/scape_engine.py",
            "--cov-report=term-missing",
            "--cov-report=html"
        ],
        "Coverage"
    )
    results["test_layers"]["coverage"] = res

    # ---------------------------
    # Layer 3: Adversarial
    # ---------------------------
    res = run_command(
        [python_cmd, "-m", "pytest", "tests/test_adversarial_scenarios.py", "-v"],
        "Adversarial Tests"
    )
    results["test_layers"]["adversarial"] = res

    # ---------------------------
    # Layer 4: Stress test
    # ---------------------------
    res = run_command(
        [python_cmd, "scape/scripts/run_stress_test.py", "100000"],
        "Stress Test"
    )
    results["test_layers"]["stress"] = res

    stress = load_json(root / "results/stress_test_results.json")
    if stress:
        results["test_layers"]["stress"]["metrics"] = stress

    # ---------------------------
    # Layer 5: Calibration
    # ---------------------------
    res = run_command(
        [python_cmd, "scape/scripts/calibrate_thresholds.py"],
        "Calibration"
    )
    results["test_layers"]["calibration"] = res

    cal = load_json(root / "results/calibration_results.json")
    if cal:
        results["test_layers"]["calibration"]["metrics"] = cal

    # ---------------------------
    # Layer 6: Evaluation
    # ---------------------------
    res = run_command(
        [python_cmd, "scape/scripts/full_evaluation.py"],
        "Cross Dataset Evaluation"
    )
    results["test_layers"]["evaluation"] = res

    ev = load_json(root / "results/full_evaluation_results.json")
    if ev:
        results["test_layers"]["evaluation"]["metrics"] = ev

    # ---------------------------
    # Summary
    # ---------------------------
    passed = sum(
        1 for k, v in results["test_layers"].items()
        if isinstance(v, dict) and v.get("success")
    )

    total = len(results["test_layers"])

    results["summary"] = {
        "passed": passed,
        "total": total,
        "all_passed": passed == total
    }

    with open(root / "results/test_summary.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n" + "="*70)
    print("RESULT")
    print("="*70)
    print(f"Passed: {passed}/{total}")
    print("Status:", "PASS" if passed == total else "FAIL")
    print("="*70)

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())