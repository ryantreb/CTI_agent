#!/usr/bin/env python3
"""
Evaluation Runner
Orchestrates all graders and produces aggregate evaluation results.

Usage:
    python run_evaluation.py <source_file> <output_file> [--json]
"""

import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any


# Grader configuration
GRADERS = [
    {
        "name": "ttp_coverage",
        "script": "ttp_coverage.py",
        "threshold": 0.80,
        "requires_source": True,
        "weight": 0.25,
    },
    {
        "name": "ioc_fidelity",
        "script": "ioc_fidelity.py",
        "threshold": 0.90,
        "requires_source": True,
        "weight": 0.30,
        "critical": True,  # Failure here is severe
    },
    {
        "name": "framework_compliance",
        "script": "framework_compliance.py",
        "threshold": 0.85,
        "requires_source": False,
        "weight": 0.25,
    },
    {
        "name": "analytical_quality",
        "config": "analytical_quality_judge.json",
        "threshold": 0.70,
        "requires_source": False,
        "weight": 0.20,
        "type": "llm_judge",
    },
]


def run_python_grader(
    script: str, source_path: str, output_path: str, requires_source: bool
) -> Dict[str, Any]:
    """Run a Python-based grader script."""
    grader_dir = Path(__file__).parent / "graders"
    script_path = grader_dir / script

    if requires_source:
        cmd = [sys.executable, str(script_path), source_path, output_path]
    else:
        cmd = [sys.executable, str(script_path), output_path]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "Grader timeout", "score": 0.0, "passed": False}
    except json.JSONDecodeError:
        return {"error": "Invalid grader output", "score": 0.0, "passed": False}
    except Exception as e:
        return {"error": str(e), "score": 0.0, "passed": False}


def run_llm_judge(config_file: str, output_path: str) -> Dict[str, Any]:
    """
    Run LLM-as-judge evaluation.

    Note: In production, this would call the Claude API.
    For now, returns a placeholder that should be replaced with actual API call.
    """
    grader_dir = Path(__file__).parent / "graders"
    config_path = grader_dir / config_file

    with open(config_path, "r") as f:
        config = json.loads(f.read())

    with open(output_path, "r") as f:
        output = f.read()

    # Heuristic fallback when API not available
    # In production, replace this with actual Claude API call
    score = heuristic_quality_score(output, config)

    return {
        "grader": "analytical_quality",
        "score": score,
        "pass_threshold": config["pass_threshold"],
        "passed": score >= config["pass_threshold"],
        "note": "Heuristic fallback - replace with API call in production",
    }


def heuristic_quality_score(output: str, config: Dict) -> float:
    """
    Fallback heuristic scoring when LLM judge unavailable.
    Checks for presence of quality indicators.
    """
    positive_count = sum(
        1
        for indicator in config["quality_indicators"]["positive"]
        if indicator.lower() in output.lower()
    )
    negative_count = sum(
        1
        for indicator in config["quality_indicators"]["negative"]
        if indicator.lower() in output.lower()
    )

    # Base score from positive indicators
    base_score = min(
        positive_count / len(config["quality_indicators"]["positive"]), 1.0
    )

    # Penalty for negative indicators
    penalty = negative_count * 0.1

    return round(max(0.0, base_score - penalty), 2)


def run_all_graders(source_path: str, output_path: str) -> Dict[str, Any]:
    """Run all graders and aggregate results."""
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "source_file": source_path,
        "output_file": output_path,
        "grader_results": {},
        "aggregate": {},
    }

    weighted_sum = 0.0
    total_weight = 0.0
    all_passed = True
    critical_failure = False
    failures = []

    for grader in GRADERS:
        if grader.get("type") == "llm_judge":
            grader_result = run_llm_judge(grader["config"], output_path)
        else:
            grader_result = run_python_grader(
                grader["script"], source_path, output_path, grader["requires_source"]
            )

        results["grader_results"][grader["name"]] = grader_result

        score = grader_result.get("score", 0.0)
        passed = grader_result.get("passed", False)
        weight = grader["weight"]

        weighted_sum += score * weight
        total_weight += weight

        if not passed:
            all_passed = False
            failures.append(
                {
                    "grader": grader["name"],
                    "score": score,
                    "threshold": grader["threshold"],
                    "gap": round(grader["threshold"] - score, 2),
                }
            )

            if grader.get("critical"):
                critical_failure = True

    # Calculate aggregate scores
    results["aggregate"] = {
        "weighted_average": round(weighted_sum / total_weight, 2)
        if total_weight > 0
        else 0.0,
        "simple_average": round(
            sum(r.get("score", 0) for r in results["grader_results"].values())
            / len(GRADERS),
            2,
        ),
        "all_passed": all_passed,
        "critical_failure": critical_failure,
        "failure_count": len(failures),
        "failures": failures,
    }

    return results


def main():
    """CLI entry point."""
    if len(sys.argv) < 3:
        print("Usage: run_evaluation.py <source_file> <output_file> [--json]")
        print("\nRuns all graders and returns aggregate evaluation results.")
        sys.exit(1)

    source_path = sys.argv[1]
    output_path = sys.argv[2]
    json_output = "--json" in sys.argv

    # Validate files exist
    if not Path(source_path).exists():
        print(f"Error: Source file not found: {source_path}")
        sys.exit(1)

    if not Path(output_path).exists():
        print(f"Error: Output file not found: {output_path}")
        sys.exit(1)

    # Run evaluation
    results = run_all_graders(source_path, output_path)

    if json_output:
        print(json.dumps(results, indent=2))
    else:
        # Human-readable output
        print("\n" + "=" * 60)
        print("EVALUATION RESULTS")
        print("=" * 60)
        print(f"\nSource: {source_path}")
        print(f"Output: {output_path}")
        print(f"Time: {results['timestamp']}")

        print("\n--- Grader Scores ---")
        for name, result in results["grader_results"].items():
            status = "✅" if result.get("passed") else "❌"
            score = result.get("score", 0.0)
            threshold = result.get("pass_threshold", 0.0)
            print(f"  {status} {name}: {score:.2f} (threshold: {threshold})")

        print("\n--- Aggregate ---")
        agg = results["aggregate"]
        print(f"  Weighted Average: {agg['weighted_average']:.2f}")
        print(f"  All Passed: {agg['all_passed']}")
        print(f"  Critical Failure: {agg['critical_failure']}")

        if agg["failures"]:
            print("\n--- Failures ---")
            for f in agg["failures"]:
                print(
                    f"  • {f['grader']}: {f['score']:.2f} < {f['threshold']} (gap: {f['gap']})"
                )

        print("\n" + "=" * 60)

    # Exit code based on pass/fail
    sys.exit(0 if results["aggregate"]["all_passed"] else 1)


if __name__ == "__main__":
    main()
