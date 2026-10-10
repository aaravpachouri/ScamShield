
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from core.analyzer import ScamAnalyzer


# ============================================================
# PATHS AND CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = PROJECT_ROOT / "tests"

DATASETS = {
    "regression": (
        TESTS_DIR / "scam_test_cases.json",
        TESTS_DIR / "evaluation_report.json",
    ),
    "holdout": (
        TESTS_DIR / "scam_holdout_cases.json",
        TESTS_DIR / "holdout_evaluation_report.json",
    ),
    "robustness": (
        TESTS_DIR / "scam_robustness_cases.json",
        TESTS_DIR / "robustness_evaluation_report.json",
    ),
}

VALID_LABELS = {"scam", "legitimate"}
SCAM_LEVELS = {"SUSPICIOUS", "HIGH RISK"}


# ============================================================
# SAFE HELPERS
# ============================================================

def safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def safe_list(value: Any) -> list:
    return value if isinstance(value, list) else []


def safe_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None

    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError, OverflowError):
        return None


def load_dataset(path: Path) -> list[Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}\n"
            "Create the dataset file before running this mode."
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            cases = json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid JSON in {path}: {exc}"
        ) from exc

    if not isinstance(cases, list) or not cases:
        raise ValueError(
            f"Dataset must contain a non-empty JSON list: {path}"
        )

    return cases


# ============================================================
# ANALYSIS EXTRACTION
# ============================================================

def extract_diagnostics(
    analysis: dict[str, Any],
) -> dict[str, Any]:
    ai_data = safe_dict(analysis.get("ai_analysis"))
    ai_result = safe_dict(ai_data.get("result"))

    # Support either wrapped or direct AI results.
    if not ai_result and "likely_scam" in ai_data:
        ai_result = ai_data

    url_data = safe_dict(analysis.get("url_analysis"))

    ai_verdict = ai_result.get("likely_scam")
    if not isinstance(ai_verdict, bool):
        ai_verdict = None

    return {
        "final_score": safe_int(analysis.get("final_score")),
        "final_level": analysis.get("final_level"),
        "final_category": analysis.get("final_category"),

        "rule_score": safe_int(analysis.get("rule_score")),
        "rule_level": analysis.get("rule_level"),
        "rule_category": analysis.get("rule_category"),

        "signals": safe_list(analysis.get("signals")),
        "reasons": safe_list(analysis.get("reasons")),
        "actions": safe_list(analysis.get("actions")),

        "url_analysis": url_data or None,
        "url_score": safe_int(url_data.get("score")),

        "ai_available": ai_data.get("available") is True,
        "ai_status": ai_data.get("status"),
        "ai_error": ai_data.get("error"),
        "ai_model": ai_data.get("model"),
        "ai_verdict": ai_verdict,
        "ai_scam_type": ai_result.get("scam_type"),
        "ai_confidence": safe_int(ai_result.get("confidence")),
        "ai_confidence_source": ai_result.get("confidence_source"),
        "ai_explanation": ai_result.get("explanation"),
        "ai_tactics": safe_list(
            ai_result.get("manipulation_tactics")
        ),
        "ai_recommended_action": ai_result.get(
            "recommended_action"
        ),

        "fusion_evidence": safe_list(
            analysis.get("fusion_evidence")
        ),
    }


# ============================================================
# METRICS
# ============================================================

def calculate_metrics(
    *,
    dataset_name: str,
    total_cases: int,
    errors: int,
    tp: int,
    tn: int,
    fp: int,
    fn: int,
    ai_available: int,
    ai_positive: int,
    ai_negative: int,
) -> dict[str, Any]:

    evaluated = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / evaluated if evaluated else None
    )
    precision = (
        tp / (tp + fp) if tp + fp else None
    )
    recall = (
        tp / (tp + fn) if tp + fn else None
    )
    specificity = (
        tn / (tn + fp) if tn + fp else None
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision is not None
        and recall is not None
        and precision + recall > 0
        else None
    )
    fpr = (
        fp / (fp + tn) if fp + tn else None
    )
    fnr = (
        fn / (fn + tp) if fn + tp else None
    )

    def rounded(value: float | None) -> float | None:
        return round(value, 4) if value is not None else None

    return {
        "dataset": dataset_name,
        "total_cases": total_cases,
        "evaluated_cases": evaluated,
        "errors_or_invalid_cases": errors,

        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,

        "accuracy": rounded(accuracy),
        "precision": rounded(precision),
        "recall": rounded(recall),
        "specificity": rounded(specificity),
        "f1_score": rounded(f1),
        "false_positive_rate": rounded(fpr),
        "false_negative_rate": rounded(fnr),

        "ai_available": ai_available,
        "ai_unavailable": evaluated - ai_available,
        "ai_positive_verdicts": ai_positive,
        "ai_negative_verdicts": ai_negative,
    }


# ============================================================
# EVALUATION
# ============================================================

def evaluate_dataset(
    dataset_path: Path,
    report_path: Path,
) -> dict[str, Any]:

    cases = load_dataset(dataset_path)
    analyzer = ScamAnalyzer()

    results: list[dict[str, Any]] = []

    tp = tn = fp = fn = errors = 0
    ai_available = ai_positive = ai_negative = 0

    print(f"\nScamShield Evaluation: {len(cases)} cases")
    print(f"Dataset: {dataset_path.name}")
    print("-" * 72)

    for index, case in enumerate(cases, start=1):

        case_id = (
            case.get("id", f"CASE_{index}")
            if isinstance(case, dict)
            else f"CASE_{index}"
        )

        if not isinstance(case, dict):
            errors += 1
            results.append({
                "id": case_id,
                "status": "INVALID_TEST_CASE",
                "error": "Each test case must be a JSON object.",
            })
            print(f"[INVALID] {case_id}: expected a JSON object")
            continue

        message = case.get("message", "")
        expected = str(case.get("label", "")).strip().lower()

        if (
            not isinstance(message, str)
            or not message.strip()
            or expected not in VALID_LABELS
        ):
            errors += 1
            results.append({
                "id": case_id,
                "status": "INVALID_TEST_CASE",
                "category": case.get("category"),
                "expected": expected,
                "message": message,
                "error": "Invalid message or label.",
            })
            print(f"[INVALID] {case_id}: invalid message or label")
            continue

        try:
            analysis = analyzer.analyze(message)

            if not isinstance(analysis, dict):
                raise TypeError(
                    "Analyzer did not return a dictionary."
                )

            if analysis.get("success") is not True:
                raise RuntimeError(
                    str(analysis.get("error", "Analysis unsuccessful"))
                )

            diagnostics = extract_diagnostics(analysis)

            final_level = diagnostics["final_level"]

            if not isinstance(final_level, str):
                raise ValueError(
                    "Analyzer returned no valid final risk level."
                )

            final_level = final_level.strip().upper()

            if final_level not in {
                "LOW RISK",
                *SCAM_LEVELS,
            }:
                raise ValueError(
                    f"Unexpected final risk level: {final_level}"
                )

            predicted_scam = final_level in SCAM_LEVELS
            expected_scam = expected == "scam"

            if expected_scam and predicted_scam:
                outcome = "TP"
                tp += 1
            elif not expected_scam and not predicted_scam:
                outcome = "TN"
                tn += 1
            elif not expected_scam and predicted_scam:
                outcome = "FP"
                fp += 1
            else:
                outcome = "FN"
                fn += 1

            if diagnostics["ai_available"]:
                ai_available += 1

            if diagnostics["ai_verdict"] is True:
                ai_positive += 1
            elif diagnostics["ai_verdict"] is False:
                ai_negative += 1

            row = {
                "id": case_id,
                "status": "EVALUATED",
                "category": case.get("category", "uncategorized"),
                "expected": expected,
                "predicted": (
                    "scam" if predicted_scam else "legitimate"
                ),
                "outcome": outcome,
                "message": message,
                **diagnostics,
            }

            results.append(row)

            print(
                f"[{outcome}] {case_id} | "
                f"Expected: {expected:10} | "
                f"Predicted: {row['predicted']:10} | "
                f"Score: {row['final_score']} | "
                f"Rule: {row['rule_score']} | "
                f"AI: {row['ai_verdict']}"
            )

        except Exception as exc:
            errors += 1

            error_row = {
                "id": case_id,
                "status": "ERROR",
                "category": case.get("category", "uncategorized"),
                "expected": expected,
                "message": message,
                "error": f"{type(exc).__name__}: {exc}",
            }

            results.append(error_row)
            print(
                f"[ERROR] {case_id}: "
                f"{type(exc).__name__}: {exc}"
            )

    metrics = calculate_metrics(
        dataset_name=dataset_path.name,
        total_cases=len(cases),
        errors=errors,
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        ai_available=ai_available,
        ai_positive=ai_positive,
        ai_negative=ai_negative,
    )

    report = {
        "metrics": metrics,
        "results": results,

        "false_positives": [
            row for row in results
            if row.get("outcome") == "FP"
        ],
        "false_negatives": [
            row for row in results
            if row.get("outcome") == "FN"
        ],
        "error_cases": [
            row for row in results
            if row.get("status") in {
                "ERROR",
                "INVALID_TEST_CASE",
            }
        ],

        "notes": [
            "Synthetic examples are not a validated real-world benchmark.",
            "SUSPICIOUS and HIGH RISK both count as scam predictions.",
            "An AI-positive verdict and a rule-based verdict are not independent ground truth.",
            "Review false positives and false negatives manually.",
            "Holdout examples should not be used to tune the detector.",
        ],
    }

    # Write atomically so an interrupted run doesn't leave a partial report.
    report_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = report_path.with_suffix(
        report_path.suffix + ".tmp"
    )

    try:
        temporary_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        temporary_path.replace(report_path)
    except Exception:
        if temporary_path.exists():
            temporary_path.unlink()
        raise

    print("\n" + "=" * 60)
    print("SCAMSHIELD EVALUATION SUMMARY")
    print("=" * 60)
    print(f"Dataset               : {dataset_path.name}")
    print(
        f"Evaluated cases       : "
        f"{metrics['evaluated_cases']}/{len(cases)}"
    )
    print(f"Errors/invalid cases  : {errors}")
    print(f"True positives        : {tp}")
    print(f"True negatives        : {tn}")
    print(f"False positives       : {fp}")
    print(f"False negatives       : {fn}")

    for label, key in (
        ("Accuracy", "accuracy"),
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("Specificity", "specificity"),
        ("F1 Score", "f1_score"),
        ("False Positive Rate", "false_positive_rate"),
        ("False Negative Rate", "false_negative_rate"),
    ):
        value = metrics[key]
        formatted = "N/A" if value is None else f"{value:.1%}"
        print(f"{label:22}: {formatted}")

    print(f"AI available          : {ai_available}/{metrics['evaluated_cases']}")
    print(f"AI positive verdicts  : {ai_positive}")
    print(f"AI negative verdicts  : {ai_negative}")
    print(f"Detailed report saved to:\n{report_path}")

    return metrics


# ============================================================
# CLI
# ============================================================

def main() -> None:
    if len(sys.argv) != 2:
        print(
            "Usage: python -m tests.evaluate_scamshield "
            "[regression|holdout|robustness]"
        )
        raise SystemExit(2)

    mode = sys.argv[1].strip().lower()

    if mode not in DATASETS:
        print(
            "Usage: python -m tests.evaluate_scamshield "
            "[regression|holdout|robustness]"
        )
        raise SystemExit(2)

    dataset_path, report_path = DATASETS[mode]

    try:
        evaluate_dataset(dataset_path, report_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"\nEvaluation could not start: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
