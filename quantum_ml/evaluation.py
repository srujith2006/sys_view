"""
Research Evaluation and Comparative Benchmarking between Classical ML and Quantum ML.
Provides side-by-side analysis, honest assessment reporting, and metric tabulation.
"""

import pandas as pd
from typing import Dict, Any, Tuple
from classical_ml.evaluation import MetricsResult

def compare_classical_vs_quantum(
    classical_metrics: MetricsResult,
    quantum_metrics: MetricsResult,
    model_names: Tuple[str, str] = ("Classical Random Forest", "Quantum Kernel SVM (QSVC)")
) -> Dict[str, Any]:
    """
    Produce an objective side-by-side comparison between Classical and Quantum ML.
    """
    c_name, q_name = model_names
    
    records = [
        {"Metric": "Accuracy", c_name: classical_metrics.accuracy, q_name: quantum_metrics.accuracy},
        {"Metric": "Precision (Macro)", c_name: classical_metrics.precision_macro, q_name: quantum_metrics.precision_macro},
        {"Metric": "Precision (Weighted)", c_name: classical_metrics.precision_weighted, q_name: quantum_metrics.precision_weighted},
        {"Metric": "Recall (Macro)", c_name: classical_metrics.recall_macro, q_name: quantum_metrics.recall_macro},
        {"Metric": "Recall (Weighted)", c_name: classical_metrics.recall_weighted, q_name: quantum_metrics.recall_weighted},
        {"Metric": "F1-Score (Macro)", c_name: classical_metrics.f1_macro, q_name: quantum_metrics.f1_macro},
        {"Metric": "F1-Score (Weighted)", c_name: classical_metrics.f1_weighted, q_name: quantum_metrics.f1_weighted},
        {"Metric": "False Positive Rate (FPR)", c_name: classical_metrics.false_positive_rate, q_name: quantum_metrics.false_positive_rate},
        {"Metric": "ROC-AUC", c_name: classical_metrics.roc_auc, q_name: quantum_metrics.roc_auc},
        {"Metric": "PR-AUC", c_name: classical_metrics.pr_auc, q_name: quantum_metrics.pr_auc},
        {"Metric": "Training Time (sec)", c_name: classical_metrics.training_time_sec, q_name: quantum_metrics.training_time_sec},
        {"Metric": "Inference Latency (ms/sample)", c_name: classical_metrics.inference_latency_ms, q_name: quantum_metrics.inference_latency_ms}
    ]
    
    df_comparison = pd.DataFrame(records)
    
    # Honest Research Analysis Findings
    findings = []
    
    # Accuracy & F1 Analysis
    if quantum_metrics.f1_weighted >= classical_metrics.f1_weighted:
        findings.append(
            f"Quantum Kernel SVM achieved competitive or superior weighted F1 ({quantum_metrics.f1_weighted:.4f} vs {classical_metrics.f1_weighted:.4f}), "
            "indicating effective non-linear separation in the quantum Hilbert feature space."
        )
    else:
        diff = classical_metrics.f1_weighted - quantum_metrics.f1_weighted
        findings.append(
            f"Classical ML outperformed Quantum Kernel SVM by {diff:.4f} in weighted F1-score. "
            "Classical decision trees and ensemble methods can leverage full feature granularity without dimensional compression constraints."
        )
        
    # Latency & Computational Overhead
    if quantum_metrics.training_time_sec > classical_metrics.training_time_sec:
        ratio = quantum_metrics.training_time_sec / max(classical_metrics.training_time_sec, 0.001)
        findings.append(
            f"Quantum Kernel simulation incurred a {ratio:.1f}x training runtime overhead relative to classical baselines. "
            "Simulating quantum state entanglement on classical hardware requires O(N^2) pairwise circuit evaluations, "
            "highlighting that near-term QML value depends on specialized QPU acceleration or high-dimensional quantum embeddings."
        )
        
    # False Positive Rate
    if quantum_metrics.false_positive_rate < classical_metrics.false_positive_rate:
        findings.append(
            f"Quantum Kernel SVM demonstrated a lower False Positive Rate ({quantum_metrics.false_positive_rate:.4f} vs {classical_metrics.false_positive_rate:.4f}), "
            "which reduces alert fatigue in Security Operations Centers."
        )
    else:
        findings.append(
            f"Classical ML maintained a comparable or lower False Positive Rate ({classical_metrics.false_positive_rate:.4f} vs {quantum_metrics.false_positive_rate:.4f})."
        )
        
    return {
        "comparison_table": df_comparison,
        "classical_metrics": classical_metrics.to_dict(),
        "quantum_metrics": quantum_metrics.to_dict(),
        "findings": findings
    }
