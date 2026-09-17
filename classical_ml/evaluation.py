"""
Evaluation and Benchmarking Metrics for Intrusion Detection Models.
Computes Accuracy, Precision, Recall, F1, False Positive Rate (FPR), ROC-AUC, and PR-AUC.
"""

import numpy as np
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    precision_recall_curve,
    auc,
    roc_curve
)

@dataclass
class MetricsResult:
    accuracy: float
    precision_macro: float
    precision_weighted: float
    recall_macro: float
    recall_weighted: float
    f1_macro: float
    f1_weighted: float
    false_positive_rate: float
    roc_auc: float
    pr_auc: float
    confusion_matrix: List[List[int]]
    class_names: List[str]
    training_time_sec: float = 0.0
    inference_latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def compute_fpr(y_true_binary: np.ndarray, y_pred_binary: np.ndarray) -> float:
    """
    Compute False Positive Rate = FP / (FP + TN)
    """
    cm = confusion_matrix(y_true_binary, y_pred_binary, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    return fpr

def compute_pr_auc(y_true_binary: np.ndarray, y_scores: np.ndarray) -> float:
    """Compute Area Under the Precision-Recall Curve."""
    precision, recall, _ = precision_recall_curve(y_true_binary, y_scores)
    return float(auc(recall, precision))

def evaluate_classification(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_scores: Optional[np.ndarray],
    class_names: List[str],
    benign_idx: int = 0,
    training_time: float = 0.0,
    inference_latency_ms: float = 0.0
) -> MetricsResult:
    """
    Comprehensive evaluation for multi-class or binary attack classification.
    """
    acc = float(accuracy_score(y_true, y_pred))
    p_macro = float(precision_score(y_true, y_pred, average="macro", zero_division=0))
    p_weighted = float(precision_score(y_true, y_pred, average="weighted", zero_division=0))
    r_macro = float(recall_score(y_true, y_pred, average="macro", zero_division=0))
    r_weighted = float(recall_score(y_true, y_pred, average="weighted", zero_division=0))
    f1_m = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    f1_w = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))
    
    # Binary conversion for FPR, ROC-AUC, and PR-AUC
    y_true_bin = (y_true != benign_idx).astype(int)
    y_pred_bin = (y_pred != benign_idx).astype(int)
    
    fpr = compute_fpr(y_true_bin, y_pred_bin)
    
    # ROC-AUC & PR-AUC
    roc_val = 0.0
    pr_val = 0.0
    if y_scores is not None and len(np.unique(y_true_bin)) > 1:
        # If multi-class probability matrix provided, extract anomaly probability (1 - P(benign))
        if y_scores.ndim > 1:
            anomaly_scores = 1.0 - y_scores[:, benign_idx]
        else:
            anomaly_scores = y_scores
            
        try:
            roc_val = float(roc_auc_score(y_true_bin, anomaly_scores))
            pr_val = compute_pr_auc(y_true_bin, anomaly_scores)
        except Exception:
            roc_val = 0.0
            pr_val = 0.0
            
    cm = confusion_matrix(y_true, y_pred).tolist()
    
    return MetricsResult(
        accuracy=round(acc, 4),
        precision_macro=round(p_macro, 4),
        precision_weighted=round(p_weighted, 4),
        recall_macro=round(r_macro, 4),
        recall_weighted=round(r_weighted, 4),
        f1_macro=round(f1_m, 4),
        f1_weighted=round(f1_w, 4),
        false_positive_rate=round(fpr, 4),
        roc_auc=round(roc_val, 4),
        pr_auc=round(pr_val, 4),
        confusion_matrix=cm,
        class_names=class_names,
        training_time_sec=round(training_time, 3),
        inference_latency_ms=round(inference_latency_ms, 3)
    )

def evaluate_anomaly_detector(
    y_true_binary: np.ndarray,
    risk_scores: np.ndarray,
    threshold: float = 0.65,
    training_time: float = 0.0,
    inference_latency_ms: float = 0.0
) -> MetricsResult:
    """
    Evaluate unsupervised anomaly detector against true labels.
    """
    y_pred_binary = (risk_scores >= threshold).astype(int)
    return evaluate_classification(
        y_true=y_true_binary,
        y_pred=y_pred_binary,
        y_scores=risk_scores,
        class_names=["BENIGN", "ANOMALY"],
        benign_idx=0,
        training_time=training_time,
        inference_latency_ms=inference_latency_ms
    )
