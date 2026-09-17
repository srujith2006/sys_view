"""
Classical Machine Learning Baseline Package for QE-NIDS
"""

from .anomaly_detection import UnsupervisedAnomalyDetector
from .classification import SupervisedAttackClassifier, HybridDecisionEngine
from .evaluation import evaluate_classification, evaluate_anomaly_detector, MetricsResult

__all__ = [
    "UnsupervisedAnomalyDetector",
    "SupervisedAttackClassifier",
    "HybridDecisionEngine",
    "evaluate_classification",
    "evaluate_anomaly_detector",
    "MetricsResult"
]
