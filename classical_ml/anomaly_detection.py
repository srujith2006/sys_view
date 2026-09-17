"""
Unsupervised Anomaly Detection Module using Isolation Forest.
Calculates continuous anomaly and risk scores calibrated to [0.0, 1.0] with SOC severity tiers.
"""

import numpy as np
from typing import Dict, Any, Tuple
from sklearn.ensemble import IsolationForest
import joblib

class UnsupervisedAnomalyDetector:
    """
    Isolation Forest Anomaly Detector.
    Learns normal baseline traffic distribution and produces calibrated risk scores.
    """
    def __init__(
        self,
        n_estimators: int = 150,
        contamination: float = 0.15,
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.min_score_: float = -0.5
        self.max_score_: float = 0.5
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray) -> "UnsupervisedAnomalyDetector":
        """
        Fit Isolation Forest on baseline network traffic.
        """
        self.model.fit(X)
        # Compute decision function bounds for normalization
        # In scikit-learn, decision_function returns positive for inliers, negative for outliers
        scores = self.model.decision_function(X)
        self.min_score_ = float(np.min(scores))
        self.max_score_ = float(np.max(scores))
        self.is_fitted = True
        return self

    def compute_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """
        Compute continuous risk/anomaly scores in [0.0, 1.0].
        0.00 = highly normal baseline
        1.00 = extreme statistical outlier
        """
        if not self.is_fitted:
            raise ValueError("Model is not fitted yet.")
            
        raw_decisions = self.model.decision_function(X)
        
        # Piecewise calibration centered at Isolation Forest's natural zero boundary
        # raw >= 0 (inliers): maps to [0.0, 0.5]
        # raw < 0 (outliers): maps to [0.5, 1.0]
        max_pos = max(self.max_score_, 1e-4)
        min_neg = max(abs(self.min_score_), 1e-4)
        
        scores = np.where(
            raw_decisions >= 0,
            0.50 * (1.0 - np.clip(raw_decisions / max_pos, 0.0, 1.0)),
            0.50 + 0.50 * np.clip(-raw_decisions / min_neg, 0.0, 1.0)
        )
        return np.clip(scores, 0.0, 1.0)

    def predict(self, X: np.ndarray, threshold: float = 0.65) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
            binary_predictions: 0 for NORMAL, 1 for ANOMALOUS
            risk_scores: continuous scores in [0.0, 1.0]
        """
        risk_scores = self.compute_anomaly_scores(X)
        binary_preds = (risk_scores >= threshold).astype(int)
        return binary_preds, risk_scores

    @staticmethod
    def get_severity(risk_score: float) -> str:
        """
        Convert continuous risk score to SOC severity tier.
        0.00 - 0.30 -> NORMAL
        0.30 - 0.60 -> LOW
        0.60 - 0.80 -> MEDIUM
        0.80 - 0.90 -> HIGH
        0.90 - 1.00 -> CRITICAL
        """
        if risk_score < 0.30:
            return "NORMAL"
        elif risk_score < 0.60:
            return "LOW"
        elif risk_score < 0.80:
            return "MEDIUM"
        elif risk_score < 0.90:
            return "HIGH"
        else:
            return "CRITICAL"

    def save(self, filepath: str):
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "UnsupervisedAnomalyDetector":
        return joblib.load(filepath)
