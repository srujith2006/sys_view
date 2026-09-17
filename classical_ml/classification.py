"""
Supervised Attack Classification and Hybrid Decision Engine for QE-NIDS.
Implements multi-class attack classification and the Unknown/Novel Anomaly detection logic.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier
import joblib

from utils.config import (
    ANOMALY_SCORE_THRESHOLD, 
    NOVEL_ATTACK_CONFIDENCE_THRESHOLD,
    RISK_THRESHOLDS
)
from .anomaly_detection import UnsupervisedAnomalyDetector

class SupervisedAttackClassifier:
    """
    Supervised Multi-Class Classifier (Random Forest).
    Classifies known attack categories (DDoS, PortScan, BruteForce, Botnet, Infiltration).
    """
    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 15,
        class_weight: str = "balanced",
        random_state: int = 42
    ):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.class_weight = class_weight
        self.random_state = random_state
        
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight=class_weight,
            random_state=random_state,
            n_jobs=-1
        )
        self.classes_: List[str] = []
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, y: np.ndarray, class_names: List[str]) -> "SupervisedAttackClassifier":
        """Fit model on multi-class network flow records."""
        self.classes_ = class_names
        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict_with_confidence(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Returns:
            predicted_indices: array of class indices
            confidences: highest class probability for each sample
            probabilities: full probability matrix (N, num_classes)
        """
        if not self.is_fitted:
            raise ValueError("Classifier is not fitted yet.")
            
        probs = self.model.predict_proba(X)
        predicted_indices = np.argmax(probs, axis=1)
        confidences = np.max(probs, axis=1)
        return predicted_indices, confidences, probs

    def save(self, filepath: str):
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "SupervisedAttackClassifier":
        return joblib.load(filepath)


class HybridDecisionEngine:
    """
    Orchestrates the Dual-Engine Detection Logic:
    1. Unsupervised Anomaly Detection (Isolation Forest) -> Anomaly/Risk Score
    2. Supervised Attack Classification (Random Forest) -> Category & Confidence
    3. Novel/Unknown Anomaly Resolution -> Flags deviations lacking known signatures
    """
    def __init__(
        self,
        anomaly_detector: UnsupervisedAnomalyDetector,
        classifier: SupervisedAttackClassifier,
        class_names: List[str],
        anomaly_threshold: float = ANOMALY_SCORE_THRESHOLD,
        novel_confidence_threshold: float = NOVEL_ATTACK_CONFIDENCE_THRESHOLD
    ):
        self.anomaly_detector = anomaly_detector
        self.classifier = classifier
        self.class_names = class_names
        self.anomaly_threshold = anomaly_threshold
        self.novel_confidence_threshold = novel_confidence_threshold

    def evaluate_flow(
        self, 
        X_sample: np.ndarray, 
        meta_dict: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate a single network flow or batch.
        Produces standardized alert JSON adhering to Section 9 & 10 requirements.
        """
        if X_sample.ndim == 1:
            X_sample = X_sample.reshape(1, -1)
            
        # 1. Unsupervised Anomaly Scoring
        risk_scores = self.anomaly_detector.compute_anomaly_scores(X_sample)
        risk_score = float(risk_scores[0])
        severity = self.anomaly_detector.get_severity(risk_score)
        
        # 2. Supervised Classification
        pred_idx, confidences, probs = self.classifier.predict_with_confidence(X_sample)
        top_idx = int(pred_idx[0])
        confidence = float(confidences[0])
        predicted_class = self.class_names[top_idx] if top_idx < len(self.class_names) else "UNKNOWN"
        
        # 3. Dual-Engine Logic
        is_anomalous = risk_score >= self.anomaly_threshold
        
        if not is_anomalous:
            status = "NORMAL"
            category = "BENIGN"
            is_novel = False
            notes = "Traffic aligns with learned normal network behavior baseline."
        else:
            status = "ANOMALOUS"
            # Check for Novel Anomaly condition:
            # High risk score, but low classifier confidence or classifier predicted Benign despite high anomaly
            if confidence < self.novel_confidence_threshold or predicted_class.upper() == "BENIGN":
                category = "Potential Novel / Unknown Anomaly"
                is_novel = True
                notes = "Potential novel network anomaly detected. Traffic deviates significantly from normal baseline, but does not match known attack signatures."
            else:
                category = f"Possible {predicted_class}"
                is_novel = False
                notes = f"Traffic signature closely matches known {predicted_class} attack patterns."

        result = {
            "status": status,
            "risk_score": round(risk_score, 3),
            "severity": severity,
            "attack_category": category,
            "confidence": round(confidence, 3),
            "is_novel_anomaly": is_novel,
            "analyst_notes": notes,
            "class_probabilities": {
                name: round(float(p), 4) for name, p in zip(self.class_names, probs[0])
            }
        }
        
        if meta_dict:
            result["metadata"] = meta_dict
            
        return result

    def evaluate_batch(
        self, 
        X_batch: np.ndarray, 
        meta_df: Optional[pd.DataFrame] = None
    ) -> List[Dict[str, Any]]:
        """Evaluate a batch of flows and return structured alerts."""
        results = []
        for i in range(len(X_batch)):
            m_dict = meta_df.iloc[i].to_dict() if meta_df is not None and i < len(meta_df) else None
            res = self.evaluate_flow(X_batch[i:i+1], meta_dict=m_dict)
            results.append(res)
        return results
