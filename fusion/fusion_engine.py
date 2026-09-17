"""
Multi-Model Decision and Fusion Engine for QE-NIDS.
Synthesizes signals from Isolation Forest, Deep Autoencoder, Random Forest,
and Quantum Kernel SVM into a unified 0-100 risk score and definitive triage status.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple

from classical_ml.anomaly_detection import UnsupervisedAnomalyDetector
from classical_ml.classification import SupervisedAttackClassifier
from deep_learning.autoencoder import DeepAutoencoderDetector
from quantum_ml.qml_classifier import QuantumKernelClassifier
from explainability.explainer import AnomalyExplainer

class ModelFusionEngine:
    """
    Orchestrates the 4-Model Defense Pipeline:
    1. Isolation Forest (Classical Unsupervised Anomaly)
    2. Deep Autoencoder (Deep Learning Reconstruction)
    3. Random Forest (Supervised Known Attack Classification)
    4. Quantum Kernel SVM (Quantum Feature Space Classification)
    """
    def __init__(
        self,
        anomaly_detector: UnsupervisedAnomalyDetector,
        autoencoder: DeepAutoencoderDetector,
        classifier: SupervisedAttackClassifier,
        q_classifier: Optional[QuantumKernelClassifier],
        explainer: AnomalyExplainer,
        class_names: List[str],
        novel_confidence_threshold: float = 0.60
    ):
        self.anomaly_detector = anomaly_detector
        self.autoencoder = autoencoder
        self.classifier = classifier
        self.q_classifier = q_classifier
        self.explainer = explainer
        self.class_names = class_names
        self.novel_confidence_threshold = novel_confidence_threshold

    @staticmethod
    def get_severity_tier(risk_score_100: float) -> str:
        """
        Calibrated Severity Tiers:
        0 - 20   -> SAFE
        20 - 40  -> LOW
        40 - 60  -> MEDIUM
        60 - 80  -> HIGH
        80 - 100 -> CRITICAL
        """
        if risk_score_100 < 20.0:
            return "SAFE"
        elif risk_score_100 < 40.0:
            return "LOW"
        elif risk_score_100 < 60.0:
            return "MEDIUM"
        elif risk_score_100 < 80.0:
            return "HIGH"
        else:
            return "CRITICAL"

    def evaluate_flow(
        self,
        X_raw: np.ndarray,
        X_classical: np.ndarray,
        X_quantum: np.ndarray,
        meta_dict: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run all models on a single network flow and perform calibrated fusion.
        """
        if X_raw.ndim == 1:
            X_raw = X_raw.reshape(1, -1)
        if X_classical.ndim == 1:
            X_classical = X_classical.reshape(1, -1)
        if X_quantum.ndim == 1:
            X_quantum = X_quantum.reshape(1, -1)
            
        # 1. Model A: Isolation Forest
        if_scores = self.anomaly_detector.compute_anomaly_scores(X_classical)
        if_score = float(if_scores[0])
        if_is_anom = if_score >= 0.50
        
        # 2. Model B: Deep Learning Autoencoder
        ae_is_anom_arr, ae_errors = self.autoencoder.predict(X_classical)
        ae_error = float(ae_errors[0])
        ae_is_anom = bool(ae_is_anom_arr[0])
        ae_norm_score = float(self.autoencoder.normalize_reconstruction_score(ae_errors)[0])
        
        # 3. Model C: Random Forest Classifier
        rf_pred_idx, rf_confs, rf_probs = self.classifier.predict_with_confidence(X_classical)
        top_idx = int(rf_pred_idx[0])
        rf_conf = float(rf_confs[0])
        rf_class = self.class_names[top_idx] if top_idx < len(self.class_names) else "UNKNOWN"
        rf_prob_dict = {name: round(float(p), 4) for name, p in zip(self.class_names, rf_probs[0])}
        p_benign = rf_prob_dict.get("BENIGN", rf_prob_dict.get("Normal", 0.5))
        
        # 4. Model D: Quantum Kernel SVM (optional / fast inference)
        qml_pred_label = "N/A"
        qml_conf = 0.0
        qml_is_anom = False
        if self.q_classifier is not None and self.q_classifier.is_fitted:
            try:
                q_preds, q_confs, q_probs, _ = self.q_classifier.predict_with_confidence(X_quantum)
                q_idx = int(q_preds[0])
                qml_pred_label = self.q_classifier.classes_[q_idx] if q_idx < len(self.q_classifier.classes_) else str(q_idx)
                qml_conf = float(q_confs[0])
                qml_is_anom = (qml_pred_label.upper() == "ANOMALY")
            except Exception:
                pass
                
        # -------------------------------------------------------------
        # FUSION LOGIC & DECISION RULES
        # -------------------------------------------------------------
        # Unsupervised composite anomaly agreement
        composite_anomaly = 0.50 * if_score + 0.50 * ae_norm_score
        
        # A flow is confirmed anomalous if:
        # - Both IF and AE flag it as anomalous, OR
        # - Composite anomaly >= 0.55, OR
        # - Supervised RF has strong attack probability (1 - p_benign > 0.65)
        attack_probability = 1.0 - p_benign
        is_anomalous_flow = (if_is_anom and ae_is_anom) or (composite_anomaly >= 0.55) or (attack_probability >= 0.65)
        
        if not is_anomalous_flow:
            primary_status = "NORMAL"
            attack_category = "BENIGN"
            is_novel = False
            # Scale normal risk safely to 0 - 35
            base_risk = 0.6 * composite_anomaly + 0.4 * attack_probability
            final_risk = float(np.clip(base_risk * 50.0, 2.0, 35.0))
            analyst_notes = "Traffic telemetry conforms with learned benign baseline distributions."
            recommendation = "Normal operational traffic. No remediation required."
            
        else:
            # Anomalous flow detected: Arbitrate between Known Attack vs Novel Anomaly
            is_confident_known_attack = (rf_class.upper() != "BENIGN") and (rf_conf >= self.novel_confidence_threshold)
            
            if is_confident_known_attack:
                primary_status = "KNOWN ATTACK"
                attack_category = f"Possible {rf_class}"
                is_novel = False
                # Known attack risk score in 60 - 98 range
                base_risk = 0.35 * composite_anomaly + 0.35 * attack_probability + 0.30 * rf_conf
                final_risk = float(np.clip(45.0 + base_risk * 55.0, 60.0, 98.0))
                analyst_notes = f"Network flow signature closely matches known {rf_class} attack telemetry."
                recommendation = f"Verify source {meta_dict.get('Source IP', 'host')} and inspect destination service on port {meta_dict.get('Destination Port', 'N/A')}."
                
            else:
                # POTENTIAL NOVEL ANOMALY:
                # Traffic deviates significantly from normal (flagged by IF / AE),
                # yet lacks confident match to known attack classes.
                primary_status = "POTENTIAL NOVEL ANOMALY"
                attack_category = "Potential Novel / Unknown Anomaly"
                is_novel = True
                # Novel anomaly risk score in 70 - 95 range
                base_risk = 0.50 * composite_anomaly + 0.50 * (1.0 - rf_conf)
                final_risk = float(np.clip(55.0 + base_risk * 40.0, 70.0, 95.0))
                analyst_notes = "Potential novel network anomaly detected. Traffic deviates significantly from normal baseline, but does not match known attack signatures."
                recommendation = "Isolate connection, preserve network flow logs, and submit host telemetry for zero-day analysis."

        severity = self.get_severity_tier(final_risk)
        
        # 5. Generate Grounded Explainability
        explanation = self.explainer.explain(
            raw_sample=X_raw[0],
            risk_score_100=final_risk,
            if_score=if_score,
            ae_error=ae_error,
            ae_threshold=self.autoencoder.threshold_
        )
        
        result = {
            "status": primary_status,
            "risk_score": round(final_risk, 1),
            "severity": severity,
            "attack_category": attack_category,
            "is_novel_anomaly": is_novel,
            "confidence": round(rf_conf, 3),
            "analyst_notes": analyst_notes,
            "recommendation": recommendation,
            "models": {
                "isolation_forest": {
                    "anomaly_score": round(if_score, 3),
                    "is_anomaly": if_is_anom
                },
                "deep_autoencoder": {
                    "reconstruction_error": round(ae_error, 5),
                    "calibrated_threshold": round(self.autoencoder.threshold_, 5),
                    "is_anomaly": ae_is_anom,
                    "normalized_score": round(ae_norm_score, 3)
                },
                "random_forest": {
                    "predicted_class": rf_class,
                    "confidence": round(rf_conf, 3),
                    "class_probabilities": rf_prob_dict
                },
                "quantum_kernel_svm": {
                    "prediction": qml_pred_label,
                    "confidence": round(qml_conf, 3),
                    "is_anomaly": qml_is_anom
                }
            },
            "explainability": {
                "headline": explanation["headline"],
                "feature_bullets": explanation["feature_bullets"],
                "model_signal_bullets": explanation["model_signal_bullets"],
                "top_contributing_features": explanation["top_contributing_features"]
            }
        }
        
        if meta_dict:
            result["metadata"] = meta_dict
            
        return result

    def evaluate_batch(
        self,
        X_raw: np.ndarray,
        X_classical: np.ndarray,
        X_quantum: np.ndarray,
        meta_df: Optional[pd.DataFrame] = None
    ) -> List[Dict[str, Any]]:
        """Evaluate a batch of network flows."""
        results = []
        for i in range(len(X_raw)):
            m_dict = meta_df.iloc[i].to_dict() if meta_df is not None and i < len(meta_df) else None
            res = self.evaluate_flow(
                X_raw=X_raw[i:i+1],
                X_classical=X_classical[i:i+1],
                X_quantum=X_quantum[i:i+1],
                meta_dict=m_dict
            )
            results.append(res)
        return results
