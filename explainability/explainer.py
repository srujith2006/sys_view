"""
Enhanced Grounded Explainability Module for SOC Alerts.
Provides statistically robust feature attributions, eliminates near-zero ratio artifacts,
and formats bulleted, actionable incident summaries for security operations teams.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
import joblib

FEATURE_HUMAN_NAMES = {
    "Flow Duration": "Connection Duration",
    "Total Fwd Packets": "Forward Packet Count",
    "Total Backward Packets": "Backward Packet Count",
    "Total Length of Fwd Packets": "Forward Data Payload (Bytes)",
    "Total Length of Bwd Packets": "Backward Data Payload (Bytes)",
    "Fwd Packet Length Mean": "Average Forward Packet Size",
    "Bwd Packet Length Mean": "Average Backward Packet Size",
    "Flow Bytes/s": "Network Bandwidth Throughput",
    "Flow Packets/s": "Packet Rate per Second",
    "Flow IAT Mean": "Packet Inter-Arrival Time Mean",
    "SYN Flag Count": "SYN Connection Flags",
    "ACK Flag Count": "ACK Acknowledgment Flags",
    "RST Flag Count": "RST Connection Reset Flags",
    "PSH Flag Count": "PSH Push Transfer Flags",
    "FIN Flag Count": "FIN Connection Termination Flags",
    "Average Packet Size": "Mean Packet Size",
    "Down/Up Ratio": "Bidirectional Flow Ratio"
}

class AnomalyExplainer:
    """
    Computes grounded statistical feature attributions relative to benign baseline distributions.
    Prevents division-by-zero ratio spikes and incorporates autoencoder reconstruction errors.
    """
    def __init__(self, feature_names: List[str]):
        self.feature_names = feature_names
        self.baseline_means_: Optional[np.ndarray] = None
        self.baseline_stds_: Optional[np.ndarray] = None
        self.is_fitted: bool = False

    def fit(self, X_benign: np.ndarray) -> "AnomalyExplainer":
        """
        Compute robust baseline distribution statistics strictly from benign network flows.
        """
        X = np.asarray(X_benign, dtype=np.float64)
        self.baseline_means_ = np.mean(X, axis=0)
        self.baseline_stds_ = np.std(X, axis=0)
        self.is_fitted = True
        return self

    def explain(
        self,
        raw_sample: np.ndarray,
        risk_score_100: float,
        if_score: float = 0.0,
        ae_error: Optional[float] = None,
        ae_threshold: Optional[float] = None,
        feature_ae_errors: Optional[np.ndarray] = None,
        top_k: int = 4
    ) -> Dict[str, Any]:
        """
        Generate grounded, bulleted explanation and feature attribution table for SOC analysts.
        """
        if not self.is_fitted:
            raise ValueError("AnomalyExplainer must be fitted on benign baseline first.")
            
        sample = np.asarray(raw_sample, dtype=np.float64).ravel()
        n_feats = min(len(sample), len(self.feature_names))
        sample = sample[:n_feats]
        means = self.baseline_means_[:n_feats]
        stds = self.baseline_stds_[:n_feats]
        
        # Calculate robust z-scores with variance smoothing
        safe_stds = np.where(stds > 1e-4, stds, np.maximum(np.abs(means) * 0.1, 1.0))
        z_scores = (sample - means) / safe_stds
        # Clip extreme statistical outliers to [-15, +15] for stable UI rendering
        z_scores_clipped = np.clip(z_scores, -15.0, 15.0)
        abs_z = np.abs(z_scores_clipped)
        
        # Rank by statistical significance
        ranked_indices = np.argsort(abs_z)[::-1]
        
        attributions = []
        narrative_bullets = []
        
        for idx in ranked_indices:
            feat_raw_name = self.feature_names[idx]
            human_name = FEATURE_HUMAN_NAMES.get(feat_raw_name, feat_raw_name)
            act_val = float(sample[idx])
            mean_val = float(means[idx])
            delta = act_val - mean_val
            z_val = float(z_scores_clipped[idx])
            
            # Meaningful deviation filter: |z| >= 1.75
            if abs(z_val) >= 1.75:
                # Format friendly narrative description without meaningless huge multipliers
                if abs(mean_val) < 1.0:
                    # Near-zero baseline: report absolute delta
                    if act_val > mean_val:
                        desc = f"{human_name} significantly above normal (observed: {act_val:.1f} vs normal: {mean_val:.2f}, +{delta:.1f})"
                    else:
                        desc = f"{human_name} significantly suppressed (observed: {act_val:.1f} vs normal: {mean_val:.2f})"
                else:
                    # Non-zero baseline: report percentage change
                    pct_diff = (delta / abs(mean_val)) * 100.0
                    if pct_diff > 0:
                        desc = f"{human_name} elevated by {pct_diff:+.1f}% above benign baseline (observed: {act_val:,.1f} vs normal: {mean_val:,.1f})"
                    else:
                        desc = f"{human_name} decreased by {abs(pct_diff):.1f}% below benign baseline (observed: {act_val:,.1f} vs normal: {mean_val:,.1f})"
                        
                severity_level = "CRITICAL" if abs(z_val) >= 4.0 else ("HIGH" if abs(z_val) >= 2.5 else "MODERATE")
                
                attributions.append({
                    "Feature": human_name,
                    "Technical Name": feat_raw_name,
                    "Actual Value": round(act_val, 2),
                    "Benign Baseline Mean": round(mean_val, 2),
                    "Deviation (Δ)": round(delta, 2),
                    "Z-Score": round(z_val, 2),
                    "Impact": severity_level
                })
                
                if len(narrative_bullets) < top_k:
                    narrative_bullets.append(desc)

        # High-level model signal summaries
        model_signal_bullets = []
        if ae_error is not None and ae_threshold is not None:
            if ae_error > ae_threshold:
                model_signal_bullets.append(
                    f"Deep Autoencoder reconstruction error ({ae_error:.4f}) exceeds the calibrated 95th percentile threshold ({ae_threshold:.4f}), signaling unlearned structural behavior."
                )
            else:
                model_signal_bullets.append(
                    f"Deep Autoencoder reconstruction error ({ae_error:.4f}) conforms with learned benign flow profiles."
                )
                
        if if_score >= 0.50:
            model_signal_bullets.append(
                f"Isolation Forest flags flow as an unsupervised topological outlier (anomaly score: {if_score:.2f})."
            )
            
        # Compile comprehensive narrative summary
        if risk_score_100 < 30:
            headline = "Flow telemetry closely aligns with normal benign operational baselines. No anomalous deviations detected."
        else:
            headline = f"Threat detection flagged with Risk Score {risk_score_100:.0f}/100 based on the following corroborating factors:"
            
        return {
            "headline": headline,
            "feature_bullets": narrative_bullets[:top_k],
            "model_signal_bullets": model_signal_bullets,
            "top_contributing_features": attributions[:top_k],
            "full_attributions": attributions
        }

    def save(self, filepath: str):
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "AnomalyExplainer":
        return joblib.load(filepath)
