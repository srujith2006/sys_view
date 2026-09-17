"""
Leave-One-Attack-Class-Out (LOACO) Empirical Research Experiment.
Evaluates how effectively the Deep Autoencoder, Isolation Forest, and Fusion Engine
detect unseen/zero-day attack classes as Novel Anomalies when completely withheld from training.
"""

import os
import sys
import json
import time
from pathlib import Path
import numpy as np
import pandas as pd
from typing import Dict, List, Any

# Path setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.config import RAW_DATA_DIR, MODELS_DIR
from preprocessing.cleaning import clean_dataset
from preprocessing.encoding import DataPipeline
from preprocessing.feature_reduction import FeatureReducer
from deep_learning.autoencoder import DeepAutoencoderDetector
from classical_ml.anomaly_detection import UnsupervisedAnomalyDetector
from classical_ml.classification import SupervisedAttackClassifier
from explainability.explainer import AnomalyExplainer
from fusion.fusion_engine import ModelFusionEngine
from utils.dataset_generator import generate_cicids2017_flows

def run_leave_one_out_experiment(
    data_path: str = None,
    candidate_classes: List[str] = ["DDoS", "PortScan", "BruteForce", "Botnet"],
    n_samples: int = 2500,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Run Leave-One-Attack-Class-Out benchmark.
    For each candidate attack class, withhold it from training and test whether
    unsupervised Autoencoder and Isolation Forest flag it as a POTENTIAL NOVEL ANOMALY.
    """
    print("=" * 80)
    print(" CRITICAL RESEARCH EXPERIMENT: LEAVE-ONE-ATTACK-CLASS-OUT (LOACO)")
    print(" Evaluating Zero-Day & Novel Anomaly Detection Capabilities")
    print("=" * 80)
    
    # 1. Load Data
    if data_path and os.path.exists(data_path):
        df_raw = pd.read_csv(data_path)
    else:
        sample_path = RAW_DATA_DIR / "cicids2017_sample.csv"
        if sample_path.exists():
            df_raw = pd.read_csv(sample_path)
        else:
            df_raw = generate_cicids2017_flows(n_samples=n_samples, random_state=random_state)
            
    cleaned_df, _ = clean_dataset(df_raw, is_training=True)
    
    results = []
    
    for held_out_class in candidate_classes:
        print(f"\n[+] Testing Held-Out Class: '{held_out_class}' (Treated as Zero-Day / Novel Anomaly)...")
        
        # Partition data: strictly exclude held_out_class from training
        train_df = cleaned_df[cleaned_df["Label"] != held_out_class].copy().reset_index(drop=True)
        unseen_test_df = cleaned_df[cleaned_df["Label"] == held_out_class].copy().reset_index(drop=True)
        
        if len(unseen_test_df) == 0:
            print(f"    Warning: No samples found for {held_out_class}, skipping.")
            continue
            
        print(f"    Training records: {len(train_df):,} (Classes: {list(train_df['Label'].unique())})")
        print(f"    Unseen test records: {len(unseen_test_df):,} flows")
        
        # 2. Fit leak-free pipeline on train data only
        pipeline = DataPipeline(random_state=random_state).fit(train_df)
        X_train_raw, y_train_m, y_train_b, _ = pipeline.transform(train_df)
        X_unseen_raw, _, _, meta_unseen = pipeline.transform(unseen_test_df)
        
        # 3. Fit feature reducer
        reducer = FeatureReducer(n_classical_features=16, n_quantum_features=4, random_state=random_state)
        reducer.fit(X_train_raw, y_train_b, feature_names=pipeline.feature_cols)
        X_train_c, X_train_q = reducer.transform(X_train_raw)
        X_unseen_c, X_unseen_q = reducer.transform(X_unseen_raw)
        
        # Extract benign training data
        benign_mask = (train_df["Label"] == "BENIGN")
        X_benign_train_c = X_train_c[benign_mask]
        X_benign_train_raw = X_train_raw[benign_mask]
        
        # 4. Train Autoencoder strictly on benign
        ae = DeepAutoencoderDetector(input_dim=16, latent_dim=8, percentile_threshold=95.0)
        ae.fit(X_benign_train_c, epochs=25, batch_size=32, verbose=False)
        
        # 5. Train Isolation Forest strictly on benign
        iso = UnsupervisedAnomalyDetector(n_estimators=100, random_state=random_state)
        iso.fit(X_benign_train_c)
        
        # 6. Train Random Forest on train classes (does NOT know held_out_class!)
        rf = SupervisedAttackClassifier(n_estimators=60, random_state=random_state)
        rf.fit(X_train_c, y_train_m, class_names=pipeline.classes_)
        
        # 7. Fit Explainer
        explainer = AnomalyExplainer(feature_names=pipeline.feature_cols).fit(X_benign_train_raw)
        
        # 8. Assemble Fusion Engine
        fusion = ModelFusionEngine(
            anomaly_detector=iso,
            autoencoder=ae,
            classifier=rf,
            q_classifier=None,
            explainer=explainer,
            class_names=pipeline.classes_,
            novel_confidence_threshold=0.60
        )
        
        # 9. Evaluate Unseen Traffic
        t0 = time.perf_counter()
        alerts = fusion.evaluate_batch(X_unseen_raw, X_unseen_c, X_unseen_q, meta_df=meta_unseen)
        eval_time = time.perf_counter() - t0
        
        # Metric aggregation
        ae_is_anom, _ = ae.predict(X_unseen_c)
        ae_detect_rate = float(np.mean(ae_is_anom)) * 100.0
        
        iso_preds, iso_scores = iso.predict(X_unseen_c, threshold=0.50)
        iso_detect_rate = float(np.mean(iso_preds)) * 100.0
        
        novel_anomaly_count = sum(1 for a in alerts if a["status"] == "POTENTIAL NOVEL ANOMALY")
        novel_detect_rate = (novel_anomaly_count / len(alerts)) * 100.0
        
        total_flagged_anomalous = sum(1 for a in alerts if a["status"] != "NORMAL")
        overall_threat_catch_rate = (total_flagged_anomalous / len(alerts)) * 100.0
        
        avg_risk = float(np.mean([a["risk_score"] for a in alerts]))
        
        # What did RF guess?
        rf_guesses = [a["models"]["random_forest"]["predicted_class"] for a in alerts]
        top_rf_guess = pd.Series(rf_guesses).mode()[0]
        
        print(f"    --> Autoencoder Detection Rate:        {ae_detect_rate:.1f}%")
        print(f"    --> Isolation Forest Detection Rate:    {iso_detect_rate:.1f}%")
        print(f"    --> Overall Threat Catch Rate:          {overall_threat_catch_rate:.1f}%")
        print(f"    --> POTENTIAL NOVEL ANOMALY Flag Rate:  {novel_detect_rate:.1f}%")
        print(f"    --> Average Assigned Risk Score:        {avg_risk:.1f}/100")
        print(f"    --> Random Forest Forced Guess:         '{top_rf_guess}' (Model has no knowledge of {held_out_class})")
        
        results.append({
            "Held-Out Attack Class": held_out_class,
            "Sample Count": len(unseen_test_df),
            "Autoencoder Catch Rate (%)": round(ae_detect_rate, 1),
            "Isolation Forest Catch Rate (%)": round(iso_detect_rate, 1),
            "Overall Threat Detection (%)": round(overall_threat_catch_rate, 1),
            "Novel Anomaly Flagged (%)": round(novel_detect_rate, 1),
            "Mean Risk Score (0-100)": round(avg_risk, 1),
            "Forced Classifier Guess": top_rf_guess
        })
        
    df_results = pd.DataFrame(results)
    
    print("\n" + "=" * 80)
    print(" EMPIRICAL LEAVE-ONE-ATTACK-CLASS-OUT RESEARCH TABLE")
    print("=" * 80)
    print(df_results.to_string(index=False))
    print("=" * 80)
    
    # Save artifacts
    out_json = MODELS_DIR / "loaco_experiment.json"
    out_csv = MODELS_DIR / "loaco_experiment.csv"
    with open(out_json, "w") as f:
        json.dump(results, f, indent=2)
    df_results.to_csv(out_csv, index=False)
    print(f" Saved LOACO experimental benchmark to {out_json} and {out_csv}")
    
    return df_results

if __name__ == "__main__":
    run_leave_one_out_experiment()
