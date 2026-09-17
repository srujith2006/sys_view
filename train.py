"""
Master Pipeline Training, Deep Learning, Quantum ML, and Research Benchmarking CLI Script for QE-NIDS.
Trains:
  1. Classical Isolation Forest (Unsupervised Anomaly)
  2. Deep Learning Autoencoder (PyTorch, Benign Reconstruction)
  3. Supervised Random Forest (Multi-Class Attack Classifier)
  4. Quantum Kernel SVM (Qiskit 2.x, Hilbert Space Classifier)
  5. Multi-Model Fusion Engine (0-100 Risk Score)
  6. Leave-One-Attack-Class-Out (LOACO) Empirical Novelty Benchmark
"""

import os
import sys
import time
import json
import argparse
from pathlib import Path
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.config import (
    RAW_DATA_DIR, 
    MODELS_DIR, 
    CLASSICAL_FEATURE_COUNT, 
    QUANTUM_FEATURE_COUNT
)
from utils.dataset_generator import generate_cicids2017_flows
from preprocessing.cleaning import clean_dataset
from preprocessing.encoding import DataPipeline
from preprocessing.feature_reduction import FeatureReducer
from classical_ml.anomaly_detection import UnsupervisedAnomalyDetector
from classical_ml.classification import SupervisedAttackClassifier
from classical_ml.evaluation import evaluate_classification, evaluate_anomaly_detector
from deep_learning.autoencoder import DeepAutoencoderDetector
from quantum_ml.qml_classifier import QuantumKernelClassifier
from quantum_ml.evaluation import compare_classical_vs_quantum
from explainability.explainer import AnomalyExplainer
from fusion.fusion_engine import ModelFusionEngine
from experiments.leave_one_out import run_leave_one_out_experiment

def run_training_pipeline(
    data_path: str = None,
    n_samples: int = 2500,
    n_classical_feats: int = CLASSICAL_FEATURE_COUNT,
    num_qubits: int = QUANTUM_FEATURE_COUNT,
    qml_train_samples: int = 400,
    run_loaco: bool = True,
    random_state: int = 42
):
    print("=" * 75)
    print(" QUANTUM-ENHANCED NETWORK INTRUSION DETECTION SYSTEM (QE-NIDS)")
    print(" Master Multi-Model Training, Deep Learning & Empirical Research Pipeline")
    print("=" * 75)
    
    # 1. Dataset Loading or Generation
    if data_path and os.path.exists(data_path):
        print(f"\n[1/8] Loading dataset from: {data_path}")
        df_raw = pd.read_csv(data_path)
    else:
        sample_path = RAW_DATA_DIR / "cicids2017_sample.csv"
        if sample_path.exists():
            print(f"\n[1/8] Loading cached reference dataset from: {sample_path}")
            df_raw = pd.read_csv(sample_path)
        else:
            print(f"\n[1/8] Generating synthetic CIC-IDS2017 benchmark dataset ({n_samples} flows)...")
            df_raw = generate_cicids2017_flows(n_samples=n_samples, random_state=random_state)
            df_raw.to_csv(sample_path, index=False)
            print(f"      Saved reference data to {sample_path}")
            
    print(f"      Total records loaded: {len(df_raw):,} flows")
    
    # 2. Data Cleaning
    print("\n[2/8] Cleaning dataset (inf, null, duplicate handling)...")
    cleaned_df, clean_stats = clean_dataset(df_raw, is_training=True)
    print(f"      Cleaned records: {len(cleaned_df):,} (Infinities handled: {clean_stats['infinities_handled']}, Duplicates removed: {clean_stats['duplicates_removed']})")
    
    # 3. Leak-Free Pipeline & Stratified Split
    print("\n[3/8] Setting up leak-free DataPipeline and stratified train/val/test splits...")
    pipeline = DataPipeline(random_state=random_state)
    df_train, df_val, df_test = pipeline.split_data(cleaned_df, train_size=0.70, val_size=0.15, test_size=0.15)
    pipeline.fit(df_train)
    
    print(f"      Split distribution: Train={len(df_train)}, Val={len(df_val)}, Test={len(df_test)}")
    print(f"      Target classes: {pipeline.classes_}")
    print(f"      Preserved metadata (zero data leakage): {pipeline.metadata_cols}")
    
    # Extract feature matrices
    X_train_raw, y_train_multi, y_train_binary, meta_train = pipeline.transform(df_train)
    X_val_raw, y_val_multi, y_val_binary, meta_val = pipeline.transform(df_val)
    X_test_raw, y_test_multi, y_test_binary, meta_test = pipeline.transform(df_test)
    
    # 4. Feature Selection & Reduction
    print(f"\n[4/8] Performing feature selection (K={n_classical_feats}) and PCA for Quantum ML ({num_qubits} qubits)...")
    reducer = FeatureReducer(
        n_classical_features=n_classical_feats,
        n_quantum_features=num_qubits,
        random_state=random_state
    )
    reducer.fit(X_train_raw, y_train_binary, feature_names=pipeline.feature_cols)
    
    X_train_c, X_train_q = reducer.transform(X_train_raw)
    X_val_c, X_val_q = reducer.transform(X_val_raw)
    X_test_c, X_test_q = reducer.transform(X_test_raw)
    
    pca_summary = reducer.get_summary()
    print(f"      Top selected features: {', '.join(pca_summary['selected_features'][:5])}...")
    print(f"      PCA explained variance ({num_qubits} qubits): {pca_summary['total_variance_explained']*100:.2f}%")
    
    # 5. Train Classical ML Baseline Models
    print("\n[5/8] Training Classical ML Baseline models...")
    # Model A: Isolation Forest (Unsupervised)
    t0 = time.perf_counter()
    anomaly_detector = UnsupervisedAnomalyDetector()
    anomaly_detector.fit(X_train_c)
    if_train_time = time.perf_counter() - t0
    print(f"      [Model A: Isolation Forest] Trained in {if_train_time:.3f}s")
    
    # Model C: Random Forest Multi-Class Classifier
    t0 = time.perf_counter()
    clf = SupervisedAttackClassifier(random_state=random_state)
    clf.fit(X_train_c, y_train_multi, class_names=pipeline.classes_)
    rf_train_time = time.perf_counter() - t0
    print(f"      [Model C: Random Forest] Trained in {rf_train_time:.3f}s")
    
    # Explainability Baseline
    explainer = AnomalyExplainer(feature_names=pipeline.feature_cols)
    benign_mask_train = (y_train_binary == 0)
    X_benign_train_raw = X_train_raw[benign_mask_train] if np.any(benign_mask_train) else X_train_raw
    X_benign_train_c = X_train_c[benign_mask_train] if np.any(benign_mask_train) else X_train_c
    explainer.fit(X_benign_train_raw)
    print("      [Explainability] Benign baseline distribution learned.")
    
    # 6. Train Deep Learning Autoencoder (Model B)
    print("\n[6/8] Training Deep Learning Autoencoder (Model B: Benign Reconstruction)...")
    benign_mask_val = (y_val_binary == 0)
    X_benign_val_c = X_val_c[benign_mask_val] if np.any(benign_mask_val) else X_val_c
    
    t0 = time.perf_counter()
    autoencoder = DeepAutoencoderDetector(
        input_dim=n_classical_feats,
        latent_dim=8,
        percentile_threshold=95.0
    )
    autoencoder.fit(
        X_benign_train=X_benign_train_c,
        X_benign_val=X_benign_val_c,
        epochs=35,
        batch_size=32,
        lr=1e-3,
        verbose=True
    )
    ae_train_time = time.perf_counter() - t0
    print(f"      [Model B: Deep Autoencoder] Trained in {ae_train_time:.3f}s")
    print(f"      [Model B: Deep Autoencoder] Calibrated Anomaly Threshold: {autoencoder.threshold_:.5f}")
    
    # 7. Train Quantum ML Model (Model D, Qiskit 2.x)
    print(f"\n[7/8] Training Quantum Kernel Support Vector Classifier (Model D: {num_qubits} Qubits, ZZFeatureMap)...")
    q_limit = min(qml_train_samples, len(X_train_q))
    idx_0 = np.where(y_train_binary == 0)[0]
    idx_1 = np.where(y_train_binary == 1)[0]
    n_per_class = q_limit // 2
    selected_q_idx = np.concatenate([
        np.random.choice(idx_0, min(len(idx_0), n_per_class), replace=False),
        np.random.choice(idx_1, min(len(idx_1), n_per_class), replace=False)
    ])
    np.random.shuffle(selected_q_idx)
    
    X_q_sub = X_train_q[selected_q_idx]
    y_q_sub = y_train_binary[selected_q_idx]
    
    q_clf = QuantumKernelClassifier(
        num_qubits=num_qubits,
        feature_map_type="zz",
        reps=1,
        entanglement="linear",
        C=1.0,
        random_state=random_state
    )
    q_clf.fit(X_q_sub, y_q_sub, class_names=["BENIGN", "ANOMALY"])
    print(f"      [Model D: Quantum ML] Trained on {len(X_q_sub)} quantum states in {q_clf.training_time_sec:.3f}s")
    
    # Assemble Multi-Model Fusion Engine
    fusion_engine = ModelFusionEngine(
        anomaly_detector=anomaly_detector,
        autoencoder=autoencoder,
        classifier=clf,
        q_classifier=q_clf,
        explainer=explainer,
        class_names=pipeline.classes_,
        novel_confidence_threshold=0.60
    )
    
    # 8. Evaluation, Benchmark & Serialization
    print("\n[8/8] Evaluating Models & Running Comparative Benchmark...")
    
    # Evaluate Classical RF
    t0 = time.perf_counter()
    rf_preds, rf_confs, rf_probs = clf.predict_with_confidence(X_test_c)
    rf_latency = ((time.perf_counter() - t0) * 1000.0) / len(X_test_c)
    classical_metrics = evaluate_classification(
        y_true=y_test_multi,
        y_pred=rf_preds,
        y_scores=rf_probs,
        class_names=pipeline.classes_,
        benign_idx=pipeline.benign_class_idx,
        training_time=rf_train_time,
        inference_latency_ms=rf_latency
    )
    
    # Evaluate Quantum Kernel SVM
    q_test_limit = min(300, len(X_test_q))
    X_test_q_eval = X_test_q[:q_test_limit]
    y_test_bin_eval = y_test_binary[:q_test_limit]
    t0 = time.perf_counter()
    q_preds, q_confs, q_probs, q_latency = q_clf.predict_with_confidence(X_test_q_eval)
    quantum_metrics = evaluate_classification(
        y_true=y_test_bin_eval,
        y_pred=q_preds,
        y_scores=q_probs,
        class_names=["BENIGN", "ANOMALY"],
        benign_idx=0,
        training_time=q_clf.training_time_sec,
        inference_latency_ms=q_latency
    )
    
    # Evaluate Autoencoder on Test Set
    ae_is_anom, ae_errors = autoencoder.predict(X_test_c)
    ae_tpr = float(np.mean(ae_is_anom[y_test_binary == 1])) * 100.0 if np.any(y_test_binary == 1) else 0.0
    ae_fpr = float(np.mean(ae_is_anom[y_test_binary == 0])) * 100.0 if np.any(y_test_binary == 0) else 0.0
    print(f"      [Autoencoder Benchmark] Attack Catch Rate (TPR): {ae_tpr:.1f}% | Benign False Alarm Rate (FPR): {ae_fpr:.1f}%")
    
    # Comparative table
    comparison = compare_classical_vs_quantum(
        classical_metrics=classical_metrics,
        quantum_metrics=quantum_metrics,
        model_names=("Classical Random Forest", f"Quantum Kernel SVM ({num_qubits}Q)")
    )
    
    print("\n" + "=" * 75)
    print(" BENCHMARK COMPARISON TABLE")
    print("=" * 75)
    print(comparison["comparison_table"].to_string(index=False))
    
    # Save Artifacts to models/
    print("\n" + "=" * 75)
    print(" Saving Serialized Model Artifacts to models/...")
    pipeline.save(MODELS_DIR / "pipeline.joblib")
    reducer.save(MODELS_DIR / "reducer.joblib")
    anomaly_detector.save(MODELS_DIR / "anomaly_detector.joblib")
    clf.save(MODELS_DIR / "classifier.joblib")
    explainer.save(MODELS_DIR / "explainer.joblib")
    q_clf.save(MODELS_DIR / "qml_classifier.joblib")
    autoencoder.save(str(MODELS_DIR / "autoencoder"))
    
    comparison_json = {
        "classical_metrics": classical_metrics.to_dict(),
        "quantum_metrics": quantum_metrics.to_dict(),
        "autoencoder_metrics": {
            "threshold_95": autoencoder.threshold_,
            "percentile_99": autoencoder.percentile_99_,
            "mean_benign_error": autoencoder.mean_benign_error_,
            "test_tpr": round(ae_tpr, 2),
            "test_fpr": round(ae_fpr, 2),
            "training_time_sec": round(ae_train_time, 3)
        },
        "findings": comparison["findings"],
        "pca_summary": pca_summary
    }
    with open(MODELS_DIR / "benchmark_report.json", "w") as f:
        json.dump(comparison_json, f, indent=2)
    comparison["comparison_table"].to_csv(MODELS_DIR / "benchmark_report.csv", index=False)
    print(" Core models and benchmark artifacts successfully saved!")
    
    # Run LOACO experiment if requested
    if run_loaco:
        print("\nExecuting Critical Leave-One-Attack-Class-Out (LOACO) Experiment...")
        run_leave_one_out_experiment(data_path=str(sample_path) if sample_path.exists() else None)
        
    print("\n" + "=" * 75)
    print(" ALL PIPELINE COMPONENTS COMPLETED SUCCESSFULLY!")
    print("=" * 75)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train QE-NIDS Multi-Model System")
    parser.add_argument("--data", type=str, default=None, help="Path to CSV dataset")
    parser.add_argument("--samples", type=int, default=2500, help="Number of samples if generating")
    parser.add_argument("--classical-feats", type=int, default=CLASSICAL_FEATURE_COUNT, help="Number of classical features")
    parser.add_argument("--qubits", type=int, default=QUANTUM_FEATURE_COUNT, help="Number of qubits for QML")
    parser.add_argument("--qml-samples", type=int, default=400, help="QML training sample count")
    parser.add_argument("--skip-loaco", action="store_true", help="Skip Leave-One-Attack-Class-Out experiment")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    
    args = parser.parse_args()
    run_training_pipeline(
        data_path=args.data,
        n_samples=args.samples,
        n_classical_feats=args.classical_feats,
        num_qubits=args.qubits,
        qml_train_samples=args.qml_samples,
        run_loaco=not args.skip_loaco,
        random_state=args.seed
    )
