"""
Flask Localhost REST API Server for QE-NIDS.
Enables local HTTP testing of the trained multi-model intrusion detection pipeline:
Isolation Forest, Deep Autoencoder, Random Forest, Quantum Kernel SVM,
Model Fusion Engine (0-100 Risk Scoring), and Grounded Explainability.
"""

import os
import sys
import json
from pathlib import Path

# Python 3.14 compatibility shim for Flask/Werkzeug
import pkgutil
import importlib.util
if not hasattr(pkgutil, "get_loader"):
    pkgutil.get_loader = lambda name: None if name == "__main__" else importlib.util.find_spec(name)

from flask import Flask, request, jsonify
import pandas as pd
import numpy as np

# Path setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.config import MODELS_DIR, RAW_DATA_DIR, ANOMALY_SCORE_THRESHOLD, NOVEL_ATTACK_CONFIDENCE_THRESHOLD
from preprocessing.cleaning import clean_dataset
from preprocessing.encoding import DataPipeline
from preprocessing.feature_reduction import FeatureReducer
from classical_ml.anomaly_detection import UnsupervisedAnomalyDetector
from classical_ml.classification import SupervisedAttackClassifier
from deep_learning.autoencoder import DeepAutoencoderDetector
from quantum_ml.qml_classifier import QuantumKernelClassifier
from explainability.explainer import AnomalyExplainer
from fusion.fusion_engine import ModelFusionEngine
from simulation.traffic_generator import LiveTrafficSimulator
from utils.dataset_generator import generate_cicids2017_flows

app = Flask(__name__)

MODELS = {}

def load_models():
    """Load serialized models and fusion engine."""
    pipeline_file = MODELS_DIR / "pipeline.joblib"
    reducer_file = MODELS_DIR / "reducer.joblib"
    anomaly_file = MODELS_DIR / "anomaly_detector.joblib"
    clf_file = MODELS_DIR / "classifier.joblib"
    explainer_file = MODELS_DIR / "explainer.joblib"
    q_clf_file = MODELS_DIR / "qml_classifier.joblib"
    ae_prefix = str(MODELS_DIR / "autoencoder")
    bench_file = MODELS_DIR / "benchmark_report.json"
    loaco_file = MODELS_DIR / "loaco_experiment.json"
    
    pipeline = DataPipeline.load(str(pipeline_file))
    reducer = FeatureReducer.load(str(reducer_file))
    anomaly_detector = UnsupervisedAnomalyDetector.load(str(anomaly_file))
    classifier = SupervisedAttackClassifier.load(str(clf_file))
    explainer = AnomalyExplainer.load(str(explainer_file))
    autoencoder = DeepAutoencoderDetector.load(ae_prefix)
    
    q_clf = None
    if q_clf_file.exists():
        try:
            q_clf = QuantumKernelClassifier.load(str(q_clf_file))
        except Exception:
            q_clf = None
            
    benchmark_report = None
    if bench_file.exists():
        with open(bench_file, "r") as f:
            benchmark_report = json.load(f)
            
    loaco_report = None
    if loaco_file.exists():
        with open(loaco_file, "r") as f:
            loaco_report = json.load(f)
            
    # Live simulator
    sample_file = RAW_DATA_DIR / "cicids2017_sample.csv"
    if sample_file.exists():
        df_base = pd.read_csv(sample_file)
    else:
        df_base = generate_cicids2017_flows(n_samples=1000)
    simulator = LiveTrafficSimulator(df_base)
    
    # Initialize 4-Model Fusion Engine
    fusion_engine = ModelFusionEngine(
        anomaly_detector=anomaly_detector,
        autoencoder=autoencoder,
        classifier=classifier,
        q_classifier=q_clf,
        explainer=explainer,
        class_names=pipeline.classes_,
        novel_confidence_threshold=NOVEL_ATTACK_CONFIDENCE_THRESHOLD
    )
    
    MODELS["pipeline"] = pipeline
    MODELS["reducer"] = reducer
    MODELS["anomaly_detector"] = anomaly_detector
    MODELS["autoencoder"] = autoencoder
    MODELS["classifier"] = classifier
    MODELS["explainer"] = explainer
    MODELS["q_clf"] = q_clf
    MODELS["benchmark_report"] = benchmark_report
    MODELS["loaco_report"] = loaco_report
    MODELS["simulator"] = simulator
    MODELS["fusion_engine"] = fusion_engine

load_models()

@app.route("/", methods=["GET"])
@app.route("/health", methods=["GET"])
def health():
    """Health check and model status endpoint."""
    return jsonify({
        "status": "ONLINE",
        "system": "Quantum-Enhanced Network Intrusion and Malware Anomaly Detection System (QE-NIDS)",
        "models_loaded": {
            "model_a_isolation_forest": "Isolation Forest (150 estimators)",
            "model_b_deep_autoencoder": f"Deep Autoencoder (51->32->16->8, Calibrated Threshold: {MODELS['autoencoder'].threshold_:.5f})",
            "model_c_random_forest": "Random Forest (100 estimators, multi-class)",
            "model_d_quantum_kernel_svm": f"Quantum Kernel SVM ({MODELS['reducer'].n_quantum_features} Qubits, ZZFeatureMap)" if MODELS["q_clf"] else "Not loaded",
            "fusion_engine": "Multi-Model Fusion (0-100 Calibrated Risk Score)",
            "explainability_engine": "AnomalyExplainer (Grounded statistical z-scores without near-zero ratio spikes)"
        },
        "target_classes": MODELS["pipeline"].classes_,
        "novel_confidence_threshold": MODELS["fusion_engine"].novel_confidence_threshold
    })

@app.route("/predict/flow", methods=["POST"])
def predict_flow():
    """Evaluate a single network flow record using the 4-Model Fusion Engine."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request. Must provide JSON network flow payload."}), 400
        
    df_single = pd.DataFrame([data])
    cleaned_df, _ = clean_dataset(df_single, is_training=False)
    
    X_raw, _, _, meta_df = MODELS["pipeline"].transform(cleaned_df)
    X_c, X_q = MODELS["reducer"].transform(X_raw)
    
    meta_dict = meta_df.iloc[0].to_dict() if len(meta_df) > 0 else {}
    alert = MODELS["fusion_engine"].evaluate_flow(
        X_raw=X_raw[0:1],
        X_classical=X_c[0:1],
        X_quantum=X_q[0:1],
        meta_dict=meta_dict
    )
    return jsonify(alert)

@app.route("/predict/batch", methods=["POST"])
def predict_batch():
    """Evaluate a batch of network flow records."""
    data = request.get_json(silent=True)
    if not data or not isinstance(data, list):
        return jsonify({"error": "Invalid request. Must provide JSON array of network flows."}), 400
        
    df_batch = pd.DataFrame(data)
    cleaned_df, _ = clean_dataset(df_batch, is_training=False)
    
    X_raw, _, _, meta_df = MODELS["pipeline"].transform(cleaned_df)
    X_c, X_q = MODELS["reducer"].transform(X_raw)
    
    alerts = MODELS["fusion_engine"].evaluate_batch(
        X_raw=X_raw,
        X_classical=X_c,
        X_quantum=X_q,
        meta_df=meta_df
    )
    return jsonify({
        "total_evaluated": len(alerts),
        "threats_detected": sum(1 for a in alerts if a["status"] != "NORMAL"),
        "novel_anomalies": sum(1 for a in alerts if a.get("is_novel_anomaly")),
        "alerts": alerts
    })

@app.route("/simulate/stream", methods=["GET"])
def simulate_stream():
    """Fetch next simulated network flow and return full 4-model evaluation."""
    flow_series = MODELS["simulator"].next_flow()
    flow_dict = flow_series.to_dict()
    
    df_single = pd.DataFrame([flow_dict])
    cleaned_df, _ = clean_dataset(df_single, is_training=False)
    
    X_raw, _, _, meta_df = MODELS["pipeline"].transform(cleaned_df)
    X_c, X_q = MODELS["reducer"].transform(X_raw)
    
    meta_dict = meta_df.iloc[0].to_dict() if len(meta_df) > 0 else {}
    alert = MODELS["fusion_engine"].evaluate_flow(
        X_raw=X_raw[0:1],
        X_classical=X_c[0:1],
        X_quantum=X_q[0:1],
        meta_dict=meta_dict
    )
    return jsonify({
        "raw_telemetry": {k: flow_dict[k] for k in ["Flow ID", "Source IP", "Destination IP", "Destination Port", "Protocol", "Flow Duration", "Total Fwd Packets", "SYN Flag Count", "Label"] if k in flow_dict},
        "detection_result": alert
    })

@app.route("/simulate/inject_novel", methods=["POST", "GET"])
def inject_novel():
    """Inject a synthetic novel anomaly and score it."""
    novel_series = MODELS["simulator"].inject_synthetic_novel_anomaly()
    flow_dict = novel_series.to_dict()
    
    df_single = pd.DataFrame([flow_dict])
    cleaned_df, _ = clean_dataset(df_single, is_training=False)
    
    X_raw, _, _, meta_df = MODELS["pipeline"].transform(cleaned_df)
    X_c, X_q = MODELS["reducer"].transform(X_raw)
    
    meta_dict = meta_df.iloc[0].to_dict() if len(meta_df) > 0 else {}
    alert = MODELS["fusion_engine"].evaluate_flow(
        X_raw=X_raw[0:1],
        X_classical=X_c[0:1],
        X_quantum=X_q[0:1],
        meta_dict=meta_dict
    )
    return jsonify({
        "injection_type": "SYNTHETIC_NOVEL_PROTOCOL_ANOMALY",
        "detection_result": alert
    })

@app.route("/predict/quantum", methods=["POST"])
def predict_quantum():
    """Run dedicated Quantum Kernel SVM (QSVC) inference."""
    if MODELS["q_clf"] is None:
        return jsonify({"error": "Quantum Kernel Classifier is not loaded."}), 500
        
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid request. Must provide JSON payload."}), 400
        
    df_single = pd.DataFrame([data] if isinstance(data, dict) else data)
    cleaned_df, _ = clean_dataset(df_single, is_training=False)
    
    X_raw, _, _, _ = MODELS["pipeline"].transform(cleaned_df)
    _, X_q = MODELS["reducer"].transform(X_raw)
    
    preds, confs, probs, latency = MODELS["q_clf"].predict_with_confidence(X_q)
    results = []
    for i in range(len(preds)):
        idx = int(preds[i])
        predicted_label = MODELS["q_clf"].classes_[idx] if idx < len(MODELS["q_clf"].classes_) else str(idx)
        results.append({
            "quantum_prediction": predicted_label,
            "confidence": round(float(confs[i]), 4),
            "class_probabilities": {
                name: round(float(p), 4) for name, p in zip(MODELS["q_clf"].classes_, probs[i])
            },
            "qubit_angles_rad": [round(float(a), 4) for a in X_q[i]]
        })
        
    return jsonify({
        "architecture": f"Quantum Kernel SVM ({MODELS['reducer'].n_quantum_features} Qubits, ZZFeatureMap)",
        "per_sample_latency_ms": round(latency, 3),
        "results": results
    })

@app.route("/benchmark", methods=["GET"])
def benchmark():
    """Return Classical vs Quantum ML benchmark report."""
    if MODELS["benchmark_report"] is None:
        return jsonify({"error": "Benchmark report not found."}), 404
    return jsonify(MODELS["benchmark_report"])

@app.route("/experiments/loaco", methods=["GET"])
def loaco_report():
    """Return Leave-One-Attack-Class-Out empirical novelty benchmark results."""
    if MODELS["loaco_report"] is None:
        return jsonify({"error": "LOACO experiment report not found."}), 404
    return jsonify(MODELS["loaco_report"])

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting QE-NIDS Localhost REST API on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)
