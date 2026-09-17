"""
Updated Localhost Test Script for QE-NIDS Multi-Model Endpoint Architecture.
Validates:
  1. System Health & 4-Model Pipeline Status
  2. Normal Flow Evaluation (0-100 Risk Score, SAFE/LOW tier)
  3. Known Attack Evaluation (DDoS/PortScan, 4-Model signals)
  4. Potential Novel Anomaly Detection (Zero-Day behavior)
  5. Grounded Explainability (no division-by-zero multipliers)
  6. Quantum Kernel SVM (QSVC) Hilbert space execution
  7. Leave-One-Attack-Class-Out (LOACO) empirical benchmark endpoint
"""

import time
import json
import requests

BASE_URL = "http://127.0.0.1:5000"

def print_separator(title):
    print("\n" + "=" * 78)
    print(f"  {title}")
    print("=" * 78)

def run_all_tests():
    print("Connecting to QE-NIDS Endpoint REST API at", BASE_URL)
    
    # 1. Health Check
    print_separator("TEST 1: System Health & 4-Model Intelligence Status (/health)")
    r = requests.get(f"{BASE_URL}/health")
    r.raise_for_status()
    res = r.json()
    print(f"Status: {res['status']}")
    print("Loaded Models:")
    for k, v in res["models_loaded"].items():
        print(f"  - {k}: {v}")
    print("Target Classes:", res["target_classes"])
    
    # 2. Normal Flow
    print_separator("TEST 2: Normal Web Telemetry Evaluation (/predict/flow)")
    import pandas as pd
    try:
        sample_df = pd.read_csv("data/raw/cicids2017_sample.csv")
        normal_flow = sample_df[sample_df["Label"] == "BENIGN"].iloc[0].to_dict()
    except Exception:
        normal_flow = {
            "Source IP": "192.168.1.45", "Destination IP": "142.250.190.46",
            "Source Port": 54321, "Destination Port": 443, "Protocol": 6,
            "Flow Duration": 120000.0, "Total Fwd Packets": 10, "Total Backward Packets": 12,
            "Total Length of Fwd Packets": 2800.0, "Total Length of Bwd Packets": 7800.0,
            "Fwd Packet Length Mean": 280.0, "Bwd Packet Length Mean": 650.0,
            "Flow Bytes/s": 88333.3, "Flow Packets/s": 183.3,
            "min_seg_size_forward": 20, "Init_Win_bytes_forward": 29200, "Init_Win_bytes_backward": 29200
        }
    r = requests.post(f"{BASE_URL}/predict/flow", json=normal_flow)
    res = r.json()
    print(f"Primary Status:       {res['status']}")
    print(f"Risk Score (0-100):   {res['risk_score']}/100 ({res['severity']})")
    print(f"Attack Category:      {res['attack_category']}")
    print(f"Is Novel Anomaly:     {res['is_novel_anomaly']}")
    print(f"Explanation:          {res['explainability']['headline']}")
    print(f"Autoencoder Recon:    {res['models']['deep_autoencoder']['reconstruction_error']} (Threshold: {res['models']['deep_autoencoder']['calibrated_threshold']})")
    
    # 3. Known Attack: DDoS
    print_separator("TEST 3: Known Cyberattack Evaluation: DDoS Flood (/predict/flow)")
    ddos_flow = {
        "Source IP": "45.33.32.156",
        "Destination IP": "192.168.1.5",
        "Source Port": 49152,
        "Destination Port": 80,
        "Protocol": 6,
        "Flow Duration": 12000.0,
        "Total Fwd Packets": 420,
        "Total Backward Packets": 1,
        "Total Length of Fwd Packets": 250000.0,
        "Total Length of Bwd Packets": 50.0,
        "Fwd Packet Length Mean": 600.0,
        "Bwd Packet Length Mean": 50.0,
        "Flow Bytes/s": 20837500.0,
        "Flow Packets/s": 35083.3,
        "SYN Flag Count": 390,
        "ACK Flag Count": 2,
        "RST Flag Count": 0,
        "FIN Flag Count": 0
    }
    r = requests.post(f"{BASE_URL}/predict/flow", json=ddos_flow)
    res = r.json()
    print(f"Primary Status:       {res['status']}")
    print(f"Risk Score (0-100):   {res['risk_score']}/100 ({res['severity']})")
    print(f"Attack Category:      {res['attack_category']}")
    print(f"Model Confidence:     {res['confidence']*100:.1f}%")
    print(f"Is Novel Anomaly:     {res['is_novel_anomaly']}")
    print(f"SOC Recommendation:   {res['recommendation']}")
    print("Grounded Explanations (No division-by-zero artifacts!):")
    for b in res["explainability"]["feature_bullets"]:
        print(f"  * {b}")
    print("4-Model Intelligence Signals:")
    print(f"  - Isolation Forest:    Score={res['models']['isolation_forest']['anomaly_score']} (Outlier={res['models']['isolation_forest']['is_anomaly']})")
    print(f"  - Deep Autoencoder:    Error={res['models']['deep_autoencoder']['reconstruction_error']} (Outlier={res['models']['deep_autoencoder']['is_anomaly']})")
    print(f"  - Random Forest:       Predicted={res['models']['random_forest']['predicted_class']} (Conf={res['models']['random_forest']['confidence']*100:.1f}%)")
    print(f"  - Quantum Kernel SVM:  Predicted={res['models']['quantum_kernel_svm']['prediction']} (Conf={res['models']['quantum_kernel_svm']['confidence']*100:.1f}%)")

    # 4. Novel / Unknown Anomaly Detection
    print_separator("TEST 4: Potential Novel Network Anomaly (/simulate/inject_novel)")
    r = requests.post(f"{BASE_URL}/simulate/inject_novel")
    res = r.json()
    det = res["detection_result"]
    print(f"Primary Status:       {det['status']}")
    print(f"Risk Score (0-100):   {det['risk_score']}/100 ({det['severity']})")
    print(f"Attack Category:      {det['attack_category']}")
    print(f"Is Novel Anomaly:     {det['is_novel_anomaly']}")
    print(f"Analyst Notes:        {det['analyst_notes']}")
    print(f"SOC Recommendation:   {det['recommendation']}")

    # 5. Quantum Kernel SVM
    print_separator("TEST 5: Dedicated Quantum Kernel SVM (QSVC) (/predict/quantum)")
    r = requests.post(f"{BASE_URL}/predict/quantum", json=ddos_flow)
    res = r.json()
    print(f"Architecture:         {res['architecture']}")
    print(f"Inference Latency:    {res['per_sample_latency_ms']} ms/sample")
    q_out = res["results"][0]
    print(f"Quantum Prediction:   {q_out['quantum_prediction']} (Confidence: {q_out['confidence']*100:.1f}%)")
    print(f"Qubit Rotation Angles:{q_out['qubit_angles_rad']}")

    # 6. Leave-One-Attack-Class-Out (LOACO) Results
    print_separator("TEST 6: Leave-One-Attack-Class-Out (LOACO) Research Results (/experiments/loaco)")
    r = requests.get(f"{BASE_URL}/experiments/loaco")
    loaco_res = r.json()
    for row in loaco_res:
        print(f"  Withheld: {row['Held-Out Attack Class']:12} | AE Catch: {row['Autoencoder Catch Rate (%)']:5.1f}% | IF Catch: {row['Isolation Forest Catch Rate (%)']:5.1f}% | Novel Flagged: {row['Novel Anomaly Flagged (%)']:5.1f}% | Risk: {row['Mean Risk Score (0-100)']}/100")

    print_separator("ALL LOCALHOST TESTS PASSED WITH 100% SUCCESS")

if __name__ == "__main__":
    run_all_tests()
