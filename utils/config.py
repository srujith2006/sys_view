"""
Central Configuration for Quantum-Enhanced Network Intrusion Detection System (QE-NIDS)
"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = BASE_DIR / "models"

os.makedirs(RAW_DATA_DIR, exist_ok=True)
os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)

# Risk Thresholds
RISK_THRESHOLDS = {
    "NORMAL": (0.00, 0.30),
    "LOW": (0.30, 0.60),
    "MEDIUM": (0.60, 0.80),
    "HIGH": (0.80, 0.90),
    "CRITICAL": (0.90, 1.00),
}

# Anomaly and Novel Attack Thresholds
ANOMALY_SCORE_THRESHOLD = 0.50       # Unsupervised Isolation Forest threshold for anomaly (decision_function <= 0)
NOVEL_ATTACK_CONFIDENCE_THRESHOLD = 0.60  # Supervised confidence below which an anomaly is flagged novel

# Known Attack Categories (CIC-IDS2017 standard benchmark classes)
ATTACK_CLASSES = [
    "BENIGN",
    "DDoS",
    "PortScan",
    "BruteForce",
    "Botnet",
    "Infiltration",
]

# Dataset Column Mappings (Schema Agnostic Layer)
DATASET_SCHEMAS = {
    "CIC-IDS2017": {
        "metadata": [
            "Flow ID", "Source IP", "Source Port", "Destination IP",
            "Destination Port", "Protocol", "Timestamp"
        ],
        "label": "Label",
        "features": [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
            "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
            "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
            "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Bwd IAT Total",
            "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
            "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
            "Min Packet Length", "Max Packet Length", "Packet Length Mean",
            "Packet Length Std", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
            "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "Down/Up Ratio",
            "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
            "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
            "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
            "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Idle Mean"
        ]
    },
    "UNSW-NB15": {
        "metadata": ["srcip", "sport", "dstip", "dsport", "proto", "state"],
        "label": "attack_cat",
        "features": [
            "dur", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
            "service", "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin",
            "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
            "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt",
            "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
            "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
            "ct_src_ ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm"
        ]
    }
}

# Feature Reduction Settings
CLASSICAL_FEATURE_COUNT = 16
QUANTUM_FEATURE_COUNT = 4   # 4 to 8 qubits for quantum simulation
QUANTUM_FEATURE_MAX = 8

# Quantum Circuit Parameters
QUANTUM_CONFIG = {
    "num_qubits": 4,
    "feature_map_type": "zz",  # 'zz' or 'z'
    "reps": 1,
    "entanglement": "linear",   # 'linear' or 'full'
    "shots": None,             # Statevector exact fidelity (None) or shot-based
    "random_state": 42
}

# Classical ML Parameters
CLASSICAL_CONFIG = {
    "isolation_forest": {
        "n_estimators": 150,
        "contamination": 0.15,
        "random_state": 42
    },
    "random_forest": {
        "n_estimators": 100,
        "max_depth": 15,
        "class_weight": "balanced",
        "random_state": 42
    },
    "svm": {
        "kernel": "rbf",
        "C": 1.0,
        "probability": True,
        "random_state": 42
    }
}
