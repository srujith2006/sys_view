# Quantum-Enhanced Network Intrusion and Malware Anomaly Detection System (QE-NIDS)

A defensive cybersecurity prototype that integrates **Classical Machine Learning** (Isolation Forest + Random Forest) with **Quantum Machine Learning** (Qiskit Quantum Feature Maps + Quantum Kernel Support Vector Classifiers) to detect malicious network telemetry, score risk, classify known cyberattacks, and identify **potential novel / unknown network anomalies**.

---

## 1. System Architecture

```
                     Network Traffic / Dataset (CSV)
                                   │
                                   ▼
                   Schema Mapping & Data Cleaning
             (Drop inf/nulls, duplicates, metadata split)
                                   │
                                   ▼
                    Leak-Free Preprocessing Layer
           (StandardScaler, Categorical/Label Encoding fitted on Train only)
                                   │
                                   ▼
                      Feature Reduction Pipeline
                     (Feature Selection + PCA)
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
     Classical Feature Vector               Reduced Quantum Vector
         (10–16 features)                       (4–8 features)
                │                                     │
        ┌───────┴───────┐                             ▼
        │               │                     Quantum Feature Map
        ▼               ▼                     (zz_feature_map / z_feature_map)
   Isolation       Random Forest                      │
    Forest         Classifier                         ▼
(Unsupervised)     (Supervised)               Quantum Kernel
        │               │                 (FidelityQuantumKernel)
        │               │                             │
        └───────┬───────┘                             ▼
                │                             Quantum Kernel SVM (QSVC)
                │                                     │
                └──────────────────┬──────────────────┘
                                   │
                                   ▼
                         Model Comparison Engine
                 (Metrics, Latencies, PR-AUC, ROC-AUC)
                                   │
                                   ▼
                       Multi-Tier Decision Logic
               (Normal vs Known Attack vs Novel Anomaly)
                                   │
                                   ▼
                     SOC Dashboard (Streamlit)
       (Overview KPIs, Flow Inspector, Alerts Table, Streaming Simulation)
```

---

## 2. Key Capabilities

1. **Unsupervised Anomaly Detection & Calibrated Risk Scoring**:
   - Isolation Forest maps complex telemetry into normalized risk scores:
     - `0.00 – 0.30`: **NORMAL** (Benign baseline)
     - `0.30 – 0.60`: **LOW** Suspicion
     - `0.60 – 0.80`: **MEDIUM** / Suspicious
     - `0.80 – 0.90`: **HIGH** Risk
     - `0.90 – 1.00`: **CRITICAL** Risk

2. **Known Attack Classification**:
   - Multi-class classifier trained on benchmark categories (e.g. `DDoS`, `PortScan`, `BruteForce`, `Botnet`, `Infiltration`).
   - Produces class probability distributions and decision confidence scores.

3. **Unknown / Novel Anomaly Discovery Engine**:
   - Dual-engine arbitration: when traffic shows an elevated anomaly score ($R > 0.65$) but the classifier confidence is low ($C < 0.60$) or diverges from known signatures, it is classified as:
     `"POTENTIAL NOVEL / UNKNOWN ANOMALY"`
     *"Potential novel network anomaly detected. Traffic deviates significantly from normal baseline, but does not match known attack signatures."*

4. **Quantum Machine Learning Component (Qiskit 2.x)**:
   - Uses `zz_feature_map` and `z_feature_map` to project reduced PCA telemetry angles $\theta_i \in [0, \pi]$ into $2^n$-dimensional Hilbert space.
   - Computes inner-product quantum kernel matrices:
     $$K(x_i, x_j) = |\langle \psi(x_i) | \psi(x_j) \rangle|^2$$
   - Trains Quantum Kernel Support Vector Classifiers (`QSVC`) with probability calibration.

5. **Honest, Empirical Research Comparison**:
   - Compares Classical ML vs Quantum ML across Accuracy, Precision, Recall, F1, False Positive Rate (FPR), PR-AUC, ROC-AUC, training time, and per-sample inference latency.
   - Transparently highlights where Classical ML dominates (speed, feature scalability) and where QML shows unique kernel boundary characteristics.

6. **Grounded Explainability**:
   - Statistical z-score attribution against learned benign baselines to generate human-readable SOC narratives (e.g. *12.4x normal packet rate, abnormal flow duration, elevated SYN flags*).

7. **Two Operational Modes**:
   - **Mode 1 — Dataset Analysis**: Upload custom CSVs (CIC-IDS2017, UNSW-NB15, or NetFlow) and run batch classification.
   - **Mode 2 — Real-Time Streaming Simulation**: Continuous live flow playback for live SOC operations center demonstration with interactive novel attack injection.

---

## 3. Project Structure

```text
quantum_ids/
├── data/
│   ├── raw/                      # Raw dataset storage (CIC-IDS2017 sample CSV)
│   └── processed/                # Preprocessed split datasets
├── preprocessing/
│   ├── cleaning.py               # Missing, inf, and duplicate cleaning
│   ├── encoding.py               # Schema detection, metadata split, leak-free pipeline
│   └── feature_reduction.py      # SelectKBest and PCA for classical and quantum vectors
├── classical_ml/
│   ├── anomaly_detection.py      # Unsupervised Isolation Forest and risk scoring
│   ├── classification.py         # Supervised attack classifier and hybrid decision engine
│   └── evaluation.py             # Metrics calculation (Accuracy, F1, FPR, ROC-AUC, PR-AUC)
├── quantum_ml/
│   ├── feature_map.py            # Qiskit feature maps and ASCII circuit visualizer
│   ├── quantum_kernel.py         # Fidelity and statevector quantum kernel engine
│   ├── qml_classifier.py         # Quantum Kernel SVM (QSVC) with latency profiling
│   └── evaluation.py             # Classical vs Quantum comparative benchmarking
├── explainability/
│   └── explainer.py              # Feature deviation z-score attributions and narratives
├── simulation/
│   └── traffic_generator.py      # Real-time network flow simulator with attack injection
├── dashboard/
│   └── app.py                    # High-fidelity dark-themed Streamlit SOC console
├── models/                       # Serialized joblib models and benchmark reports
├── utils/
│   ├── config.py                 # Central configuration, risk brackets, and schemas
│   └── dataset_generator.py      # Realistic CIC-IDS2017 telemetry generator
├── tests/
│   ├── test_preprocessing.py     # Data cleaning and pipeline tests
│   ├── test_classical_ml.py      # Classical ML and hybrid decision tests
│   └── test_quantum_ml.py        # Qiskit quantum kernel and QSVC tests
├── train.py                      # Master pipeline training CLI
├── requirements.txt              # Pinned environment dependencies
└── README.md                     # Documentation and run guide
```

---

## 4. How to Download & Run (For Anyone / Any Device)

### 📱 Android Mobile: Install the APK directly

1. Go to the [Releases](https://github.com/srujith2006/sys_view/releases) section of this repository.
2. Download **`QE-NIDS-ThreatGuard.apk`** on your Android phone.
3. Tap the file to install (allow "Install unknown apps" if prompted).
4. Enjoy the native **Flutter Material 3 Cyber-SOC UI** with live risk scores, simulated attack injection, and push notifications!

---

### 💻 Windows PC: 1-Click Launch (Recommended for Everyone)

1. **Download the Repository**:
   - Go to [https://github.com/srujith2006/sys_view](https://github.com/srujith2006/sys_view).
   - Click the green **`<> Code`** button at the top right, then click **`Download ZIP`**.
   - Extract the downloaded ZIP file to any folder on your computer.

2. **Ensure Python is Installed**:
   - Download & install [Python 3.10+](https://www.python.org/downloads/) (tick **"Add python.exe to PATH"** during setup).

3. **Start the App (Double-Click)**:
   - **For SOC Dashboard & Visual Threat Monitor**:
     Double-click **`start_app.bat`**.
     *(This automatically installs dependencies and opens the web dashboard at `http://localhost:8501`).*
   - **For Low-Power Background Inspection**:
     Double-click **`start_background_monitor.bat`**.
     *(Runs silently in background, consumes <0.1% idle CPU, and pops native Windows desktop toast notifications when threats appear).*

---

### Method 2: Git Clone (For Developers)

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/srujith2006/sys_view.git
   cd sys_view
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Dashboard**:
   ```bash
   streamlit run dashboard/app.py
   ```

4. **Run the Low-Power Background Sniffer**:
   ```bash
   python agent/low_power_monitor.py
   ```

5. **Run the REST API**:
   ```bash
   python api/server.py
   ```

6. **Run Automated Unit Tests**:
   ```bash
   python -m unittest discover tests
   ```

> **Note**: All ML/DL/QML models are already pre-trained in the `models/` directory, so users can run predictions and real-time simulations immediately without needing to re-train!

---

### Optional: Re-train All Models from Scratch
If you want to re-train the classical, deep learning, and quantum models on new data:
```bash
python train.py --samples 2500 --qubits 4 --qml-samples 400
```

---

## 5. Defensive Cybersecurity Boundary & Scope

- **Telemetry Only**: The system analyzes network flow metadata/telemetry (packet sizes, flow duration, inter-arrival times, TCP flags); it does **not** inspect malware binary executables.
- **Defensive Boundary**: No malware generation, exploit code, payload execution, or credential extraction tools are included.
- **Decision Support**: Risk scores and confidence values are probabilistic model indicators intended to assist human SOC analysts in alert prioritization, not mathematical certainties.
