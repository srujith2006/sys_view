# QE-NIDS ThreatGuard — Android Mobile App (Flutter)

A high-fidelity, Cyber-SOC Android mobile client built with **Flutter (Material 3)** for the **Quantum-Enhanced Network Intrusion & Threat Detection System**.

---

## 📱 Features

1. **Cyber-SOC Dashboard & Animated Radial Risk Gauge**:
   - Real-time 0–100 calibrated risk scoring (`SAFE`, `LOW`, `MEDIUM`, `CRITICAL`).
   - Dynamic neon color coding (Emerald Green, Cyan, Amber, Crimson, Quantum Purple).
2. **4-Model Decision Matrix**:
   - **Random Forest**: Supervised known attack classifier.
   - **Isolation Forest**: Unsupervised statistical anomaly detector.
   - **Deep Autoencoder (PyTorch)**: Non-linear reconstruction error metric.
   - **Qiskit Quantum Kernel SVM**: Quantum Hilbert space boundary evaluation.
3. **Grounded Explainability Engine**:
   - Root-cause telemetry attribution and $z$-score deviation metrics.
4. **Consent-Based Flow Inspection**:
   - Explicit user toggle required before any flow inspection is activated.
   - **Zero Payload Inspection**: Strict privacy guarantee—only 51 flow metadata statistics are evaluated.
5. **Interactive Threat Simulation**:
   - Test attack injection buttons directly in the UI (`Normal`, `DDoS`, `PortScan`, `Novel Zero-Day`).
6. **Backend Server Integration**:
   - Syncs with the QE-NIDS Flask REST API (`api/server.py`).
   - Built-in offline fallback with local simulation if disconnected from the server.

---

## 📥 How to Download & Install the APK on Your Android Phone

### Method 1: Download from GitHub Releases (Easiest)

1. Open your browser on your Android phone and go to:
   **[https://github.com/srujith2006/sys_view/releases](https://github.com/srujith2006/sys_view/releases)**
2. Under the latest **v1.0.0-android** release, tap **`QE-NIDS-ThreatGuard.apk`** to download it.
3. Once downloaded, tap the file in your notification drawer or Downloads folder.
4. If Android asks *"For your security, your phone is not allowed to install unknown apps from this source"*:
   - Tap **Settings** -> Toggle **"Allow from this source"** ON.
5. Tap **Install** -> **Open**.

---

### Method 2: Build the APK Locally (For Developers)

If you have Flutter SDK installed on your PC:
1. Open terminal inside `mobile_app`:
   ```bash
   cd mobile_app
   flutter pub get
   flutter build apk --release
   ```
   *(Or simply double-click `build_apk.bat` on Windows).*
2. The compiled APK will be located at:
   `mobile_app/build/app/outputs/flutter-apk/app-release.apk`
3. Transfer it to your phone via USB cable, Google Drive, or WhatsApp, and install.

---

## ⚙️ Connecting the App to Your Computer's Backend Server

To connect your phone to the QE-NIDS AI/Quantum engine running on your computer:
1. Ensure your PC and Android phone are on the same Wi-Fi network.
2. Find your computer's local IP address (on Windows, run `ipconfig` in Command Prompt, look for `IPv4 Address`, e.g. `192.168.1.15`).
3. Start the QE-NIDS REST API on your PC:
   ```bash
   python api/server.py
   ```
4. Open the **QE-NIDS ThreatGuard** app on your phone:
   - Tap the **Settings icon** (top right).
   - Enter your server URL: `http://192.168.1.15:5000`.
   - Tap **Save & Test Link**.
   - Your phone will now display **"🟢 Connected"** and stream live assessments directly from your PC's 4-model engine!
