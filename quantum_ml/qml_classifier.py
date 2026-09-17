"""
Quantum Kernel Support Vector Classifier (QSVC) for Network Intrusion Detection.
Trains a Support Vector Classifier using a quantum feature map and quantum kernel.
Provides probability calibration and runtime latency profiling.
"""

import time
import numpy as np
from typing import Dict, List, Tuple, Any, Optional
from sklearn.svm import SVC
import joblib

from .quantum_kernel import QuantumKernelEngine

class QuantumKernelClassifier:
    """
    Quantum Support Vector Classifier leveraging Quantum Kernel methods.
    """
    def __init__(
        self,
        num_qubits: int = 4,
        feature_map_type: str = "zz",
        reps: int = 1,
        entanglement: str = "linear",
        C: float = 1.0,
        random_state: int = 42
    ):
        self.num_qubits = num_qubits
        self.feature_map_type = feature_map_type
        self.reps = reps
        self.entanglement = entanglement
        self.C = C
        self.random_state = random_state
        
        self.kernel_engine = QuantumKernelEngine(
            num_qubits=num_qubits,
            feature_map_type=feature_map_type,
            reps=reps,
            entanglement=entanglement
        )
        
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=FutureWarning)
            self.model = SVC(
                kernel="precomputed",
                C=C,
                probability=True,
                random_state=random_state
            )
        
        self.X_train_: Optional[np.ndarray] = None
        self.classes_: List[str] = []
        self.training_time_sec: float = 0.0
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, y: np.ndarray, class_names: Optional[List[str]] = None) -> "QuantumKernelClassifier":
        """
        Fit Quantum Kernel Classifier.
        1. Evaluates NxN Quantum Gram Matrix K(X, X).
        2. Fits precomputed Kernel SVM with probability calibration.
        """
        start_t = time.perf_counter()
        
        self.X_train_ = np.asarray(X, dtype=np.float64)
        if class_names is not None:
            self.classes_ = class_names
        else:
            unique_y = np.unique(y)
            self.classes_ = [str(c) for c in unique_y]
            
        # Compute Quantum Kernel Matrix
        gram_train = self.kernel_engine.evaluate(self.X_train_)
        
        # Fit SVC
        self.model.fit(gram_train, y)
        
        self.training_time_sec = float(time.perf_counter() - start_t)
        self.is_fitted = True
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Compute class probabilities for test samples using Quantum Kernel.
        """
        if not self.is_fitted or self.X_train_ is None:
            raise ValueError("QuantumKernelClassifier is not fitted yet.")
            
        X = np.asarray(X, dtype=np.float64)
        # Compute rectangular kernel matrix K(X_test, X_train)
        k_test = self.kernel_engine.evaluate(X, self.X_train_)
        return self.model.predict_proba(k_test)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict classes using Quantum Kernel."""
        probs = self.predict_proba(X)
        return np.argmax(probs, axis=1)

    def predict_with_confidence(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray, float]:
        """
        Returns:
            predicted_indices: array of predicted class indices
            confidences: array of highest class probabilities
            probs: full class probability matrix
            latency_ms: per-sample inference latency in milliseconds
        """
        start_t = time.perf_counter()
        probs = self.predict_proba(X)
        total_time_ms = (time.perf_counter() - start_t) * 1000.0
        per_sample_latency = total_time_ms / max(len(X), 1)
        
        preds = np.argmax(probs, axis=1)
        confs = np.max(probs, axis=1)
        return preds, confs, probs, per_sample_latency

    def save(self, filepath: str):
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "QuantumKernelClassifier":
        return joblib.load(filepath)
