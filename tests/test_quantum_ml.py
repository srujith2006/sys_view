"""
Unit tests for Quantum Machine Learning modules (Feature Maps, Quantum Kernel, QSVC).
"""

import os
import sys
import unittest
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from quantum_ml.feature_map import build_quantum_feature_map, draw_feature_map_ascii
from quantum_ml.quantum_kernel import QuantumKernelEngine
from quantum_ml.qml_classifier import QuantumKernelClassifier
from quantum_ml.evaluation import compare_classical_vs_quantum
from classical_ml.evaluation import MetricsResult

class TestQuantumML(unittest.TestCase):
    def test_feature_map(self):
        c = build_quantum_feature_map(num_qubits=4, feature_map_type="zz", reps=1)
        self.assertEqual(c.num_qubits, 4)
        ascii_drawing = draw_feature_map_ascii(c)
        self.assertIsInstance(ascii_drawing, str)
        self.assertGreater(len(ascii_drawing), 10)

    def test_quantum_kernel_engine(self):
        engine = QuantumKernelEngine(num_qubits=3, feature_map_type="zz", reps=1)
        X = np.random.uniform(0, np.pi, size=(5, 3))
        gram = engine.evaluate(X)
        
        self.assertEqual(gram.shape, (5, 5))
        # Diagonal elements must be 1.0
        np.testing.assert_allclose(np.diag(gram), 1.0, atol=1e-5)
        # Must be symmetric
        np.testing.assert_allclose(gram, gram.T, atol=1e-5)
        # Rectangular kernel
        Y = np.random.uniform(0, np.pi, size=(3, 3))
        rect_k = engine.evaluate(X, Y)
        self.assertEqual(rect_k.shape, (5, 3))

    def test_quantum_classifier(self):
        # 4 qubits, 2 classes (Binary Anomaly classification)
        np.random.seed(42)
        X_train = np.random.uniform(0, np.pi, size=(16, 4))
        y_train = np.array([0]*8 + [1]*8)
        
        clf = QuantumKernelClassifier(num_qubits=4, reps=1, C=1.0)
        clf.fit(X_train, y_train, class_names=["BENIGN", "ANOMALY"])
        
        X_test = np.random.uniform(0, np.pi, size=(4, 4))
        preds, confs, probs, latency = clf.predict_with_confidence(X_test)
        
        self.assertEqual(len(preds), 4)
        self.assertEqual(probs.shape, (4, 2))
        np.testing.assert_allclose(np.sum(probs, axis=1), 1.0, atol=1e-4)
        self.assertGreater(latency, 0.0)

    def test_comparative_benchmark(self):
        m1 = MetricsResult(
            accuracy=0.95, precision_macro=0.94, precision_weighted=0.95,
            recall_macro=0.93, recall_weighted=0.95, f1_macro=0.93, f1_weighted=0.95,
            false_positive_rate=0.02, roc_auc=0.98, pr_auc=0.97,
            confusion_matrix=[[50, 2], [3, 45]], class_names=["A", "B"],
            training_time_sec=0.15, inference_latency_ms=0.05
        )
        m2 = MetricsResult(
            accuracy=0.92, precision_macro=0.91, precision_weighted=0.92,
            recall_macro=0.90, recall_weighted=0.92, f1_macro=0.90, f1_weighted=0.92,
            false_positive_rate=0.03, roc_auc=0.96, pr_auc=0.94,
            confusion_matrix=[[48, 4], [4, 44]], class_names=["A", "B"],
            training_time_sec=1.20, inference_latency_ms=1.50
        )
        comp = compare_classical_vs_quantum(m1, m2)
        self.assertIn("comparison_table", comp)
        self.assertIn("findings", comp)
        self.assertEqual(len(comp["comparison_table"]), 12)

if __name__ == "__main__":
    unittest.main()
