"""
Unit tests for Classical ML modules: Isolation Forest, Classifier, and Hybrid Decision Engine.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing.cleaning import clean_dataset
from preprocessing.encoding import DataPipeline
from preprocessing.feature_reduction import FeatureReducer
from classical_ml.anomaly_detection import UnsupervisedAnomalyDetector
from classical_ml.classification import SupervisedAttackClassifier, HybridDecisionEngine
from classical_ml.evaluation import evaluate_classification, evaluate_anomaly_detector
from utils.dataset_generator import generate_cicids2017_flows

class TestClassicalML(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        df_raw = generate_cicids2017_flows(n_samples=300, random_state=42)
        cleaned_df, _ = clean_dataset(df_raw)
        cls.pipeline = DataPipeline(random_state=42).fit(cleaned_df)
        X, y_multi, y_binary, meta_df = cls.pipeline.transform(cleaned_df)
        
        cls.reducer = FeatureReducer(n_classical_features=10, n_quantum_features=4)
        cls.reducer.fit(X, y_binary)
        cls.X_classical, _ = cls.reducer.transform(X)
        cls.y_multi = y_multi
        cls.y_binary = y_binary
        cls.meta_df = meta_df

    def test_isolation_forest(self):
        detector = UnsupervisedAnomalyDetector(n_estimators=50)
        detector.fit(self.X_classical)
        
        scores = detector.compute_anomaly_scores(self.X_classical)
        self.assertEqual(len(scores), len(self.X_classical))
        self.assertTrue(np.all(scores >= 0.0))
        self.assertTrue(np.all(scores <= 1.0))
        
        preds, _ = detector.predict(self.X_classical, threshold=0.65)
        self.assertTrue(set(preds).issubset({0, 1}))

    def test_supervised_classifier(self):
        clf = SupervisedAttackClassifier(n_estimators=30)
        clf.fit(self.X_classical, self.y_multi, self.pipeline.classes_)
        
        preds, confs, probs = clf.predict_with_confidence(self.X_classical)
        self.assertEqual(len(preds), len(self.X_classical))
        self.assertTrue(np.all(confs >= 0.0) and np.all(confs <= 1.0))
        self.assertEqual(probs.shape[1], len(self.pipeline.classes_))

    def test_hybrid_decision_engine_and_novel_anomaly(self):
        detector = UnsupervisedAnomalyDetector(n_estimators=50).fit(self.X_classical)
        clf = SupervisedAttackClassifier(n_estimators=30).fit(self.X_classical, self.y_multi, self.pipeline.classes_)
        
        engine = HybridDecisionEngine(
            anomaly_detector=detector,
            classifier=clf,
            class_names=self.pipeline.classes_,
            anomaly_threshold=0.60,
            novel_confidence_threshold=0.55
        )
        
        # Test normal flow evaluation
        res_normal = engine.evaluate_flow(self.X_classical[0])
        self.assertIn("status", res_normal)
        self.assertIn("risk_score", res_normal)
        self.assertIn("severity", res_normal)
        self.assertIn("attack_category", res_normal)
        
        # Craft an extreme synthetic outlier to test Novel Anomaly triggering
        extreme_outlier = np.ones((1, self.X_classical.shape[1])) * 50.0
        res_novel = engine.evaluate_flow(extreme_outlier)
        # Should be flagged as anomalous
        self.assertEqual(res_novel["status"], "ANOMALOUS")
        self.assertIn(res_novel["severity"], ["HIGH", "CRITICAL"])

    def test_metrics_evaluation(self):
        y_true = np.array([0, 0, 1, 1, 0, 1])
        y_pred = np.array([0, 0, 1, 0, 0, 1])
        scores = np.array([0.1, 0.2, 0.9, 0.4, 0.15, 0.85])
        
        metrics = evaluate_anomaly_detector(y_true, scores, threshold=0.5)
        self.assertGreaterEqual(metrics.accuracy, 0.8)
        self.assertGreaterEqual(metrics.roc_auc, 0.8)
        self.assertEqual(metrics.false_positive_rate, 0.0)

if __name__ == "__main__":
    unittest.main()
