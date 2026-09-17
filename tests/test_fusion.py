"""
Unit tests for Model Fusion Engine and Endpoint Flow Collector.
"""

import os
import sys
import unittest
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from agent.collector import EndpointFlowCollector, FlowRecord
from fusion.fusion_engine import ModelFusionEngine
from classical_ml.anomaly_detection import UnsupervisedAnomalyDetector
from classical_ml.classification import SupervisedAttackClassifier
from deep_learning.autoencoder import DeepAutoencoderDetector
from explainability.explainer import AnomalyExplainer

class TestFusionAndAgent(unittest.TestCase):
    def test_flow_record_51_features(self):
        record = FlowRecord(
            src_ip="192.168.1.10", dst_ip="8.8.8.8",
            src_port=50000, dst_port=53, protocol=17,
            start_time=1000.0, last_seen=1001.0
        )
        record.add_packet(length=60, timestamp=1000.0, is_forward=True, flags={"SYN": 1})
        record.add_packet(length=120, timestamp=1001.0, is_forward=False, flags={"ACK": 1})
        
        feat_dict = record.to_cicids2017_dict()
        self.assertEqual(feat_dict["Total Fwd Packets"], 1)
        self.assertEqual(feat_dict["Total Backward Packets"], 1)
        self.assertEqual(feat_dict["SYN Flag Count"], 1)
        self.assertIn("Flow Duration", feat_dict)
        self.assertIn("Flow Bytes/s", feat_dict)

    def test_collector_consent_enforcement(self):
        collector = EndpointFlowCollector()
        self.assertFalse(collector.user_consent)
        
        # Must raise PermissionError without consent
        with self.assertRaises(PermissionError):
            collector.start_monitoring()
            
        collector.grant_consent(True)
        self.assertTrue(collector.user_consent)

    def test_fusion_severity_tiers(self):
        self.assertEqual(ModelFusionEngine.get_severity_tier(15.0), "SAFE")
        self.assertEqual(ModelFusionEngine.get_severity_tier(35.0), "LOW")
        self.assertEqual(ModelFusionEngine.get_severity_tier(55.0), "MEDIUM")
        self.assertEqual(ModelFusionEngine.get_severity_tier(75.0), "HIGH")
        self.assertEqual(ModelFusionEngine.get_severity_tier(92.0), "CRITICAL")

if __name__ == "__main__":
    unittest.main()
