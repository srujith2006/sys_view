"""
Unit tests for data cleaning, encoding pipeline, and feature reduction.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from preprocessing.cleaning import clean_dataset
from preprocessing.encoding import DataPipeline, detect_dataset_schema
from preprocessing.feature_reduction import FeatureReducer
from utils.dataset_generator import generate_cicids2017_flows

class TestPreprocessing(unittest.TestCase):
    def setUp(self):
        self.df_raw = generate_cicids2017_flows(n_samples=200, random_state=42)

    def test_cleaning(self):
        # Introduce artificial inf and NaN
        df_dirty = self.df_raw.copy()
        df_dirty.loc[0, "Flow Duration"] = np.inf
        df_dirty.loc[1, "Total Fwd Packets"] = np.nan
        df_dirty.loc[2, "Flow Duration"] = -500  # Negative duration
        
        cleaned_df, stats = clean_dataset(df_dirty, is_training=True)
        self.assertEqual(stats["infinities_handled"], 1)
        self.assertEqual(stats["invalid_durations_dropped"], 1)
        self.assertFalse(np.isinf(cleaned_df["Flow Duration"]).any())
        self.assertFalse(cleaned_df.isna().any().any())

    def test_pipeline_and_splits(self):
        cleaned_df, _ = clean_dataset(self.df_raw)
        pipeline = DataPipeline(random_state=42)
        df_train, df_val, df_test = pipeline.split_data(cleaned_df, 0.7, 0.15, 0.15)
        
        self.assertGreater(len(df_train), 0)
        self.assertGreater(len(df_val), 0)
        self.assertGreater(len(df_test), 0)
        
        pipeline.fit(df_train)
        X_train, y_train_m, y_train_b, meta_train = pipeline.transform(df_train)
        X_test, y_test_m, y_test_b, meta_test = pipeline.transform(df_test)
        
        self.assertEqual(X_train.shape[1], len(pipeline.feature_cols))
        self.assertEqual(X_test.shape[1], len(pipeline.feature_cols))
        self.assertIn("Source IP", meta_train.columns)
        self.assertNotIn("Source IP", pipeline.feature_cols)  # Zero data leakage

    def test_feature_reduction(self):
        cleaned_df, _ = clean_dataset(self.df_raw)
        pipeline = DataPipeline().fit(cleaned_df)
        X, y_multi, y_binary, _ = pipeline.transform(cleaned_df)
        
        reducer = FeatureReducer(n_classical_features=8, n_quantum_features=4)
        reducer.fit(X, y_binary, feature_names=pipeline.feature_cols)
        
        X_classical, X_quantum = reducer.transform(X)
        self.assertEqual(X_classical.shape[1], 8)
        self.assertEqual(X_quantum.shape[1], 4)
        # Verify quantum angles in [0, pi]
        self.assertTrue(np.all(X_quantum >= 0.0))
        self.assertTrue(np.all(X_quantum <= np.pi + 1e-5))

if __name__ == "__main__":
    unittest.main()
