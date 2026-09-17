"""
Unit tests for Deep Learning Autoencoder module.
"""

import os
import sys
import unittest
import numpy as np

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from deep_learning.autoencoder import DeepAutoencoderDetector

class TestDeepAutoencoder(unittest.TestCase):
    def test_autoencoder_training_and_reconstruction(self):
        np.random.seed(42)
        X_benign = np.random.normal(loc=0.0, scale=1.0, size=(120, 16))
        
        ae = DeepAutoencoderDetector(input_dim=16, latent_dim=4, percentile_threshold=95.0)
        ae.fit(X_benign, epochs=15, batch_size=32, verbose=False)
        
        self.assertTrue(ae.is_fitted)
        self.assertGreater(ae.threshold_, 0.0)
        
        # Test normal evaluation
        recon_errors = ae.compute_reconstruction_error(X_benign[:10])
        self.assertEqual(len(recon_errors), 10)
        
        # Test outlier evaluation (reconstruction error should spike)
        X_outlier = X_benign[:5] + 10.0
        outlier_errors = ae.compute_reconstruction_error(X_outlier)
        self.assertGreater(np.mean(outlier_errors), np.mean(recon_errors) * 5.0)
        
        is_anom, _ = ae.predict(X_outlier)
        self.assertTrue(np.all(is_anom))

if __name__ == "__main__":
    unittest.main()
