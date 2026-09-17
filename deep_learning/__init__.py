"""
Deep Learning Package for QE-NIDS.
Implements deep autoencoders for unsupervised benign network behavior modeling
and zero-day/novel threat discovery.
"""

from .autoencoder import DeepAutoencoderDetector, AutoencoderNet

__all__ = ["DeepAutoencoderDetector", "AutoencoderNet"]
