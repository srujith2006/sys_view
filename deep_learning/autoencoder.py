"""
Deep Learning Autoencoder for Network Traffic Anomaly Detection.
Trained strictly on benign traffic to learn normal baseline representations.
Reconstruction errors above validation percentiles signal novel or anomalous network behavior.
"""

import os
import json
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from typing import Dict, Any, Tuple, Optional, List

class AutoencoderNet(nn.Module):
    """
    Symmetric Deep Autoencoder Network.
    Compresses high-dimensional flow features into a bottleneck latent representation.
    """
    def __init__(self, input_dim: int = 51, latent_dim: int = 8):
        super().__init__()
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        
        # Encoder
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Linear(32, 16),
            nn.BatchNorm1d(16),
            nn.LeakyReLU(0.1),
            nn.Linear(16, latent_dim),
            nn.LeakyReLU(0.1)
        )
        
        # Decoder
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 16),
            nn.BatchNorm1d(16),
            nn.LeakyReLU(0.1),
            nn.Linear(16, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.1),
            nn.Linear(32, input_dim)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction


class DeepAutoencoderDetector:
    """
    Deep Autoencoder Anomaly Detector for Network Intrusion Detection.
    Learns normal baseline traffic distributions and uses reconstruction error
    calibrated against benign validation percentiles to identify outliers.
    """
    def __init__(
        self,
        input_dim: int = 51,
        latent_dim: int = 8,
        percentile_threshold: float = 95.0,
        device: Optional[str] = None
    ):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.percentile_threshold = percentile_threshold
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        
        self.model = AutoencoderNet(input_dim=input_dim, latent_dim=latent_dim).to(self.device)
        self.threshold_: float = 0.5
        self.percentile_95_: float = 0.5
        self.percentile_99_: float = 1.0
        self.mean_benign_error_: float = 0.1
        self.std_benign_error_: float = 0.05
        self.loss_history_: List[float] = []
        self.is_fitted: bool = False

    def fit(
        self,
        X_benign_train: np.ndarray,
        X_benign_val: Optional[np.ndarray] = None,
        epochs: int = 35,
        batch_size: int = 64,
        lr: float = 1e-3,
        verbose: bool = True
    ) -> "DeepAutoencoderDetector":
        """
        Train the autoencoder strictly on benign traffic.
        Calibrates threshold using the benign validation set.
        """
        self.model.train()
        X_tensor = torch.tensor(X_benign_train, dtype=torch.float32)
        dataset = TensorDataset(X_tensor)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=(len(X_tensor) > batch_size))
        
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr, weight_decay=1e-5)
        criterion = nn.MSELoss()
        
        self.loss_history_ = []
        for epoch in range(epochs):
            total_loss = 0.0
            for (batch_x,) in loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                recon = self.model(batch_x)
                loss = criterion(recon, batch_x)
                loss.backward()
                optimizer.step()
                total_loss += loss.item() * len(batch_x)
                
            epoch_loss = total_loss / len(X_tensor)
            self.loss_history_.append(epoch_loss)
            if verbose and (epoch + 1) % 10 == 0:
                print(f"      [Autoencoder] Epoch {epoch+1}/{epochs} - Reconstruction Loss (MSE): {epoch_loss:.6f}")
                
        # Calibrate threshold on validation benign data
        val_data = X_benign_val if X_benign_val is not None else X_benign_train
        val_errors = self.compute_reconstruction_error(val_data)
        
        self.mean_benign_error_ = float(np.mean(val_errors))
        self.std_benign_error_ = float(np.std(val_errors))
        self.percentile_95_ = float(np.percentile(val_errors, 95))
        self.percentile_99_ = float(np.percentile(val_errors, 99))
        
        # Select threshold based on configured percentile
        self.threshold_ = float(np.percentile(val_errors, self.percentile_threshold))
        self.is_fitted = True
        
        if verbose:
            print(f"      [Autoencoder] Calibrated Anomaly Threshold ({self.percentile_threshold}th percentile): {self.threshold_:.5f}")
            print(f"      [Autoencoder] Benign baseline reconstruction error: {self.mean_benign_error_:.5f} +/- {self.std_benign_error_:.5f}")
            
        return self

    def compute_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """
        Compute mean squared reconstruction error per sample:
        E(x) = (1/D) * sum( (x_j - x_hat_j)^2 )
        """
        self.model.eval()
        X_tensor = torch.tensor(X, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            errors = torch.mean((X_tensor - reconstructed) ** 2, dim=1)
        return errors.cpu().numpy()

    def compute_feature_reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """
        Compute per-feature squared error (N, D) to reveal which telemetry metrics
        deviate most from benign representations.
        """
        self.model.eval()
        X_tensor = torch.tensor(X, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            reconstructed = self.model(X_tensor)
            feat_errors = (X_tensor - reconstructed) ** 2
        return feat_errors.cpu().numpy()

    def predict(self, X: np.ndarray, custom_threshold: Optional[float] = None) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
            is_anomaly: boolean array (True if error > threshold)
            errors: continuous reconstruction errors
        """
        thresh = custom_threshold if custom_threshold is not None else self.threshold_
        errors = self.compute_reconstruction_error(X)
        is_anomaly = errors > thresh
        return is_anomaly, errors

    def normalize_reconstruction_score(self, errors: np.ndarray) -> np.ndarray:
        """
        Normalize reconstruction errors into a calibrated [0.0, 1.0] anomaly signal:
        - Error at benign mean -> ~0.0
        - Error at threshold (95th percentile) -> ~0.65
        - Error at 3x threshold -> ~1.0
        """
        # Piecewise logistic or scaled ratio
        ratio = errors / max(self.threshold_, 1e-6)
        # Scaled mapping: ratio=1.0 maps to 0.65
        normalized = 1.0 / (1.0 + np.exp(-2.5 * (ratio - 0.85)))
        return np.clip(normalized, 0.0, 1.0)

    def save(self, filepath_prefix: str):
        """Save model weights and calibration metadata."""
        pt_path = f"{filepath_prefix}.pt"
        json_path = f"{filepath_prefix}_meta.json"
        
        torch.save(self.model.state_dict(), pt_path)
        meta = {
            "input_dim": self.input_dim,
            "latent_dim": self.latent_dim,
            "percentile_threshold": self.percentile_threshold,
            "threshold": self.threshold_,
            "percentile_95": self.percentile_95_,
            "percentile_99": self.percentile_99_,
            "mean_benign_error": self.mean_benign_error_,
            "std_benign_error": self.std_benign_error_,
            "loss_history": self.loss_history_
        }
        with open(json_path, "w") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, filepath_prefix: str, device: Optional[str] = None) -> "DeepAutoencoderDetector":
        """Load model weights and metadata."""
        pt_path = f"{filepath_prefix}.pt"
        json_path = f"{filepath_prefix}_meta.json"
        
        with open(json_path, "r") as f:
            meta = json.load(f)
            
        instance = cls(
            input_dim=meta["input_dim"],
            latent_dim=meta["latent_dim"],
            percentile_threshold=meta["percentile_threshold"],
            device=device
        )
        instance.threshold_ = meta["threshold"]
        instance.percentile_95_ = meta["percentile_95"]
        instance.percentile_99_ = meta["percentile_99"]
        instance.mean_benign_error_ = meta["mean_benign_error"]
        instance.std_benign_error_ = meta["std_benign_error"]
        instance.loss_history_ = meta.get("loss_history", [])
        
        instance.model.load_state_dict(torch.load(pt_path, map_location=instance.device))
        instance.model.eval()
        instance.is_fitted = True
        return instance
