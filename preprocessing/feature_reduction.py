"""
Feature Selection and Reduction Module for Classical and Quantum ML pipelines.
Reduces high-dimensional network flow spaces to standardized classical vectors (e.g. 16)
and compact quantum vectors (4-8 qubits) normalized for quantum rotation gates.
"""

import numpy as np
import pandas as pd
from typing import Tuple, List, Dict, Any, Optional
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.decomposition import PCA
import joblib

class FeatureReducer:
    """
    Feature Reduction Pipeline:
    1. Standardization (StandardScaler)
    2. Feature Selection (SelectKBest via f_classif)
    3. PCA for Quantum Dimension (configurable 4-8 features)
    4. Quantum Angle Normalization (MinMaxScaler to [0, pi])
    """
    def __init__(
        self,
        n_classical_features: int = 16,
        n_quantum_features: int = 4,
        random_state: int = 42
    ):
        self.n_classical_features = n_classical_features
        self.n_quantum_features = n_quantum_features
        self.random_state = random_state
        
        self.scaler = StandardScaler()
        self.selector = SelectKBest(score_func=f_classif, k=n_classical_features)
        self.pca = PCA(n_components=n_quantum_features, random_state=random_state)
        self.quantum_scaler = MinMaxScaler(feature_range=(0, np.pi))
        
        self.selected_feature_indices: np.ndarray = np.array([])
        self.selected_feature_names: List[str] = []
        self.feature_scores: np.ndarray = np.array([])
        self.pca_explained_variance_ratio: np.ndarray = np.array([])
        self.pca_components_: np.ndarray = np.array([])
        self.is_fitted: bool = False

    def fit(self, X: np.ndarray, y: np.ndarray, feature_names: Optional[List[str]] = None) -> "FeatureReducer":
        """
        Fit all scalers, selectors, and PCA transformations strictly on training data.
        """
        n_features = X.shape[1]
        k_val = min(self.n_classical_features, n_features)
        self.selector.k = k_val
        
        # 1. Fit standard scaler
        X_scaled = self.scaler.fit_transform(X)
        
        # Eliminate constant features (zero variance)
        var = np.var(X_scaled, axis=0)
        non_constant_mask = var > 1e-6
        if not np.any(non_constant_mask):
            non_constant_mask = np.ones(n_features, dtype=bool)
            
        X_active = X_scaled[:, non_constant_mask]
        active_indices = np.where(non_constant_mask)[0]
        
        # 2. Fit feature selector
        k_active = min(k_val, X_active.shape[1])
        self.selector.k = k_active
        
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.selector.fit(X_active, y)
            scores_active = np.nan_to_num(self.selector.scores_, nan=0.0)
            
        # Map scores back to original indices
        full_scores = np.zeros(n_features)
        full_scores[active_indices] = scores_active
        self.feature_scores = full_scores
        
        self.selected_feature_indices = np.argsort(full_scores)[::-1][:k_val]
        
        if feature_names:
            self.selected_feature_names = [feature_names[i] for i in self.selected_feature_indices]
        else:
            self.selected_feature_names = [f"Feature_{i}" for i in self.selected_feature_indices]
            
        X_classical = X_scaled[:, self.selected_feature_indices]
        
        # 3. Fit PCA for quantum features
        n_q = min(self.n_quantum_features, k_val)
        self.pca.n_components = n_q
        X_pca = self.pca.fit_transform(X_classical)
        self.pca_explained_variance_ratio = self.pca.explained_variance_ratio_
        self.pca_components_ = self.pca.components_
        
        # 4. Fit Quantum Angle Scaler (Maps to [0, pi] for angle embedding)
        self.quantum_scaler.fit(X_pca)
        
        self.is_fitted = True
        return self

    def transform_classical(self, X: np.ndarray) -> np.ndarray:
        """Transform raw features into reduced classical feature matrix."""
        if not self.is_fitted:
            raise ValueError("FeatureReducer is not fitted yet.")
        X_scaled = self.scaler.transform(X)
        return X_scaled[:, self.selected_feature_indices]

    def transform_quantum(self, X_classical: np.ndarray) -> np.ndarray:
        """Transform classical feature matrix into quantum-ready angles in [0, pi]."""
        if not self.is_fitted:
            raise ValueError("FeatureReducer is not fitted yet.")
        X_pca = self.pca.transform(X_classical)
        X_quantum = self.quantum_scaler.transform(X_pca)
        return X_quantum

    def transform(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Transform raw X into both classical and quantum feature representations."""
        X_classical = self.transform_classical(X)
        X_quantum = self.transform_quantum(X_classical)
        return X_classical, X_quantum

    def get_summary(self) -> Dict[str, Any]:
        """Return metadata for visualization on dashboard."""
        return {
            "n_classical_features": len(self.selected_feature_indices),
            "selected_features": self.selected_feature_names,
            "feature_importance_scores": self.feature_scores[self.selected_feature_indices].tolist(),
            "n_quantum_features": int(self.pca.n_components_),
            "pca_explained_variance_ratio": self.pca_explained_variance_ratio.tolist(),
            "total_variance_explained": float(np.sum(self.pca_explained_variance_ratio))
        }

    def save(self, filepath: str):
        joblib.dump(self, filepath)

    @staticmethod
    def load(filepath: str) -> "FeatureReducer":
        return joblib.load(filepath)
