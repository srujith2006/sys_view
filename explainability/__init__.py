"""
Explainability Package for QE-NIDS.
Provides feature attribution and SOC alert contextualization.
"""

from .explainer import AnomalyExplainer

__all__ = ["AnomalyExplainer"]
