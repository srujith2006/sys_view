"""
Quantum Machine Learning Package for QE-NIDS.
Utilizes Qiskit 2.x and Qiskit Machine Learning for Quantum Feature Maps and Quantum Kernel Methods.
"""

from .feature_map import build_quantum_feature_map, draw_feature_map_ascii
from .quantum_kernel import QuantumKernelEngine
from .qml_classifier import QuantumKernelClassifier
from .evaluation import compare_classical_vs_quantum

__all__ = [
    "build_quantum_feature_map",
    "draw_feature_map_ascii",
    "QuantumKernelEngine",
    "QuantumKernelClassifier",
    "compare_classical_vs_quantum"
]
