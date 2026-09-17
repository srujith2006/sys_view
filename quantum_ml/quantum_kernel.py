"""
Quantum Kernel Engine using Qiskit and Qiskit Machine Learning.
Computes quantum fidelity kernel matrices K(x_i, x_j) = |<psi(x_i)|psi(x_j)>|^2.
Supports FidelityQuantumKernel and accelerated vectorized statevector simulation.
"""

import numpy as np
from typing import Optional, Union
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from .feature_map import build_quantum_feature_map

class QuantumKernelEngine:
    """
    Quantum Kernel computation engine.
    Calculates Gram matrix representing inner products in quantum Hilbert space.
    """
    def __init__(
        self,
        num_qubits: int = 4,
        feature_map_type: str = "zz",
        reps: int = 1,
        entanglement: str = "linear",
        mode: str = "auto"  # 'auto', 'fidelity', or 'statevector'
    ):
        self.num_qubits = num_qubits
        self.feature_map_type = feature_map_type
        self.reps = reps
        self.entanglement = entanglement
        self.mode = mode
        
        self.circuit = build_quantum_feature_map(
            num_qubits=num_qubits,
            feature_map_type=feature_map_type,
            reps=reps,
            entanglement=entanglement
        )
        
        self._fidelity_kernel = None
        self._init_qiskit_kernel()

    def _init_qiskit_kernel(self):
        """Attempt initialization of Qiskit Machine Learning FidelityQuantumKernel."""
        try:
            from qiskit_machine_learning.kernels import FidelityQuantumKernel
            self._fidelity_kernel = FidelityQuantumKernel(feature_map=self.circuit)
        except Exception:
            self._fidelity_kernel = None

    def evaluate_statevector(self, X: np.ndarray, Y: Optional[np.ndarray] = None) -> np.ndarray:
        """
        High-performance exact statevector fidelity kernel calculation:
        K_ij = |<psi(x_i) | psi(y_j)>|^2 = |psi_i^dagger @ psi_j|^2
        Vectorized across all samples.
        """
        # Generate statevectors for X
        sv_list_X = []
        for row in X:
            bound_c = self.circuit.assign_parameters(row)
            sv = Statevector(bound_c).data
            sv_list_X.append(sv)
        sv_mat_X = np.array(sv_list_X)  # shape (N, 2^n)
        
        if Y is None or (Y is X):
            # Symmetric Gram matrix: |Psi @ Psi^dagger|^2
            gram = np.abs(sv_mat_X @ sv_mat_X.conj().T) ** 2
            # Ensure diagonal is exactly 1.0
            np.fill_diagonal(gram, 1.0)
            return gram.astype(np.float64)
        else:
            sv_list_Y = []
            for row in Y:
                bound_c = self.circuit.assign_parameters(row)
                sv = Statevector(bound_c).data
                sv_list_Y.append(sv)
            sv_mat_Y = np.array(sv_list_Y)  # shape (M, 2^n)
            
            kernel_rect = np.abs(sv_mat_X @ sv_mat_Y.conj().T) ** 2
            return kernel_rect.astype(np.float64)

    def evaluate(self, X: np.ndarray, Y: Optional[np.ndarray] = None) -> np.ndarray:
        """
        Evaluate quantum kernel between dataset X and Y (or X and X).
        """
        X = np.asarray(X, dtype=np.float64)
        if Y is not None:
            Y = np.asarray(Y, dtype=np.float64)
            
        if self.mode == "fidelity" and self._fidelity_kernel is not None:
            try:
                return self._fidelity_kernel.evaluate(X, Y)
            except Exception:
                pass
                
        # Default/Fallback: exact statevector calculation (fast, robust, zero dependencies on C++ backends)
        return self.evaluate_statevector(X, Y)
