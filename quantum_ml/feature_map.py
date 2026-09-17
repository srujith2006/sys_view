"""
Quantum Feature Map Module for Quantum-Enhanced Intrusion Detection.
Constructs parameterized quantum circuits for embedding reduced classical network features into Hilbert space.
Supports modern Qiskit 2.x API.
"""

from typing import Optional, Union
import qiskit
from qiskit import QuantumCircuit

def build_quantum_feature_map(
    num_qubits: int = 4,
    feature_map_type: str = "zz",
    reps: int = 1,
    entanglement: str = "linear"
) -> QuantumCircuit:
    """
    Construct a Qiskit Quantum Feature Map circuit.
    
    Args:
        num_qubits: Number of qubits (4-8 recommended for simulation).
        feature_map_type: 'zz' for ZZFeatureMap (with entanglement), 'z' for ZFeatureMap.
        reps: Circuit repetitions / depth.
        entanglement: Entanglement topology ('linear' or 'full').
        
    Returns:
        QuantumCircuit: Parameterized quantum circuit.
    """
    try:
        # Modern Qiskit 2.x functional API
        from qiskit.circuit.library import zz_feature_map, z_feature_map
        if feature_map_type.lower() == "z":
            circuit = z_feature_map(feature_dimension=num_qubits, reps=reps)
        else:
            circuit = zz_feature_map(
                feature_dimension=num_qubits, 
                reps=reps, 
                entanglement=entanglement
            )
    except (ImportError, AttributeError):
        # Backward-compatible fallback for earlier versions
        from qiskit.circuit.library import ZZFeatureMap, ZFeatureMap
        if feature_map_type.lower() == "z":
            circuit = ZFeatureMap(feature_dimension=num_qubits, reps=reps)
        else:
            circuit = ZZFeatureMap(
                feature_dimension=num_qubits, 
                reps=reps, 
                entanglement=entanglement
            )
            
    return circuit

def draw_feature_map_ascii(circuit: QuantumCircuit) -> str:
    """
    Render ASCII representation of the quantum feature map circuit for SOC dashboard display.
    """
    try:
        # Decompose one level if it's a composite circuit to display gates clearly
        decomposed = circuit.decompose()
        return str(decomposed.draw(output="text"))
    except Exception:
        return str(circuit.draw(output="text"))
