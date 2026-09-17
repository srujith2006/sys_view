"""
Network Traffic Simulation Package for QE-NIDS.
Simulates real-time network flow telemetry for SOC demonstration.
"""

from .traffic_generator import LiveTrafficSimulator

__all__ = ["LiveTrafficSimulator"]
