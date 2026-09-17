"""
Endpoint Monitoring Agent Package for QE-NIDS.
Provides consent-based live network interface sniffing, 5-tuple flow aggregation,
and privacy-preserving feature extraction.
"""

from .collector import EndpointFlowCollector, FlowRecord
from .client import EndpointAgentClient

__all__ = ["EndpointFlowCollector", "FlowRecord", "EndpointAgentClient"]
