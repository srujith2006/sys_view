"""
Endpoint Agent Client supporting Local Mode and Server Mode.
Provides privacy-preserving transmission of extracted flow telemetry without packet payloads.
"""

import requests
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional
from fusion.fusion_engine import ModelFusionEngine
from preprocessing.cleaning import clean_dataset

class EndpointAgentClient:
    """
    Client interface for Endpoint Agent.
    Operates in Local Mode (in-process models) or Server Mode (REST API).
    """
    def __init__(
        self,
        mode: str = "LOCAL",  # 'LOCAL' or 'SERVER'
        server_url: str = "http://127.0.0.1:5000",
        fusion_engine: Optional[ModelFusionEngine] = None,
        pipeline = None,
        reducer = None
    ):
        self.mode = mode.upper()
        self.server_url = server_url.rstrip("/")
        self.fusion_engine = fusion_engine
        self.pipeline = pipeline
        self.reducer = reducer

    def evaluate_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate a single flow in Local Mode or Server Mode.
        """
        if self.mode == "SERVER":
            try:
                r = requests.post(f"{self.server_url}/predict/flow", json=flow_dict, timeout=5)
                r.raise_for_status()
                return r.json()
            except Exception as e:
                return {
                    "status": "ERROR",
                    "error": f"Server mode connection failed: {str(e)}",
                    "risk_score": 0.0,
                    "severity": "UNKNOWN"
                }
        else:
            # Local in-process evaluation
            if self.fusion_engine is None or self.pipeline is None or self.reducer is None:
                raise ValueError("Local mode requires initialized fusion_engine, pipeline, and reducer.")
                
            df_single = pd.DataFrame([flow_dict])
            cleaned_df, _ = clean_dataset(df_single, is_training=False)
            
            X_raw, _, _, meta_df = self.pipeline.transform(cleaned_df)
            X_c, X_q = self.reducer.transform(X_raw)
            
            meta_dict = meta_df.iloc[0].to_dict() if len(meta_df) > 0 else {}
            return self.fusion_engine.evaluate_flow(
                X_raw=X_raw[0:1],
                X_classical=X_c[0:1],
                X_quantum=X_q[0:1],
                meta_dict=meta_dict
            )

    def evaluate_batch(self, df_flows: pd.DataFrame) -> List[Dict[str, Any]]:
        """Evaluate a batch of flows."""
        if len(df_flows) == 0:
            return []
            
        if self.mode == "SERVER":
            try:
                r = requests.post(f"{self.server_url}/predict/batch", json=df_flows.to_dict(orient="records"), timeout=15)
                r.raise_for_status()
                return r.json().get("alerts", [])
            except Exception as e:
                return [{"status": "ERROR", "error": str(e)}]
        else:
            cleaned_df, _ = clean_dataset(df_flows, is_training=False)
            X_raw, _, _, meta_df = self.pipeline.transform(cleaned_df)
            X_c, X_q = self.reducer.transform(X_raw)
            return self.fusion_engine.evaluate_batch(
                X_raw=X_raw,
                X_classical=X_c,
                X_quantum=X_q,
                meta_df=meta_df
            )
