"""
Real-Time Network Flow Telemetry Simulator for SOC Live Demonstration.
Streams flow records from reference data, generates updated timestamps,
and supports dynamic attack pattern injection for interactive monitoring.
"""

import time
import random
from datetime import datetime
import pandas as pd
import numpy as np
from typing import Generator, Dict, Any, List, Optional

class LiveTrafficSimulator:
    """
    Simulates real-time network flow traffic for live SOC operations center demonstration.
    """
    def __init__(self, source_df: pd.DataFrame, shuffle: bool = True, seed: int = 42):
        self.source_df = source_df.copy()
        if shuffle:
            self.source_df = self.source_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        self.cursor = 0
        self.total_samples = len(self.source_df)

    def next_flow(self) -> pd.Series:
        """Fetch the next flow record and update timestamp to current local time."""
        row = self.source_df.iloc[self.cursor].copy()
        self.cursor = (self.cursor + 1) % self.total_samples
        
        # Inject live current timestamp
        now = datetime.now()
        row["Timestamp"] = now.strftime("%Y-%m-%d %H:%M:%S")
        return row

    def get_batch(self, batch_size: int = 10) -> pd.DataFrame:
        """Fetch a batch of consecutive flows with current timestamps."""
        rows = [self.next_flow() for _ in range(batch_size)]
        return pd.DataFrame(rows)

    def inject_synthetic_novel_anomaly(self) -> pd.Series:
        """
        Generate a synthetic telemetry record that mimics an unknown/novel protocol anomaly
        (e.g., highly deviant packet sizing and abnormal flag combination).
        """
        base_row = self.source_df.iloc[0].copy()
        now = datetime.now()
        base_row["Timestamp"] = now.strftime("%Y-%m-%d %H:%M:%S")
        base_row["Source IP"] = f"10.240.{random.randint(1, 254)}.{random.randint(1, 254)}"
        base_row["Destination IP"] = "192.168.1.5"
        base_row["Source Port"] = random.randint(49152, 65535)
        base_row["Destination Port"] = random.randint(8000, 9000)
        base_row["Protocol"] = 6
        
        # Highly abnormal telemetry
        base_row["Flow Duration"] = 850000.0
        base_row["Total Fwd Packets"] = 350
        base_row["Total Backward Packets"] = 2
        base_row["Flow Packets/s"] = 411.7
        base_row["Flow Bytes/s"] = 250000.0
        base_row["SYN Flag Count"] = 150
        base_row["RST Flag Count"] = 45
        base_row["ACK Flag Count"] = 3
        base_row["Fwd Packet Length Mean"] = 1380.0
        base_row["Bwd Packet Length Mean"] = 10.0
        base_row["Label"] = "UNKNOWN_ANOMALY"
        
        return base_row
