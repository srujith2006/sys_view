"""
Data Encoding and Leak-Free Pipeline for Network Intrusion Telemetry.
Handles dynamic dataset schema mapping, metadata separation, and stratified splitting.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any, Optional
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import joblib

def detect_dataset_schema(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Introspect DataFrame columns to map metadata, features, and target label.
    Supports CIC-IDS2017, UNSW-NB15, or generic network intrusion datasets.
    """
    cols = [c.strip() for c in df.columns]
    
    # 1. Detect Label column
    label_col = None
    for candidate in ["Label", "label", "attack_cat", "class", "target", "Attack"]:
        if candidate in cols:
            label_col = candidate
            break
    if label_col is None:
        # Fallback: check last column
        label_col = cols[-1]
        
    # 2. Detect Metadata columns (Identifiers to retain for SOC alerting, but NEVER train on)
    metadata_candidates = {
        "Flow ID", "flow_id", "id",
        "Source IP", "src_ip", "srcip", "Source_IP",
        "Destination IP", "dst_ip", "dstip", "Destination_IP",
        "Source Port", "src_port", "sport", "Source_Port",
        "Destination Port", "dst_port", "dsport", "Destination_Port",
        "Timestamp", "timestamp", "time", "date", "Stime", "Ltime",
        "Protocol", "protocol", "proto"
    }
    
    meta_cols = [c for c in cols if c in metadata_candidates]
    
    # 3. Numeric Feature columns
    feature_cols = [
        c for c in cols 
        if c not in meta_cols and c != label_col and pd.api.types.is_numeric_dtype(df[c])
    ]
    
    return {
        "label_col": label_col,
        "metadata_cols": meta_cols,
        "feature_cols": feature_cols
    }

class DataPipeline:
    """
    Leak-free data processing pipeline.
    Encapsulates column mapping, metadata preservation, and label encoding.
    """
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.label_encoder = LabelEncoder()
        self.label_col: Optional[str] = None
        self.metadata_cols: List[str] = []
        self.feature_cols: List[str] = []
        self.classes_: List[str] = []
        self.benign_class_name: str = "BENIGN"
        self.benign_class_idx: int = 0
        self.is_fitted: bool = False
        
    def fit(self, df: pd.DataFrame) -> "DataPipeline":
        """
        Fit label encoder and determine feature schemas strictly on training data.
        """
        schema = detect_dataset_schema(df)
        self.label_col = schema["label_col"]
        self.metadata_cols = schema["metadata_cols"]
        self.feature_cols = schema["feature_cols"]
        
        # Ensure all feature columns are cast to float
        df_feats = df[self.feature_cols].copy()
        
        # Fit Label Encoder
        raw_labels = df[self.label_col].astype(str).str.strip()
        self.label_encoder.fit(raw_labels)
        self.classes_ = list(self.label_encoder.classes_)
        
        # Identify benign class
        for name in ["BENIGN", "benign", "Normal", "normal", "0"]:
            if name in self.classes_:
                self.benign_class_name = name
                self.benign_class_idx = int(self.label_encoder.transform([name])[0])
                break
                
        self.is_fitted = True
        return self
        
    def transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, Optional[np.ndarray], Optional[np.ndarray], pd.DataFrame]:
        """
        Transform dataset:
        Returns:
            X: numerical feature matrix (N, num_features)
            y_multi: multi-class labels (N,) or None
            y_binary: binary labels (0=Normal, 1=Anomaly) or None
            meta_df: metadata dataframe containing IPs, ports, timestamps for SOC display
        """
        if not self.is_fitted:
            raise ValueError("DataPipeline must be fitted before transforming data.")
            
        # Metadata extraction
        available_meta = [c for c in self.metadata_cols if c in df.columns]
        meta_df = df[available_meta].copy() if available_meta else pd.DataFrame(index=df.index)
        
        # Feature extraction
        missing_feats = [c for c in self.feature_cols if c not in df.columns]
        df_feats = df[[c for c in self.feature_cols if c in df.columns]].copy()
        for mf in missing_feats:
            df_feats[mf] = 0.0
        # Preserve original column order
        df_feats = df_feats[self.feature_cols]
        X = df_feats.values.astype(np.float32)
        
        # Labels if present
        y_multi = None
        y_binary = None
        if self.label_col in df.columns:
            labels_str = df[self.label_col].astype(str).str.strip()
            # Map unseen labels safely to benign
            known_mask = labels_str.isin(self.classes_)
            labels_clean = labels_str.copy()
            labels_clean[~known_mask] = self.benign_class_name
            y_multi = self.label_encoder.transform(labels_clean)
            y_binary = (y_multi != self.benign_class_idx).astype(int)
            
        return X, y_multi, y_binary, meta_df

    def split_data(
        self, 
        df: pd.DataFrame, 
        train_size: float = 0.70, 
        val_size: float = 0.15, 
        test_size: float = 0.15
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Split dataset into stratified train/val/test splits without leakage.
        """
        schema = detect_dataset_schema(df)
        label_col = schema["label_col"]
        
        # Check if stratification is valid (each class must have >= 2 instances)
        stratify = None
        if label_col in df.columns:
            class_counts = df[label_col].value_counts()
            if (class_counts >= 2).all():
                stratify = df[label_col]
        
        # First split train vs (val + test)
        temp_size = val_size + test_size
        df_train, df_temp = train_test_split(
            df, 
            test_size=temp_size, 
            random_state=self.random_state, 
            stratify=stratify
        )
        
        # Second split val vs test with safety check
        temp_stratify = None
        if label_col in df_temp.columns:
            temp_counts = df_temp[label_col].value_counts()
            if (temp_counts >= 2).all():
                temp_stratify = df_temp[label_col]
                
        val_ratio = val_size / temp_size
        df_val, df_test = train_test_split(
            df_temp, 
            test_size=(1.0 - val_ratio), 
            random_state=self.random_state, 
            stratify=temp_stratify
        )
        
        return df_train.reset_index(drop=True), df_val.reset_index(drop=True), df_test.reset_index(drop=True)

    def save(self, filepath: str):
        joblib.dump(self, filepath)
        
    @staticmethod
    def load(filepath: str) -> "DataPipeline":
        return joblib.load(filepath)
