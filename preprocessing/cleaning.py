"""
Data Cleaning Module for Network Intrusion Detection.
Handles infinite values, NaN values, duplicates, and negative duration anomalies.
"""

import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any

def clean_dataset(
    df: pd.DataFrame, 
    impute_medians: Dict[str, float] = None,
    is_training: bool = True
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Clean network traffic dataset:
    - Strips whitespace from column names.
    - Replaces inf and -inf with NaN.
    - Drops duplicates (if is_training=True).
    - Removes rows with negative or nonsensical flow duration.
    - Imputes missing numerical values using training medians.
    
    Returns:
        cleaned_df: Cleaned pandas DataFrame
        stats: Dictionary containing cleaning metrics (duplicates removed, nulls imputed, etc.)
    """
    initial_rows = len(df)
    df_clean = df.copy()
    
    # Strip whitespace from column headers
    df_clean.columns = [c.strip() for c in df_clean.columns]
    
    # Numerical column identification
    num_cols = df_clean.select_dtypes(include=[np.number]).columns.tolist()
    
    # Count initial infinities
    inf_count = 0
    for col in num_cols:
        inf_mask = np.isinf(df_clean[col])
        inf_count += int(inf_mask.sum())
        if inf_mask.any():
            df_clean[col] = df_clean[col].replace([np.inf, -np.inf], np.nan)
            
    # Remove negative flow duration if present
    invalid_durations = 0
    duration_cols = [c for c in df_clean.columns if "duration" in c.lower()]
    for col in duration_cols:
        neg_mask = df_clean[col] < 0
        invalid_durations += int(neg_mask.sum())
        df_clean = df_clean[~neg_mask]
        
    # Duplicate removal (during training)
    duplicates_removed = 0
    if is_training:
        dup_mask = df_clean.duplicated()
        duplicates_removed = int(dup_mask.sum())
        df_clean = df_clean.drop_duplicates().reset_index(drop=True)
        
    # Impute missing values
    learned_medians = {}
    null_imputed_count = int(df_clean[num_cols].isna().sum().sum())
    
    if is_training:
        for col in num_cols:
            median_val = float(df_clean[col].median(skipna=True))
            if np.isnan(median_val):
                median_val = 0.0
            learned_medians[col] = median_val
            df_clean[col] = df_clean[col].fillna(median_val)
    else:
        if impute_medians is not None:
            for col, med in impute_medians.items():
                if col in df_clean.columns:
                    df_clean[col] = df_clean[col].fillna(med)
        # Fallback for remaining NaNs
        df_clean[num_cols] = df_clean[num_cols].fillna(0.0)
        
    final_rows = len(df_clean)
    
    stats = {
        "initial_rows": initial_rows,
        "final_rows": final_rows,
        "rows_removed": initial_rows - final_rows,
        "infinities_handled": inf_count,
        "duplicates_removed": duplicates_removed,
        "invalid_durations_dropped": invalid_durations,
        "nulls_imputed": null_imputed_count,
        "impute_medians": learned_medians if is_training else impute_medians
    }
    
    return df_clean, stats
