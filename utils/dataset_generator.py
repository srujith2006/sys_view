"""
Realistic CIC-IDS2017 Network Flow Generator for Benchmarking and Prototyping.
Generates authentic flow telemetry with representative distributions for Benign and Attack categories.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random

def generate_cicids2017_flows(n_samples=2500, random_state=42):
    """
    Generate synthetic yet statistically grounded network flows adhering to CIC-IDS2017 schema.
    
    Classes:
      - BENIGN (~60%)
      - DDoS (~15%)
      - PortScan (~10%)
      - BruteForce (~8%)
      - Botnet (~4%)
      - Infiltration (~3%)
    """
    np.random.seed(random_state)
    random.seed(random_state)
    
    # Class distribution
    class_probs = [0.60, 0.15, 0.10, 0.08, 0.04, 0.03]
    classes = ["BENIGN", "DDoS", "PortScan", "BruteForce", "Botnet", "Infiltration"]
    
    labels = np.random.choice(classes, size=n_samples, p=class_probs)
    
    # Realistic IP pools
    internal_ips = [f"192.168.1.{i}" for i in range(10, 80)]
    server_ips = ["192.168.1.5", "192.168.1.6", "172.16.0.1", "10.0.0.10"]
    external_ips = [
        f"{random.randint(40, 210)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        for _ in range(50)
    ]
    
    start_time = datetime(2026, 7, 7, 9, 0, 0)
    
    rows = []
    for i, label in enumerate(labels):
        flow_time = start_time + timedelta(seconds=i * 0.4 + np.random.uniform(0, 0.2))
        time_str = flow_time.strftime("%d/%m/%Y %H:%M:%S")
        
        # Behavior modeling per class
        if label == "BENIGN":
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips + server_ips)
            src_port = random.randint(32768, 61000)
            dst_port = random.choice([80, 443, 53, 8080, 22])
            proto = 6 if dst_port != 53 else 17  # TCP or UDP
            
            flow_duration = float(np.random.exponential(scale=350000) + 100)
            total_fwd_pkts = int(np.random.poisson(lam=12) + 2)
            total_bwd_pkts = int(np.random.poisson(lam=14) + 1)
            fwd_pkt_len_mean = float(np.clip(np.random.normal(loc=280, scale=80), 40, 1460))
            bwd_pkt_len_mean = float(np.clip(np.random.normal(loc=650, scale=200), 40, 1500))
            syn_count = 1 if proto == 6 else 0
            ack_count = total_fwd_pkts + total_bwd_pkts - 1 if proto == 6 else 0
            rst_count = 0
            psh_count = int(np.random.binomial(n=5, p=0.3))
            
        elif label == "DDoS":
            src_ip = random.choice(external_ips)
            dst_ip = "192.168.1.5"  # Targeted web server
            src_port = random.randint(1024, 65535)
            dst_port = 80
            proto = 6
            
            flow_duration = float(np.random.uniform(500, 20000))
            total_fwd_pkts = int(np.random.uniform(80, 500))
            total_bwd_pkts = int(np.random.uniform(0, 4))   # Server cannot respond
            fwd_pkt_len_mean = float(np.random.uniform(300, 1200))
            bwd_pkt_len_mean = float(np.random.uniform(0, 60))
            syn_count = int(total_fwd_pkts * 0.9)  # Heavy SYN flood
            ack_count = int(np.random.uniform(0, 5))
            rst_count = int(np.random.uniform(0, 3))
            psh_count = int(np.random.uniform(0, 2))
            
        elif label == "PortScan":
            src_ip = random.choice(external_ips)
            dst_ip = random.choice(server_ips)
            src_port = random.randint(40000, 60000)
            dst_port = random.randint(20, 1024)   # Scanning low ports
            proto = 6
            
            flow_duration = float(np.random.uniform(10, 2500))
            total_fwd_pkts = int(np.random.choice([1, 2, 3]))
            total_bwd_pkts = int(np.random.choice([0, 1]))
            fwd_pkt_len_mean = float(np.random.uniform(0, 60))
            bwd_pkt_len_mean = float(np.random.uniform(0, 60))
            syn_count = total_fwd_pkts
            ack_count = 0
            rst_count = 1 if total_bwd_pkts > 0 else 0
            psh_count = 0
            
        elif label == "BruteForce":
            src_ip = random.choice(external_ips)
            dst_ip = "192.168.1.6"  # SSH/FTP server
            src_port = random.randint(30000, 50000)
            dst_port = random.choice([22, 21])
            proto = 6
            
            flow_duration = float(np.random.uniform(15000, 180000))
            total_fwd_pkts = int(np.random.uniform(15, 60))
            total_bwd_pkts = int(np.random.uniform(15, 60))
            fwd_pkt_len_mean = float(np.random.uniform(90, 180))
            bwd_pkt_len_mean = float(np.random.uniform(80, 170))
            syn_count = 1
            ack_count = total_fwd_pkts + total_bwd_pkts
            rst_count = 1
            psh_count = int(total_fwd_pkts * 0.6)  # Auth attempts pushed
            
        elif label == "Botnet":
            src_ip = random.choice(internal_ips)
            dst_ip = random.choice(external_ips)
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([6667, 8088, 4444])  # C2 ports
            proto = 6
            
            flow_duration = float(np.random.uniform(80000, 900000))
            total_fwd_pkts = int(np.random.uniform(6, 25))
            total_bwd_pkts = int(np.random.uniform(4, 20))
            fwd_pkt_len_mean = float(np.random.uniform(40, 120))
            bwd_pkt_len_mean = float(np.random.uniform(40, 120))
            syn_count = 1
            ack_count = total_fwd_pkts + total_bwd_pkts
            rst_count = 0
            psh_count = int(np.random.uniform(2, 8))
            
        else:  # Infiltration / Novel Anomaly candidate
            src_ip = random.choice(external_ips)
            dst_ip = random.choice(server_ips)
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1024, 65535)
            proto = 6
            
            flow_duration = float(np.random.uniform(50000, 600000))
            total_fwd_pkts = int(np.random.uniform(30, 150))
            total_bwd_pkts = int(np.random.uniform(10, 80))
            fwd_pkt_len_mean = float(np.random.uniform(400, 1400))
            bwd_pkt_len_mean = float(np.random.uniform(200, 900))
            syn_count = int(np.random.choice([1, 2]))
            ack_count = total_fwd_pkts + total_bwd_pkts
            rst_count = int(np.random.choice([0, 1]))
            psh_count = int(np.random.uniform(5, 20))
            
        # Computed telemetry metrics
        tot_fwd_len = total_fwd_pkts * fwd_pkt_len_mean
        tot_bwd_len = total_bwd_pkts * bwd_pkt_len_mean
        dur_sec = max(flow_duration / 1e6, 0.0001)
        flow_bytes_s = (tot_fwd_len + tot_bwd_len) / dur_sec
        flow_pkts_s = (total_fwd_pkts + total_bwd_pkts) / dur_sec
        
        flow_id = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
        
        rows.append({
            "Flow ID": flow_id,
            "Source IP": src_ip,
            "Source Port": src_port,
            "Destination IP": dst_ip,
            "Destination Port": dst_port,
            "Protocol": proto,
            "Timestamp": time_str,
            "Flow Duration": flow_duration,
            "Total Fwd Packets": total_fwd_pkts,
            "Total Backward Packets": total_bwd_pkts,
            "Total Length of Fwd Packets": tot_fwd_len,
            "Total Length of Bwd Packets": tot_bwd_len,
            "Fwd Packet Length Max": fwd_pkt_len_mean * 1.5,
            "Fwd Packet Length Min": max(0, fwd_pkt_len_mean * 0.4),
            "Fwd Packet Length Mean": fwd_pkt_len_mean,
            "Bwd Packet Length Max": bwd_pkt_len_mean * 1.5,
            "Bwd Packet Length Min": max(0, bwd_pkt_len_mean * 0.3),
            "Bwd Packet Length Mean": bwd_pkt_len_mean,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_duration / max(total_fwd_pkts + total_bwd_pkts - 1, 1),
            "Flow IAT Std": (flow_duration / max(total_fwd_pkts + total_bwd_pkts - 1, 1)) * 0.4,
            "Flow IAT Max": flow_duration * 0.6,
            "Flow IAT Min": max(1.0, flow_duration * 0.02),
            "Fwd IAT Total": flow_duration * 0.9,
            "Bwd IAT Total": flow_duration * 0.8,
            "Fwd PSH Flags": 1 if psh_count > 0 else 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 0,
            "Bwd URG Flags": 0,
            "Fwd Header Length": total_fwd_pkts * 20,
            "Bwd Header Length": total_bwd_pkts * 20,
            "Fwd Packets/s": total_fwd_pkts / dur_sec,
            "Bwd Packets/s": total_bwd_pkts / dur_sec,
            "Min Packet Length": min(fwd_pkt_len_mean * 0.4, bwd_pkt_len_mean * 0.3),
            "Max Packet Length": max(fwd_pkt_len_mean * 1.5, bwd_pkt_len_mean * 1.5),
            "Packet Length Mean": (tot_fwd_len + tot_bwd_len) / max(total_fwd_pkts + total_bwd_pkts, 1),
            "Packet Length Std": abs(fwd_pkt_len_mean - bwd_pkt_len_mean) * 0.5,
            "FIN Flag Count": 1 if label == "BENIGN" else 0,
            "SYN Flag Count": syn_count,
            "RST Flag Count": rst_count,
            "PSH Flag Count": psh_count,
            "ACK Flag Count": ack_count,
            "URG Flag Count": 0,
            "Down/Up Ratio": total_bwd_pkts / max(total_fwd_pkts, 1),
            "Average Packet Size": (tot_fwd_len + tot_bwd_len) / max(total_fwd_pkts + total_bwd_pkts, 1),
            "Avg Fwd Segment Size": fwd_pkt_len_mean,
            "Avg Bwd Segment Size": bwd_pkt_len_mean,
            "Subflow Fwd Packets": total_fwd_pkts,
            "Subflow Fwd Bytes": tot_fwd_len,
            "Subflow Bwd Packets": total_bwd_pkts,
            "Subflow Bwd Bytes": tot_bwd_len,
            "Init_Win_bytes_forward": int(np.random.choice([8192, 29200, 65535])),
            "Init_Win_bytes_backward": int(np.random.choice([0, 8192, 29200])),
            "act_data_pkt_fwd": max(0, total_fwd_pkts - 2),
            "min_seg_size_forward": 20,
            "Active Mean": flow_duration * 0.1,
            "Idle Mean": flow_duration * 0.2,
            "Label": label
        })
        
    df = pd.DataFrame(rows)
    return df

if __name__ == "__main__":
    from config import RAW_DATA_DIR
    df = generate_cicids2017_flows(n_samples=3000)
    out_path = RAW_DATA_DIR / "cicids2017_sample.csv"
    df.to_csv(out_path, index=False)
    print(f"Generated {len(df)} realistic flows at {out_path}")
    print("Class distribution:")
    print(df["Label"].value_counts())
