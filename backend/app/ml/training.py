import random
from typing import List, Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit

from .feature_extraction import extract_flow_features
from ..schemas.traffic_privacy import TrafficFlowFeatures

FEATURE_COLUMNS = [
    "packet_count",
    "total_bytes",
    "duration_seconds",
    "mean_packet_size",
    "std_packet_size",
    "min_packet_size",
    "max_packet_size",
    "mean_iat_ms",
    "std_iat_ms",
    "burst_count",
    "mean_burst_bytes",
    "forward_backward_ratio",
]

def generate_synthetic_flow_dataset(num_sessions_per_class: int = 15) -> Tuple[List[TrafficFlowFeatures], List[str]]:
    """
    Generate synthetic encrypted traffic traces partitioned by session IDs.
    Demonstrates metadata inference capabilities without touching real network traffic.
    """
    random.seed(42)
    np.random.seed(42)

    features_list: List[TrafficFlowFeatures] = []
    group_ids: List[str] = []

    classes = [
        ("Bulk_Transfer", 1420, 20.0, 5.0, 3.0),
        ("Interactive_Terminal", 95, 25.0, 350.0, 150.0),
        ("VoIP_Call", 180, 5.0, 20.0, 2.0),
        ("API_Telemetry", 650, 120.0, 2500.0, 800.0),
    ]

    for label, base_sz, sz_var, base_iat, iat_var in classes:
        for s_idx in range(num_sessions_per_class):
            session_id = f"sess-{label.lower()}-{s_idx:02d}"
            # Each session generates 3-5 distinct flow segments
            num_flows = random.randint(3, 5)
            for f_idx in range(num_flows):
                flow_id = f"{session_id}-flow{f_idx}"
                pkt_count = random.randint(40, 120) if label != "Bulk_Transfer" else random.randint(150, 400)

                # Generate packet sizes
                if label == "Bulk_Transfer":
                    # 85% full MTU data packets, 15% TCP ACKs (~64 bytes)
                    sizes = [1420 if random.random() > 0.15 else random.randint(52, 70) for _ in range(pkt_count)]
                    dirs = [1 if s > 200 else -1 for s in sizes]
                elif label == "Interactive_Terminal":
                    # Small human keystrokes
                    sizes = [int(np.clip(np.random.normal(base_sz, sz_var), 54, 250)) for _ in range(pkt_count)]
                    dirs = [1 if i % 2 == 0 else -1 for i in range(pkt_count)]
                elif label == "VoIP_Call":
                    # Regular audio payload
                    sizes = [int(np.clip(np.random.normal(base_sz, sz_var), 140, 220)) for _ in range(pkt_count)]
                    dirs = [1 if i % 2 == 0 else -1 for i in range(pkt_count)]
                else: # API_Telemetry
                    sizes = [int(np.clip(np.random.normal(base_sz, sz_var), 200, 1100)) for _ in range(pkt_count)]
                    dirs = [1 if random.random() > 0.4 else -1 for _ in range(pkt_count)]

                # Generate timestamps
                cur_t = 0.0
                timestamps = []
                for _ in range(pkt_count):
                    cur_t += max(0.001, np.random.normal(base_iat / 1000.0, iat_var / 1000.0))
                    timestamps.append(cur_t)

                feat = extract_flow_features(
                    flow_id=flow_id,
                    session_id=session_id,
                    packet_sizes=sizes,
                    timestamps=timestamps,
                    directions=dirs,
                    ground_truth=label
                )
                features_list.append(feat)
                group_ids.append(session_id)

    return features_list, group_ids


def train_baseline_model(
    features_list: List[TrafficFlowFeatures],
    group_ids: List[str]
) -> Tuple[RandomForestClassifier, List[TrafficFlowFeatures], List[TrafficFlowFeatures], np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Train Random Forest classifier with GroupShuffleSplit to prevent session leakage."""
    data = []
    labels = []
    for f in features_list:
        row = [getattr(f, col) for col in FEATURE_COLUMNS]
        data.append(row)
        labels.append(f.ground_truth_label)

    X = np.array(data)
    y = np.array(labels)
    groups = np.array(group_ids)

    # GroupShuffleSplit ensures entire sessions are either in train or test
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]

    train_feats = [features_list[i] for i in train_idx]
    test_feats = [features_list[i] for i in test_idx]

    clf = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42)
    clf.fit(X_train, y_train)

    return clf, train_feats, test_feats, X_train, X_test, y_train, y_test
