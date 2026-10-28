import numpy as np
from typing import List, Dict, Any, Tuple
from ..schemas.traffic_privacy import TrafficFlowFeatures

def extract_flow_features(
    flow_id: str,
    session_id: str,
    packet_sizes: List[int],
    timestamps: List[float],
    directions: List[int], # 1 for forward (initiator->responder), -1 for backward
    ground_truth: str = "Unknown"
) -> TrafficFlowFeatures:
    """Extract interpretable statistical features from encrypted packet flow metadata."""
    if not packet_sizes or not timestamps:
        return TrafficFlowFeatures(
            flow_id=flow_id,
            session_id=session_id,
            packet_count=0,
            total_bytes=0,
            duration_seconds=0.0,
            mean_packet_size=0.0,
            std_packet_size=0.0,
            min_packet_size=0,
            max_packet_size=0,
            mean_iat_ms=0.0,
            std_iat_ms=0.0,
            min_iat_ms=0.0,
            max_iat_ms=0.0,
            burst_count=0,
            mean_burst_bytes=0.0,
            forward_backward_ratio=1.0,
            ground_truth_label=ground_truth
        )

    pkt_count = len(packet_sizes)
    tot_bytes = sum(packet_sizes)
    duration = max(0.001, timestamps[-1] - timestamps[0])

    sizes = np.array(packet_sizes, dtype=float)
    mean_sz = float(np.mean(sizes))
    std_sz = float(np.std(sizes))
    min_sz = int(np.min(sizes))
    max_sz = int(np.max(sizes))

    # Inter-arrival times in milliseconds
    iats = np.diff(timestamps) * 1000.0 if len(timestamps) > 1 else np.array([0.0])
    mean_iat = float(np.mean(iats))
    std_iat = float(np.std(iats))
    min_iat = float(np.min(iats))
    max_iat = float(np.max(iats))

    # Detect bursts: sequences of packets with IAT < 20ms in the same direction
    burst_count = 1
    current_burst_bytes = packet_sizes[0]
    burst_bytes_list = []

    for i in range(1, len(packet_sizes)):
        iat = (timestamps[i] - timestamps[i-1]) * 1000.0
        same_dir = (directions[i] == directions[i-1]) if i < len(directions) else True
        if iat < 20.0 and same_dir:
            current_burst_bytes += packet_sizes[i]
        else:
            burst_bytes_list.append(current_burst_bytes)
            burst_count += 1
            current_burst_bytes = packet_sizes[i]
    burst_bytes_list.append(current_burst_bytes)
    mean_burst = float(np.mean(burst_bytes_list)) if burst_bytes_list else 0.0

    # Directionality
    fwd_pkts = sum(1 for d in directions if d >= 0)
    bwd_pkts = max(1, sum(1 for d in directions if d < 0))
    fb_ratio = round(fwd_pkts / bwd_pkts, 3)

    return TrafficFlowFeatures(
        flow_id=flow_id,
        session_id=session_id,
        packet_count=pkt_count,
        total_bytes=tot_bytes,
        duration_seconds=round(duration, 4),
        mean_packet_size=round(mean_sz, 2),
        std_packet_size=round(std_sz, 2),
        min_packet_size=min_sz,
        max_packet_size=max_sz,
        mean_iat_ms=round(mean_iat, 2),
        std_iat_ms=round(std_iat, 2),
        min_iat_ms=round(min_iat, 2),
        max_iat_ms=round(max_iat, 2),
        burst_count=burst_count,
        mean_burst_bytes=round(mean_burst, 2),
        forward_backward_ratio=fb_ratio,
        ground_truth_label=ground_truth
    )
