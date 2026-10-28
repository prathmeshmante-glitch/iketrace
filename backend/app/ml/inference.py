from typing import Dict, Any, List
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from .training import FEATURE_COLUMNS
from ..schemas.traffic_privacy import TrafficFlowFeatures

def predict_flow_class(clf: RandomForestClassifier, flow_features: TrafficFlowFeatures) -> Dict[str, Any]:
    """Predict traffic class and confidence scores for a flow using its statistical features."""
    row = [getattr(flow_features, col) for col in FEATURE_COLUMNS]
    X = np.array([row])
    pred_label = clf.predict(X)[0]
    probs = clf.predict_proba(X)[0]
    classes = clf.classes_

    prob_dict = {str(c): round(float(p), 4) for c, p in zip(classes, probs)}
    confidence = float(np.max(probs))

    return {
        "flow_id": flow_features.flow_id,
        "predicted_class": str(pred_label),
        "confidence": round(confidence, 4),
        "class_probabilities": prob_dict,
        "inferred_properties": {
            "is_interactive": bool(pred_label == "Interactive_Terminal"),
            "is_bulk_transfer": bool(pred_label == "Bulk_Transfer"),
            "is_voice_or_realtime": bool(pred_label == "VoIP_Call"),
            "is_periodic_api": bool(pred_label == "API_Telemetry"),
        },
        "privacy_disclosure_note": (
            "Inference is derived exclusively from encrypted packet sizing and timing distributions. "
            "No plaintext or cleartext headers within the ESP payload were accessed."
        )
    }
