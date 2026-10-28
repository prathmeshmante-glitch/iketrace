from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class TrafficFlowFeatures(BaseModel):
    flow_id: str
    session_id: str
    packet_count: int
    total_bytes: int
    duration_seconds: float
    mean_packet_size: float
    std_packet_size: float
    min_packet_size: int
    max_packet_size: int
    mean_iat_ms: float
    std_iat_ms: float
    min_iat_ms: float
    max_iat_ms: float
    burst_count: int
    mean_burst_bytes: float
    forward_backward_ratio: float
    ground_truth_label: str # e.g. "Bulk_Transfer", "Interactive_Terminal", "VoIP_Call", "API_Telemetry"

class ConfusionMatrixData(BaseModel):
    class_labels: List[str]
    matrix: List[List[int]]

class ModelEvaluationReport(BaseModel):
    model_name: str
    model_family: str # e.g. "Random Forest Classifier", "Decision Tree"
    trained_at: str
    train_samples_count: int
    test_samples_count: int
    cross_validation_strategy: str = "Group-KFold (No flow leakage across sessions)"
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    per_class_f1: Dict[str, float] = Field(default_factory=dict)
    feature_importances: Dict[str, float] = Field(default_factory=dict)
    confusion_matrix: ConfusionMatrixData
    prediction_vs_truth_sample: List[Dict[str, Any]] = Field(default_factory=list)
    generalization_limitations: str = Field(
        "Metadata-only inference model. Accuracies obtained on controlled synthetic flows. "
        "Does NOT constitute plaintext recovery or secret key compromise. "
        "Performance will degrade with padding, chaffing, or protocol multiplexing."
    )

class PrivacyExposureSummary(BaseModel):
    target_id: str
    analyzed_flows_count: int
    identifiable_classes_count: int
    highest_vulnerability_leakage_feature: str
    mitigation_recommendation: str
    padding_recommendation: str
