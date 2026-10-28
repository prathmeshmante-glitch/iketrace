from fastapi import APIRouter
from typing import Dict, Any
from pydantic import BaseModel

from ..schemas.traffic_privacy import (
    ModelEvaluationReport,
    PrivacyExposureSummary,
    TrafficFlowFeatures,
)
from ..services.traffic_privacy import traffic_privacy_service
from ..services.audit_service import audit_service

router = APIRouter(prefix="/traffic-privacy", tags=["TrafficPrivacy"])

class RetrainRequest(BaseModel):
    num_sessions_per_class: int = 15

@router.get("/model", response_model=ModelEvaluationReport)
def get_model_evaluation():
    return traffic_privacy_service.get_latest_evaluation()

@router.post("/retrain", response_model=ModelEvaluationReport)
def retrain_model(req: RetrainRequest = RetrainRequest()):
    report = traffic_privacy_service.run_training_experiment(req.num_sessions_per_class)
    audit_service.record_event(
        event_type="ML_EXPERIMENT_TRAINED",
        entity_id="TRAFFIC_CLASSIFIER_RF",
        entity_type="ML_MODEL",
        data={
            "accuracy": report.accuracy,
            "f1_macro": report.f1_macro,
            "test_samples": report.test_samples_count,
        }
    )
    return report

@router.post("/classify")
def classify_flow(flow: TrafficFlowFeatures):
    return traffic_privacy_service.classify_flow(flow)

@router.get("/exposure", response_model=PrivacyExposureSummary)
def get_privacy_exposure():
    return traffic_privacy_service.get_privacy_exposure_summary()
