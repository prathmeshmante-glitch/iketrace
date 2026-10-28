from datetime import datetime, timezone
from typing import Dict, Any, List
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score

from .training import FEATURE_COLUMNS
from ..schemas.traffic_privacy import ModelEvaluationReport, ConfusionMatrixData, TrafficFlowFeatures

def evaluate_trained_model(
    clf: RandomForestClassifier,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    test_feats: List[TrafficFlowFeatures]
) -> ModelEvaluationReport:
    """Calculate verified, actual evaluation metrics strictly on held-out test data."""
    now_str = datetime.now(timezone.utc).isoformat()
    y_pred = clf.predict(X_test)
    labels = sorted(list(set(y_train)))

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="macro", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="macro", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))

    # Per class F1
    per_class_f1_vals = f1_score(y_test, y_pred, average=None, labels=labels, zero_division=0)
    per_class_dict = {label: float(val) for label, val in zip(labels, per_class_f1_vals)}

    # Feature importances
    importances = clf.feature_importances_
    feat_imp_dict = {col: round(float(imp), 4) for col, imp in zip(FEATURE_COLUMNS, importances)}
    # Sort descending
    sorted_feat_imp = dict(sorted(feat_imp_dict.items(), key=lambda item: item[1], reverse=True))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    cm_list = [[int(cell) for cell in row] for row in cm]

    # Sample comparison between predictions and truth
    sample_comps = []
    for i in range(min(10, len(test_feats))):
        sample_comps.append({
            "flow_id": test_feats[i].flow_id,
            "session_id": test_feats[i].session_id,
            "mean_packet_size": test_feats[i].mean_packet_size,
            "mean_iat_ms": test_feats[i].mean_iat_ms,
            "ground_truth": str(y_test[i]),
            "predicted_label": str(y_pred[i]),
            "correct": bool(y_test[i] == y_pred[i]),
        })

    return ModelEvaluationReport(
        model_name="RandomForest-TrafficClassifier-v1",
        model_family="Random Forest Ensemble (50 estimators, max_depth=6)",
        trained_at=now_str,
        train_samples_count=len(X_train),
        test_samples_count=len(X_test),
        cross_validation_strategy="Group-KFold (Session Partitioned, Zero Group Leakage)",
        accuracy=round(acc, 4),
        precision_macro=round(prec, 4),
        recall_macro=round(rec, 4),
        f1_macro=round(f1, 4),
        per_class_f1=per_class_dict,
        feature_importances=sorted_feat_imp,
        confusion_matrix=ConfusionMatrixData(class_labels=labels, matrix=cm_list),
        prediction_vs_truth_sample=sample_comps,
        generalization_limitations=(
            "Model operates strictly on statistical flow metadata (packet lengths, inter-arrival times, burst sizes). "
            "It does NOT decrypt ESP payload data or recover cryptographic keys. "
            "In real-world networks, traffic padding (RFC 4303 Section 2.4) or constant-rate chaffing reduces classification accuracy significantly."
        )
    )
