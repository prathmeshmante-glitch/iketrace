import pytest
from backend.app.ml.training import generate_synthetic_flow_dataset, train_baseline_model
from backend.app.ml.evaluation import evaluate_trained_model
from backend.app.ml.inference import predict_flow_class

def test_ml_workflow_zero_leakage_and_metrics():
    feats, groups = generate_synthetic_flow_dataset(num_sessions_per_class=10)
    assert len(feats) > 0

    clf, train_feats, test_feats, X_tr, X_te, y_tr, y_te = train_baseline_model(feats, groups)

    # Verify zero session leakage: no session ID in train appears in test
    train_sessions = {f.session_id for f in train_feats}
    test_sessions = {f.session_id for f in test_feats}
    overlap = train_sessions.intersection(test_sessions)
    assert len(overlap) == 0, f"Data leakage detected! Sessions in both sets: {overlap}"

    # Evaluate on held-out test data
    report = evaluate_trained_model(clf, X_tr, X_te, y_tr, y_te, test_feats)
    assert 0.0 <= report.accuracy <= 1.0
    assert report.test_samples_count == len(X_te)
    assert len(report.confusion_matrix.class_labels) > 0
    assert len(report.feature_importances) > 0

    # Test inference on a single sample
    pred_res = predict_flow_class(clf, test_feats[0])
    assert "predicted_class" in pred_res
    assert "confidence" in pred_res
    assert 0.0 <= pred_res["confidence"] <= 1.0
