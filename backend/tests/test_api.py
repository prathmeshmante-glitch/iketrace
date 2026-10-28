import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data

def test_api_list_policies():
    res = client.get("/api/policies")
    assert res.status_code == 200
    policies = res.json()
    assert len(policies) >= 2
    ids = [p["policy_id"] for p in policies]
    assert "POL-DEF-CNSA-2.0" in ids
    assert "POL-DEF-NIST-SP800-77" in ids

def test_api_scenarios_and_execution():
    res = client.get("/api/scenarios")
    assert res.status_code == 200
    scenarios = res.json()
    assert len(scenarios) == 8

    # Run scenario 1
    run_res = client.post("/api/scenarios/SCEN-01-SECURE-BASELINE/run")
    assert run_res.status_code == 200
    data = run_res.json()
    assert data["status"] == "PASSED"
    assert data["all_assertions_met"] is True

def test_api_traffic_privacy_model():
    res = client.get("/api/traffic-privacy/model")
    assert res.status_code == 200
    data = res.json()
    assert "accuracy" in data
    assert "confusion_matrix" in data
    assert "feature_importances" in data

def test_api_audit_verify():
    res = client.get("/api/audit/verify")
    assert res.status_code == 200
    data = res.json()
    assert "chain_intact" in data
