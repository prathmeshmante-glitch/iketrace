import pytest
from backend.app.services.scenario_engine import scenario_engine

def test_all_standard_scenarios_execute():
    scenarios = scenario_engine.list_scenarios()
    assert len(scenarios) == 8, f"Expected 8 standard scenarios, found {len(scenarios)}"

    for s in scenarios:
        res = scenario_engine.execute_scenario(s.scenario_id)
        assert res.is_synthetic is True, "Must explicitly be labeled as synthetic"
        assert res.status == "PASSED", f"Scenario {s.scenario_id} did not pass: {res.execution_log[-1]}"
        assert res.all_assertions_met is True
