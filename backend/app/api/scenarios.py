from fastapi import APIRouter, HTTPException
from typing import List
from pydantic import BaseModel

from ..schemas.scenario import ScenarioDefinition, ScenarioResult
from ..services.scenario_engine import scenario_engine
from ..services.audit_service import audit_service

router = APIRouter(prefix="/scenarios", tags=["Scenarios"])

class RunScenarioRequest(BaseModel):
    policy_id: str = "POL-DEF-NIST-SP800-77"

@router.get("", response_model=List[ScenarioDefinition])
def list_scenarios():
    return scenario_engine.list_scenarios()

@router.get("/{scenario_id}", response_model=ScenarioDefinition)
def get_scenario(scenario_id: str):
    scen = scenario_engine.get_scenario(scenario_id)
    if not scen:
        raise HTTPException(status_code=404, detail=f"Scenario {scenario_id} not found.")
    return scen

@router.post("/{scenario_id}/run", response_model=ScenarioResult)
def run_scenario(scenario_id: str, req: RunScenarioRequest = RunScenarioRequest()):
    try:
        res = scenario_engine.execute_scenario(scenario_id, req.policy_id)
        audit_service.record_event(
            event_type="SCENARIO_EXECUTED",
            entity_id=scenario_id,
            entity_type="SCENARIO",
            data={
                "scenario_id": scenario_id,
                "status": res.status,
                "all_assertions_met": res.all_assertions_met,
            }
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/run-all", response_model=List[ScenarioResult])
def run_all_scenarios(req: RunScenarioRequest = RunScenarioRequest()):
    results: List[ScenarioResult] = []
    for s in scenario_engine.list_scenarios():
        res = scenario_engine.execute_scenario(s.scenario_id, req.policy_id)
        results.append(res)
    audit_service.record_event(
        event_type="ALL_SCENARIOS_EXECUTED",
        entity_id="ALL_SCENARIOS",
        entity_type="SCENARIO_BATCH",
        data={"count": len(results), "all_passed": all(r.all_assertions_met for r in results)}
    )
    return results
