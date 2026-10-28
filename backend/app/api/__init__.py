from fastapi import APIRouter

from .health import router as health_router
from .captures import router as captures_router
from .analyses import router as analyses_router
from .policies import router as policies_router
from .scenarios import router as scenarios_router
from .drift import router as drift_router
from .traffic_privacy import router as traffic_privacy_router
from .crypto_inventory import router as crypto_inventory_router
from .evidence_graph import router as evidence_graph_router
from .reports import router as reports_router
from .audit import router as audit_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(captures_router)
api_router.include_router(analyses_router)
api_router.include_router(policies_router)
api_router.include_router(scenarios_router)
api_router.include_router(drift_router)
api_router.include_router(traffic_privacy_router)
api_router.include_router(crypto_inventory_router)
api_router.include_router(evidence_graph_router)
api_router.include_router(reports_router)
api_router.include_router(audit_router)
