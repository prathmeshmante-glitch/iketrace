from fastapi import APIRouter
from typing import List

from ..schemas.audit import AuditRecord, AuditVerificationResult
from ..services.audit_service import audit_service

router = APIRouter(prefix="/audit", tags=["Audit"])

@router.get("/records", response_model=List[AuditRecord])
def get_audit_records():
    return audit_service.get_records()

@router.get("/verify", response_model=AuditVerificationResult)
def verify_audit_chain():
    return audit_service.verify_chain()
