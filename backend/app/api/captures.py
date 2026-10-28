from fastapi import APIRouter, UploadFile, File, HTTPException
from typing import List

from ..core.config import settings
from ..schemas.capture import CaptureAnalysisResult
from ..services.capture_service import capture_service
from ..services.audit_service import audit_service

router = APIRouter(prefix="/captures", tags=["Captures"])

@router.post("/upload", response_model=CaptureAnalysisResult)
async def upload_capture(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename missing.")

    content = await file.read()
    if len(content) > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum upload limit of {settings.max_upload_size_bytes // (1024*1024)}MB."
        )

    is_valid, reason = capture_service.validate_file_header(content)
    if not is_valid:
        raise HTTPException(status_code=400, detail=reason)

    capture_id, temp_path = capture_service.save_temp_capture(file.filename, content)
    analysis = capture_service.analyze_capture(capture_id, file.filename, temp_path)

    # Record audit event
    audit_service.record_event(
        event_type="CAPTURE_UPLOADED",
        entity_id=capture_id,
        entity_type="CAPTURE",
        data={
            "filename": file.filename,
            "size": len(content),
            "packets": analysis.total_packets,
            "ike_packets": analysis.ike_packets,
            "sessions": analysis.session_count,
        }
    )

    return analysis

@router.get("", response_model=List[CaptureAnalysisResult])
def list_captures():
    return capture_service.list_analyses()

@router.get("/{capture_id}", response_model=CaptureAnalysisResult)
def get_capture(capture_id: str):
    analysis = capture_service.get_analysis(capture_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Capture analysis for {capture_id} not found.")
    return analysis
