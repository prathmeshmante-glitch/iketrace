from fastapi import APIRouter
from ..core.config import settings
from ..services.protocol_parser import TSharkProtocolAdapter

router = APIRouter(prefix="/health", tags=["Health"])

@router.get("")
def get_health():
    tshark = TSharkProtocolAdapter(settings.tshark_path)
    return {
        "status": "healthy",
        "app_name": settings.app_name,
        "version": settings.version,
        "offline_mode": settings.offline_mode,
        "tshark_available": tshark.is_available,
        "tshark_executable": tshark.tshark_executable if tshark.is_available else "Not installed (pure Scapy fallback active)"
    }
