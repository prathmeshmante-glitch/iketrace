import os
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import settings
from .api import api_router
from .services.capture_service import capture_service
from .services.policy_engine import policy_engine
from .services.drift_engine import drift_engine
from .services.audit_service import audit_service

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Preload sample fixtures if present for seamless demo experience
    sample_dir = Path("sample-data/captures")
    if sample_dir.exists():
        for pcap_file in sample_dir.glob("*.pcap"):
            try:
                cap_id = f"demo-{pcap_file.stem}"
                # Check if already loaded
                if not capture_service.get_analysis(cap_id):
                    analysis = capture_service.analyze_capture(cap_id, pcap_file.name, pcap_file)
                    # Automatically establish baseline for secure baseline
                    if "secure_ikev2_baseline" in pcap_file.name:
                        report = policy_engine.evaluate_capture(analysis, "POL-DEF-NIST-SP800-77")
                        drift_engine.create_baseline(
                            name="Production VPN Gateway Baseline (NIST SP 800-77)",
                            policy_report=report,
                            target_id=cap_id,
                            metadata={"origin": "Initial deployment audit"}
                        )
                    elif "cnsa_2_0_compliant" in pcap_file.name:
                        report_cnsa = policy_engine.evaluate_capture(analysis, "POL-DEF-CNSA-2.0")
                        drift_engine.create_baseline(
                            name="CNSA 2.0 High-Assurance Gateway Baseline",
                            policy_report=report_cnsa,
                            target_id=cap_id,
                            metadata={"origin": "CNSA 2.0 Compliance Audit"}
                        )
            except Exception as e:
                print(f"Error preloading {pcap_file}: {e}")

    yield

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Defensive Cybersecurity Workbench for VPN Security Assurance and Cryptographic Configuration Analysis",
    lifespan=lifespan
)

# Explicit trusted origins for local Vite development & dashboard
trusted_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
if os.getenv("IKETRACE_CORS_ORIGINS"):
    trusted_origins.extend([o.strip() for o in os.getenv("IKETRACE_CORS_ORIGINS", "").split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=trusted_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Mount API router
app.include_router(api_router, prefix=settings.api_prefix)

@app.get("/")
def get_root():
    return {
        "name": settings.app_name,
        "version": settings.version,
        "tagline": "See what your VPN negotiated. Prove what your security policy guarantees.",
        "documentation": "/docs",
        "health": f"{settings.api_prefix}/health",
        "api_prefix": settings.api_prefix
    }
