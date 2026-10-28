import os
from pathlib import Path
from pydantic import BaseModel, Field

class Settings(BaseModel):
    app_name: str = "IKETrace - VPN Security Assurance Lab"
    version: str = "1.0.0"
    api_prefix: str = "/api"
    env: str = os.getenv("IKETRACE_ENV", "development")
    max_upload_size_bytes: int = int(os.getenv("IKETRACE_MAX_UPLOAD_MB", "25")) * 1024 * 1024
    capture_dir: Path = Path(os.getenv("IKETRACE_CAPTURE_DIR", "./temp_captures"))
    offline_mode: bool = os.getenv("IKETRACE_OFFLINE_MODE", "true").lower() in ("true", "1", "yes")
    tshark_path: str = os.getenv("IKETRACE_TSHARK_PATH", "")
    ai_api_key: str = os.getenv("IKETRACE_AI_API_KEY", "")

    def ensure_directories(self) -> None:
        self.capture_dir.mkdir(parents=True, exist_ok=True)

settings = Settings()
settings.ensure_directories()
