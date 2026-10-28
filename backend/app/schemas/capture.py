from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from .common import EvidenceItem, ObservationProvenance

class IKETransform(BaseModel):
    transform_type: str = Field(..., description="Transform type: ENCR, PRF, INTEG, D-H, ESN")
    transform_id: int = Field(..., description="Numeric transform ID")
    transform_name: str = Field(..., description="Standard cryptographic algorithm name (e.g., ENCR_AES_GCM_16, DH_GROUP_19)")
    key_length: Optional[int] = Field(None, description="Key length in bits if specified in attribute")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Raw transform attributes")

class IKEProposal(BaseModel):
    proposal_num: int = Field(..., description="Proposal sequence number")
    protocol_id: str = Field(..., description="Protocol: IKE or ESP")
    spi: Optional[str] = Field(None, description="SPI hex string")
    transforms: List[IKETransform] = Field(default_factory=list, description="List of proposed transforms")

class ESPObservation(BaseModel):
    packet_index: int
    timestamp: float
    spi: str
    seq: int
    packet_length: int
    payload_hex_preview: str = Field(..., description="Hex snippet of ciphertext (never full sensitive payload)")
    inferred_encryption_state: str = Field("ENCRYPTED_OPAQUE", description="Payload visibility status")

class PacketSummary(BaseModel):
    index: int
    timestamp: float
    length: int
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = Field(..., description="UDP, ESP, etc.")
    summary: str
    is_ike: bool = False
    is_esp: bool = False
    ike_version: Optional[str] = None  # "IKEv1" or "IKEv2"
    exchange_type: Optional[str] = None # e.g. "IKE_SA_INIT", "IKE_AUTH", "Quick Mode"
    message_id: Optional[int] = None
    is_initiator: Optional[bool] = None
    initiator_spi: Optional[str] = None
    responder_spi: Optional[str] = None
    payload_types: List[str] = Field(default_factory=list)
    proposals: List[IKEProposal] = Field(default_factory=list)
    esp_spi: Optional[str] = None
    esp_seq: Optional[int] = None
    parser_warnings: List[str] = Field(default_factory=list)

class SessionSummary(BaseModel):
    session_id: str
    initiator_ip: str
    responder_ip: str
    initiator_port: int
    responder_port: int
    initiator_spi: Optional[str] = None
    responder_spi: Optional[str] = None
    ike_version: Optional[str] = None
    exchange_types_observed: List[str] = Field(default_factory=list)
    packet_count: int = 0
    start_time: float
    end_time: float
    duration_seconds: float = 0.0
    packets: List[int] = Field(default_factory=list, description="Packet indices belonging to session")
    proposals_offered: List[IKEProposal] = Field(default_factory=list)
    proposals_chosen: List[IKEProposal] = Field(default_factory=list)
    esp_packet_count: int = 0
    esp_spis: List[str] = Field(default_factory=list)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    completeness_score: float = 1.0
    limitations: List[str] = Field(default_factory=list)

class CaptureAnalysisResult(BaseModel):
    capture_id: str
    filename: str
    file_hash_sha256: Optional[str] = "unknown"
    file_size_bytes: int
    uploaded_at: str
    status: str = "READY"
    error_message: Optional[str] = None
    total_packets: int
    ike_packets: int
    esp_packets: int
    other_packets: int
    session_count: int
    parse_completeness_pct: float
    parser_backend: str = "scapy_native" # "scapy_native" or "tshark_adapter"
    parser_warnings: List[str] = Field(default_factory=list)
    sessions: List[SessionSummary] = Field(default_factory=list)
    packets: List[PacketSummary] = Field(default_factory=list)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
