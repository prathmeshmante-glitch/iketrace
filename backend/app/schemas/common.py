from enum import Enum
from typing import Optional, Any, Dict, List
from pydantic import BaseModel, Field

class ObservationProvenance(str, Enum):
    DIRECTLY_OBSERVED = "DIRECTLY_OBSERVED"
    DETERMINISTICALLY_DERIVED = "DETERMINISTICALLY_DERIVED"
    SUPPLIED_CONFIGURATION = "SUPPLIED_CONFIGURATION"
    EXPERIMENTALLY_VERIFIED = "EXPERIMENTALLY_VERIFIED"
    UNKNOWN_OR_UNSUPPORTED = "UNKNOWN_OR_UNSUPPORTED"

class EvaluationOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class EvidenceSufficiency(str, Enum):
    SUFFICIENT = "SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    ABSENT = "ABSENT"

class EvidenceItem(BaseModel):
    id: str = Field(..., description="Unique evidence identifier")
    field_name: str = Field(..., description="Name of the observed field or property")
    observed_value: Any = Field(..., description="Raw or formatted observed value")
    source_reference: str = Field(..., description="Packet index, byte offset, or configuration file line")
    observation_method: str = Field("scapy_dissector", description="Dissector or extraction routine used")
    provenance: ObservationProvenance = Field(..., description="Provenance categorization")
    sufficiency: EvidenceSufficiency = Field(EvidenceSufficiency.SUFFICIENT, description="Sufficiency of this observation")
    timestamp: Optional[float] = Field(None, description="Packet timestamp if available")
    limitations: Optional[str] = Field(None, description="Known parser or observation limitations")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
