import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

from ..core.config import settings
from ..schemas.common import EvidenceItem, ObservationProvenance, EvidenceSufficiency
from ..schemas.capture import (
    CaptureAnalysisResult,
    PacketSummary,
    SessionSummary,
    IKEProposal,
)
from ..repositories.session_repository import session_repository, AnalysisStatus
from .protocol_parser import ScapyProtocolParser, TSharkProtocolAdapter

# Valid PCAP / PCAPNG magic numbers
MAGIC_PCAP_MICRO_BE = b"\xa1\xb2\xc3\xd4"
MAGIC_PCAP_MICRO_LE = b"\xd4\xc3\xb2\xa1"
MAGIC_PCAP_NANO_BE = b"\xa1\xb2\xcd\x34"
MAGIC_PCAP_NANO_LE = b"\x34\xcd\xb2\xa1"
MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"

VALID_CAPTURE_MAGICS = [
    MAGIC_PCAP_MICRO_BE,
    MAGIC_PCAP_MICRO_LE,
    MAGIC_PCAP_NANO_BE,
    MAGIC_PCAP_NANO_LE,
    MAGIC_PCAPNG,
]


class CaptureService:
    def __init__(self):
        self.parser = ScapyProtocolParser()
        self.tshark_adapter = TSharkProtocolAdapter(settings.tshark_path)
        self.in_memory_results: Dict[str, CaptureAnalysisResult] = {}

    def validate_file_header(self, file_bytes: bytes) -> Tuple[bool, str]:
        if len(file_bytes) < 4:
            return False, "File is too small to be a valid PCAP or PCAPNG capture (< 4 bytes)."
            
        magic = file_bytes[:4]
        if magic not in VALID_CAPTURE_MAGICS:
            return False, f"Invalid packet capture signature: {magic.hex()}. Supported: PCAP and PCAPNG."
            
        return True, "Valid capture signature"

    def save_temp_capture(self, filename: str, content: bytes) -> Tuple[str, Path]:
        capture_id = f"cap-{uuid.uuid4().hex[:12]}"
        # Prevent directory traversal and enforce safe characters
        base_name = os.path.basename(filename.replace('\\', '/'))
        clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', base_name) or "unnamed.pcap"
        safe_name = f"{capture_id}_{clean_name}"
        target_path = settings.capture_dir / safe_name
        target_path.write_bytes(content)
        return capture_id, target_path

    def cleanup_temp_capture(self, target_path: Path) -> None:
        """Safely delete temporary capture file after parsing."""
        try:
            if target_path.exists() and target_path.is_file():
                target_path.unlink()
        except Exception:
            pass

    def analyze_capture(self, capture_id: str, filename: str, file_path: Path) -> CaptureAnalysisResult:
        file_size = file_path.stat().st_size
        try:
            file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        except Exception:
            file_hash = "unknown"

        packets, warnings = self.parser.parse_capture(file_path)
        
        ike_packets = [p for p in packets if p.is_ike]
        esp_packets = [p for p in packets if p.is_esp]
        other_packets = [p for p in packets if not p.is_ike and not p.is_esp]

        sessions, evidence_items = self._group_sessions_and_extract_evidence(capture_id, packets)

        completeness = 100.0
        if len(warnings) > 0 and len(packets) > 0:
            completeness = max(10.0, round(100.0 - (len(warnings) / len(packets) * 100.0), 1))
        elif len(packets) == 0:
            completeness = 0.0

        result = CaptureAnalysisResult(
            capture_id=capture_id,
            filename=filename,
            file_hash_sha256=file_hash,
            file_size_bytes=file_size,
            uploaded_at=datetime.now(timezone.utc).isoformat(),
            total_packets=len(packets),
            ike_packets=len(ike_packets),
            esp_packets=len(esp_packets),
            other_packets=len(other_packets),
            session_count=len(sessions),
            parse_completeness_pct=completeness,
            parser_backend="scapy_native",
            parser_warnings=warnings,
            sessions=sessions,
            packets=packets,
            evidence_items=evidence_items,
        )

        self.in_memory_results[capture_id] = result
        try:
            session_repository.save_analysis(result, status=AnalysisStatus.READY)
        except Exception as e:
            # Fallback gracefully if database lock or error occurs
            pass
        return result

    def _group_sessions_and_extract_evidence(
        self, capture_id: str, packets: List[PacketSummary]
    ) -> Tuple[List[SessionSummary], List[EvidenceItem]]:
        sessions_map: Dict[str, Dict[str, Any]] = {}
        all_evidence: List[EvidenceItem] = []

        for p in packets:
            # Create a session key based on endpoints or SPI
            if p.is_ike:
                # Use canonical sorted IP pair + SPI
                ip_pair = tuple(sorted([p.src_ip, p.dst_ip]))
                session_key = f"ike-{ip_pair[0]}_{ip_pair[1]}"
                if p.initiator_spi and p.initiator_spi != "0000000000000000":
                    session_key += f"_{p.initiator_spi[:8]}"
            elif p.is_esp:
                ip_pair = tuple(sorted([p.src_ip, p.dst_ip]))
                session_key = f"esp-{ip_pair[0]}_{ip_pair[1]}_{p.esp_spi or '0x0'}"
            else:
                session_key = f"other-{p.src_ip}_{p.dst_ip}"

            if session_key not in sessions_map:
                sessions_map[session_key] = {
                    "session_id": session_key,
                    "initiator_ip": p.src_ip,
                    "responder_ip": p.dst_ip,
                    "initiator_port": p.src_port or 500,
                    "responder_port": p.dst_port or 500,
                    "initiator_spi": p.initiator_spi,
                    "responder_spi": p.responder_spi,
                    "ike_version": p.ike_version,
                    "exchange_types": set(),
                    "packets": [],
                    "start_time": p.timestamp,
                    "end_time": p.timestamp,
                    "proposals_offered": [],
                    "proposals_chosen": [],
                    "esp_packets": 0,
                    "esp_spis": set(),
                    "evidence_items": [],
                    "limitations": [],
                }

            s = sessions_map[session_key]
            s["packets"].append(p.index)
            s["end_time"] = max(s["end_time"], p.timestamp)
            if p.exchange_type:
                s["exchange_types"].add(p.exchange_type)
            if p.is_esp:
                s["esp_packets"] += 1
                if p.esp_spi:
                    s["esp_spis"].add(p.esp_spi)

            # Extract directly observed evidence from IKE proposals
            if p.proposals:
                if p.is_initiator or p.is_initiator is None:
                    s["proposals_offered"].extend(p.proposals)
                else:
                    s["proposals_chosen"].extend(p.proposals)

                for prop in p.proposals:
                    for tr in prop.transforms:
                        ev_id = f"ev-{capture_id}-pkt{p.index}-{tr.transform_type}-{tr.transform_id}"
                        ev = EvidenceItem(
                            id=ev_id,
                            field_name=f"{tr.transform_type} Transform",
                            observed_value=tr.transform_name,
                            source_reference=f"Packet #{p.index} [Payload SA: Proposal #{prop.proposal_num}]",
                            observation_method="scapy_dissector",
                            provenance=ObservationProvenance.DIRECTLY_OBSERVED,
                            sufficiency=EvidenceSufficiency.SUFFICIENT,
                            timestamp=p.timestamp,
                            limitations="Directly observed in unencrypted IKE_SA_INIT negotiation",
                            metadata={
                                "transform_type": tr.transform_type,
                                "transform_id": tr.transform_id,
                                "key_length": tr.key_length,
                                "proposal_num": prop.proposal_num,
                                "protocol": prop.protocol_id,
                            }
                        )
                        s["evidence_items"].append(ev)
                        all_evidence.append(ev)

            # If IKE Version is observed
            if p.ike_version:
                ev_ver_id = f"ev-{capture_id}-pkt{p.index}-ike-version"
                ev_ver = EvidenceItem(
                    id=ev_ver_id,
                    field_name="IKE Protocol Version",
                    observed_value=p.ike_version,
                    source_reference=f"Packet #{p.index} Header [Major Version {p.ike_version}]",
                    observation_method="scapy_dissector",
                    provenance=ObservationProvenance.DIRECTLY_OBSERVED,
                    sufficiency=EvidenceSufficiency.SUFFICIENT,
                    timestamp=p.timestamp,
                    limitations=None,
                    metadata={"exchange_type": p.exchange_type}
                )
                if not any(x.id == ev_ver_id for x in all_evidence):
                    s["evidence_items"].append(ev_ver)
                    all_evidence.append(ev_ver)

        session_summaries: List[SessionSummary] = []
        for s in sessions_map.values():
            duration = max(0.0, round(s["end_time"] - s["start_time"], 4))
            session_summaries.append(SessionSummary(
                session_id=s["session_id"],
                initiator_ip=s["initiator_ip"],
                responder_ip=s["responder_ip"],
                initiator_port=s["initiator_port"],
                responder_port=s["responder_port"],
                initiator_spi=s["initiator_spi"],
                responder_spi=s["responder_spi"],
                ike_version=s["ike_version"],
                exchange_types_observed=sorted(list(s["exchange_types"])),
                packet_count=len(s["packets"]),
                start_time=s["start_time"],
                end_time=s["end_time"],
                duration_seconds=duration,
                packets=s["packets"],
                proposals_offered=s["proposals_offered"],
                proposals_chosen=s["proposals_chosen"],
                esp_packet_count=s["esp_packets"],
                esp_spis=sorted(list(s["esp_spis"])),
                evidence_items=s["evidence_items"],
                completeness_score=1.0 if s["evidence_items"] else 0.5,
                limitations=s["limitations"]
            ))

        return session_summaries, all_evidence

    def get_analysis(self, capture_id: str) -> Optional[CaptureAnalysisResult]:
        if capture_id in self.in_memory_results:
            return self.in_memory_results[capture_id]
        res = session_repository.get_analysis(capture_id)
        if res:
            self.in_memory_results[capture_id] = res
        return res

    def list_analyses(self) -> List[CaptureAnalysisResult]:
        persisted = session_repository.list_analyses()
        persisted_ids = {p.capture_id for p in persisted}
        for cid, mem_res in self.in_memory_results.items():
            if cid not in persisted_ids:
                try:
                    session_repository.save_analysis(mem_res, status=AnalysisStatus.READY)
                except Exception:
                    pass
                persisted.append(mem_res)
        return persisted


capture_service = CaptureService()
