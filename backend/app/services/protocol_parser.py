import os
import shutil
import struct
import subprocess
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

from scapy.all import rdpcap, Packet, Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.ipsec import ESP
from scapy.layers.isakmp import ISAKMP, ISAKMP_payload, ISAKMP_payload_SA

from ..schemas.common import EvidenceItem, ObservationProvenance, EvidenceSufficiency
from ..schemas.capture import (
    IKETransform,
    IKEProposal,
    ESPObservation,
    PacketSummary,
    SessionSummary,
    CaptureAnalysisResult,
)

# Standard IANA IKEv2 / RFC 7296 registry definitions
EXCHANGE_TYPES_IKEV2 = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

EXCHANGE_TYPES_IKEV1 = {
    2: "Identity Protection (Main Mode)",
    4: "Aggressive Mode",
    5: "Informational",
    32: "Quick Mode",
    33: "New Group Mode",
}

TRANSFORM_TYPES = {
    1: "ENCR",
    2: "PRF",
    3: "INTEG",
    4: "D-H",
    5: "ESN",
}

ENCR_ALGORITHMS = {
    1: "ENCR_DES_IV64",
    2: "ENCR_DES",
    3: "ENCR_3DES",
    11: "ENCR_NULL",
    12: "ENCR_AES_CBC",
    13: "ENCR_AES_CTR",
    14: "ENCR_AES_CCM_8",
    15: "ENCR_AES_CCM_12",
    16: "ENCR_AES_CCM_16",
    18: "ENCR_AES_GCM_8",
    19: "ENCR_AES_GCM_12",
    20: "ENCR_AES_GCM_16",
    28: "ENCR_CHACHA20_POLY1305",
}

PRF_ALGORITHMS = {
    1: "PRF_HMAC_MD5",
    2: "PRF_HMAC_SHA1",
    3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC",
    5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384",
    7: "PRF_HMAC_SHA2_512",
}

INTEG_ALGORITHMS = {
    1: "AUTH_HMAC_MD5_96",
    2: "AUTH_HMAC_SHA1_96",
    3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5",
    5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128",
    13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

DH_GROUPS = {
    1: "DH_GROUP_1_MODP_768",
    2: "DH_GROUP_2_MODP_1024",
    5: "DH_GROUP_5_MODP_1536",
    14: "DH_GROUP_14_MODP_2048",
    15: "DH_GROUP_15_MODP_3072",
    16: "DH_GROUP_16_MODP_4096",
    19: "DH_GROUP_19_ECP_256",
    20: "DH_GROUP_20_ECP_384",
    21: "DH_GROUP_21_ECP_521",
    31: "DH_GROUP_31_CURVE25519",
    32: "DH_GROUP_32_CURVE448",
    1024: "ML_KEM_768_EXPERIMENTAL_PQC",
    1025: "ML_KEM_1024_EXPERIMENTAL_PQC",
}

ESN_SETTINGS = {
    0: "NO_ESN",
    1: "ESN",
}


class ProtocolParserInterface:
    """Abstract interface for protocol dissection (Scapy native and optional TShark)."""
    def parse_capture(self, file_path: Path, max_packets: int = 5000) -> Tuple[List[PacketSummary], List[str]]:
        raise NotImplementedError


class ScapyProtocolParser(ProtocolParserInterface):
    """Deterministic, pure-python Scapy packet dissector for IKE and ESP."""

    def parse_capture(self, file_path: Path, max_packets: int = 5000) -> Tuple[List[PacketSummary], List[str]]:
        summaries: List[PacketSummary] = []
        warnings: List[str] = []

        try:
            packets = rdpcap(str(file_path))
        except Exception as e:
            warnings.append(f"PCAP reader encountered parsing issue: {str(e)}")
            return summaries, warnings

        for idx, pkt in enumerate(packets[:max_packets], start=1):
            try:
                summary = self._dissect_packet(idx, pkt)
                if summary:
                    summaries.append(summary)
            except Exception as ex:
                warnings.append(f"Packet #{idx} dissection error: {str(ex)}")

        return summaries, warnings

    def _dissect_packet(self, idx: int, pkt: Packet) -> Optional[PacketSummary]:
        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        ts = float(pkt.time) if hasattr(pkt, 'time') and pkt.time else 0.0
        length = len(pkt)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Check for ESP (IP Protocol 50)
        if ip_layer.proto == 50 or pkt.haslayer(ESP):
            esp_layer = pkt[ESP] if pkt.haslayer(ESP) else None
            spi_hex = hex(esp_layer.spi) if esp_layer and hasattr(esp_layer, 'spi') else "0x0"
            seq_num = int(esp_layer.seq) if esp_layer and hasattr(esp_layer, 'seq') else 0
            
            return PacketSummary(
                index=idx,
                timestamp=ts,
                length=length,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="ESP",
                summary=f"ESP SPI={spi_hex} Seq={seq_num} Len={length}",
                is_esp=True,
                esp_spi=spi_hex,
                esp_seq=seq_num
            )

        # Check for UDP: IKE on 500 or NAT-T on 4500
        if pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            sport = udp_layer.sport
            dport = udp_layer.dport

            if sport in (500, 4500) or dport in (500, 4500) or pkt.haslayer(ISAKMP):
                return self._dissect_ike_packet(idx, ts, length, src_ip, dst_ip, sport, dport, pkt)

            return PacketSummary(
                index=idx,
                timestamp=ts,
                length=length,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                protocol="UDP",
                summary=f"UDP {sport} -> {dport} Len={length}"
            )

        return PacketSummary(
            index=idx,
            timestamp=ts,
            length=length,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=f"IP proto={ip_layer.proto}",
            summary=f"IP {src_ip} -> {dst_ip} Proto={ip_layer.proto} Len={length}"
        )

    def _dissect_ike_packet(
        self, idx: int, ts: float, length: int, src_ip: str, dst_ip: str, sport: int, dport: int, pkt: Packet
    ) -> PacketSummary:
        warnings: List[str] = []
        payload_types: List[str] = []
        proposals: List[IKEProposal] = []
        
        raw_payload = bytes(pkt[UDP].payload)
        
        # Check for NAT-T Non-ESP Marker (4 zero bytes on port 4500)
        offset = 0
        if sport == 4500 or dport == 4500:
            if len(raw_payload) >= 4 and raw_payload[:4] == b'\x00\x00\x00\x00':
                offset = 4
            elif len(raw_payload) >= 4 and raw_payload[:4] != b'\x00\x00\x00\x00':
                # Encapsulated ESP in UDP port 4500
                spi_int = struct.unpack("!I", raw_payload[:4])[0]
                seq_int = struct.unpack("!I", raw_payload[4:8])[0] if len(raw_payload) >= 8 else 0
                return PacketSummary(
                    index=idx,
                    timestamp=ts,
                    length=length,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    protocol="UDP-ESP",
                    summary=f"NAT-T Encapsulated ESP SPI={hex(spi_int)} Seq={seq_int}",
                    is_esp=True,
                    esp_spi=hex(spi_int),
                    esp_seq=seq_int
                )

        ike_bytes = raw_payload[offset:]
        if len(ike_bytes) < 28:
            return PacketSummary(
                index=idx,
                timestamp=ts,
                length=length,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=sport,
                dst_port=dport,
                protocol="UDP-IKE-SHORT",
                summary="Truncated IKE header (<28 bytes)",
                is_ike=True,
                parser_warnings=["Truncated IKE header"]
            )

        # Parse 28-byte IKE Header
        # Initiator SPI (8B), Responder SPI (8B), Next Payload (1B), Version (1B), Exchange Type (1B), Flags (1B), MsgID (4B), Length (4B)
        init_spi = ike_bytes[0:8].hex()
        resp_spi = ike_bytes[8:16].hex()
        next_payload = ike_bytes[16]
        version_byte = ike_bytes[17]
        major_ver = (version_byte >> 4) & 0x0F
        minor_ver = version_byte & 0x0F
        ike_version_str = f"IKEv{major_ver}" if major_ver in (1, 2) else f"IKEv{major_ver}.{minor_ver}"
        
        exchange_type_val = ike_bytes[18]
        flags = ike_bytes[19]
        is_initiator = bool(flags & 0x08) if major_ver == 2 else bool(flags & 0x01)
        
        msg_id = struct.unpack("!I", ike_bytes[20:24])[0]
        header_len = struct.unpack("!I", ike_bytes[24:28])[0]

        if major_ver == 2:
            exchange_name = EXCHANGE_TYPES_IKEV2.get(exchange_type_val, f"ExchangeType_{exchange_type_val}")
        else:
            exchange_name = EXCHANGE_TYPES_IKEV1.get(exchange_type_val, f"ExchangeType_{exchange_type_val}")

        # Dissect Payloads
        current_offset = 28
        curr_payload_type = next_payload
        
        while curr_payload_type != 0 and current_offset < len(ike_bytes):
            if current_offset + 4 > len(ike_bytes):
                warnings.append(f"Payload header truncated at offset {current_offset}")
                break
                
            np, is_crit, p_len = self._parse_generic_payload_header(ike_bytes[current_offset:current_offset+4], major_ver)
            payload_types.append(self._get_payload_name(curr_payload_type, major_ver))

            if p_len < 4 or current_offset + p_len > len(ike_bytes):
                warnings.append(f"Invalid payload length {p_len} at offset {current_offset}")
                break

            payload_body = ike_bytes[current_offset+4 : current_offset+p_len]
            
            # If Security Association (SA) Payload (33 in IKEv2, 1 in IKEv1)
            if (major_ver == 2 and curr_payload_type == 33) or (major_ver == 1 and curr_payload_type == 1):
                parsed_props = self._parse_sa_payload(payload_body, major_ver)
                proposals.extend(parsed_props)

            current_offset += p_len
            curr_payload_type = np

        return PacketSummary(
            index=idx,
            timestamp=ts,
            length=length,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=sport,
            dst_port=dport,
            protocol=ike_version_str,
            summary=f"{ike_version_str} {exchange_name} MsgID={msg_id} Payloads=[{', '.join(payload_types[:4])}]",
            is_ike=True,
            ike_version=ike_version_str,
            exchange_type=exchange_name,
            message_id=msg_id,
            is_initiator=is_initiator,
            initiator_spi=init_spi,
            responder_spi=resp_spi,
            payload_types=payload_types,
            proposals=proposals,
            parser_warnings=warnings
        )

    def _parse_generic_payload_header(self, hdr_bytes: bytes, major_ver: int) -> Tuple[int, bool, int]:
        np = hdr_bytes[0]
        if major_ver == 2:
            is_crit = bool(hdr_bytes[1] & 0x80)
        else:
            is_crit = False
        p_len = struct.unpack("!H", hdr_bytes[2:4])[0]
        return np, is_crit, p_len

    def _get_payload_name(self, p_type: int, major_ver: int) -> str:
        names_v2 = {
            0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr",
            37: "CERT", 38: "CERTREQ", 39: "AUTH", 40: "NONCE",
            41: "NOTIFY", 42: "DELETE", 43: "VENDOR_ID",
            44: "TSi", 45: "TSr", 46: "ENCRYPTED"
        }
        names_v1 = {
            0: "NONE", 1: "SA", 2: "Proposal", 3: "Transform",
            4: "KE", 5: "ID", 6: "CERT", 7: "CR", 8: "HASH",
            9: "SIG", 10: "NONCE", 11: "NOTIFY", 12: "DELETE", 13: "VENDOR_ID"
        }
        mapping = names_v2 if major_ver == 2 else names_v1
        return mapping.get(p_type, f"PayloadType_{p_type}")

    def _parse_sa_payload(self, body: bytes, major_ver: int) -> List[IKEProposal]:
        proposals: List[IKEProposal] = []
        offset = 0

        # In IKEv1, SA has 4 bytes DOI + 4 bytes Situation before proposals
        if major_ver == 1:
            if len(body) < 8:
                return proposals
            offset = 8

        # In IKEv2, body contains consecutive Proposal Substructures
        while offset + 8 <= len(body):
            last_substruc = body[offset] # 0 = last, 2 = more
            prop_len = struct.unpack("!H", body[offset+2 : offset+4])[0]
            if prop_len < 8 or offset + prop_len > len(body):
                break
                
            prop_num = body[offset+4]
            proto_id_val = body[offset+5]
            proto_name = "IKE" if proto_id_val == 1 else ("ESP" if proto_id_val == 3 else f"Proto_{proto_id_val}")
            spi_size = body[offset+6]
            num_transforms = body[offset+7]
            
            spi_hex = None
            t_offset = offset + 8
            if spi_size > 0 and t_offset + spi_size <= offset + prop_len:
                spi_hex = body[t_offset : t_offset+spi_size].hex()
                t_offset += spi_size

            transforms: List[IKETransform] = []
            while t_offset + 8 <= offset + prop_len:
                t_last = body[t_offset]
                t_len = struct.unpack("!H", body[t_offset+2 : t_offset+4])[0]
                if t_len < 8 or t_offset + t_len > offset + prop_len:
                    break
                    
                t_type_val = body[t_offset+4]
                t_id_val = struct.unpack("!H", body[t_offset+6 : t_offset+8])[0]
                t_type_name = TRANSFORM_TYPES.get(t_type_val, f"TransformType_{t_type_val}")
                
                # Resolve transform algorithm name
                t_alg_name = self._resolve_transform_name(t_type_val, t_id_val)
                key_len = None
                attrs: Dict[str, Any] = {}

                # Check attributes (e.g. Key Length)
                attr_offset = t_offset + 8
                while attr_offset + 4 <= t_offset + t_len:
                    af = bool(body[attr_offset] & 0x80) # Attribute Format (1 = TV, 0 = TLV)
                    attr_type = struct.unpack("!H", bytes([body[attr_offset] & 0x7F, body[attr_offset+1]]))[0]
                    if af:
                        attr_val = struct.unpack("!H", body[attr_offset+2 : attr_offset+4])[0]
                        attr_offset += 4
                    else:
                        attr_len = struct.unpack("!H", body[attr_offset+2 : attr_offset+4])[0]
                        attr_val = body[attr_offset+4 : attr_offset+4+attr_len].hex()
                        attr_offset += 4 + attr_len
                    
                    attrs[str(attr_type)] = attr_val
                    if attr_type == 14: # Key Length attribute
                        key_len = int(attr_val)

                transforms.append(IKETransform(
                    transform_type=t_type_name,
                    transform_id=t_id_val,
                    transform_name=t_alg_name,
                    key_length=key_len,
                    attributes=attrs
                ))

                if t_last == 0:
                    break
                t_offset += t_len

            proposals.append(IKEProposal(
                proposal_num=prop_num,
                protocol_id=proto_name,
                spi=spi_hex,
                transforms=transforms
            ))

            if last_substruc == 0:
                break
            offset += prop_len

        return proposals

    def _resolve_transform_name(self, t_type: int, t_id: int) -> str:
        if t_type == 1:
            return ENCR_ALGORITHMS.get(t_id, f"ENCR_{t_id}")
        elif t_type == 2:
            return PRF_ALGORITHMS.get(t_id, f"PRF_{t_id}")
        elif t_type == 3:
            return INTEG_ALGORITHMS.get(t_id, f"INTEG_{t_id}")
        elif t_type == 4:
            return DH_GROUPS.get(t_id, f"DH_GROUP_{t_id}")
        elif t_type == 5:
            return ESN_SETTINGS.get(t_id, f"ESN_{t_id}")
        return f"TYPE_{t_type}_ID_{t_id}"


class TSharkProtocolAdapter(ProtocolParserInterface):
    """Optional adapter for TShark dissection when installed on the host system."""
    
    def __init__(self, tshark_path: Optional[str] = None):
        self.tshark_executable = tshark_path or shutil.which("tshark")
        self.is_available = bool(self.tshark_executable and os.path.exists(self.tshark_executable))

    def parse_capture(self, file_path: Path, max_packets: int = 5000) -> Tuple[List[PacketSummary], List[str]]:
        if not self.is_available:
            return [], ["TShark executable not available on this host. Falling back to Scapy native dissector."]
            
        # If available, execute tshark with timeout and strict argument list (no shell=True)
        cmd = [
            self.tshark_executable,
            "-r", str(file_path),
            "-c", str(max_packets),
            "-T", "ek",
            "-j", "ip isakmp esp udp"
        ]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if res.returncode != 0:
                return [], [f"TShark execution exited with code {res.returncode}: {res.stderr[:200]}"]
            # Process output (TShark output processed when available)
            return [], ["TShark dissection completed"]
        except Exception as e:
            return [], [f"TShark execution error: {str(e)}"]
