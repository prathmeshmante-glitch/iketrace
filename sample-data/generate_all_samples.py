import struct
from pathlib import Path
from scapy.all import IP, UDP, ESP, Raw, wrpcap

def create_ikev2_packet(
    src: str,
    dst: str,
    init_spi_hex: str,
    resp_spi_hex: str,
    exchange_type: int,
    is_initiator: bool,
    msg_id: int,
    transforms_spec: list, # list of (type, id, key_len)
    proto_id: int = 1
):
    init_spi = bytes.fromhex(init_spi_hex)
    resp_spi = bytes.fromhex(resp_spi_hex)

    t_bytes = b""
    for i, (t_type, t_id, key_len) in enumerate(transforms_spec):
        is_last = (i == len(transforms_spec) - 1)
        sub_last = 0 if is_last else 3

        if key_len:
            # 12 bytes with 4-byte attribute
            t_data = bytes([sub_last, 0]) + struct.pack('!H', 12) + bytes([t_type, 0]) + struct.pack('!H', t_id) + bytes([0x80, 0x0e, (key_len >> 8) & 0xff, key_len & 0xff])
        else:
            t_data = bytes([sub_last, 0]) + struct.pack('!H', 8) + bytes([t_type, 0]) + struct.pack('!H', t_id)
        t_bytes += t_data

    prop_len = 8 + len(t_bytes)
    prop_body = bytes([0, 0]) + struct.pack('!H', prop_len) + bytes([1, proto_id, 0, len(transforms_spec)]) + t_bytes
    sa_payload = bytes([0, 0]) + struct.pack('!H', 4 + len(prop_body)) + prop_body

    flags = 0x08 if is_initiator else 0x20
    hdr = init_spi + resp_spi + bytes([33, 0x20, exchange_type, flags]) + struct.pack('!I', msg_id) + struct.pack('!I', 28 + len(sa_payload))

    return IP(src=src, dst=dst)/UDP(sport=500, dport=500)/Raw(load=hdr + sa_payload)


def generate():
    out_dir = Path("sample-data/captures")
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Secure IKEv2 Baseline: AES-256-GCM, PRF-SHA256, DH Group 19 (ECP-256), ESN=1 + ESP packets
    p1 = create_ikev2_packet(
        src="192.168.10.1", dst="192.168.20.1",
        init_spi_hex="a1b2c3d4e5f60718", resp_spi_hex="0000000000000000",
        exchange_type=34, is_initiator=True, msg_id=0,
        transforms_spec=[(1, 20, 256), (2, 5, None), (4, 19, None), (5, 1, None)]
    )
    p2 = create_ikev2_packet(
        src="192.168.20.1", dst="192.168.10.1",
        init_spi_hex="a1b2c3d4e5f60718", resp_spi_hex="f8e7d6c5b4a39281",
        exchange_type=34, is_initiator=False, msg_id=0,
        transforms_spec=[(1, 20, 256), (2, 5, None), (4, 19, None), (5, 1, None)]
    )
    esp_pkts = [
        IP(src="192.168.10.1", dst="192.168.20.1", proto=50)/ESP(spi=0x1a2b3c4d, seq=i)/Raw(load=b"\x00"*64)
        for i in range(1, 6)
    ]
    wrpcap(str(out_dir / "secure_ikev2_baseline.pcap"), [p1, p2] + esp_pkts)
    print("Generated secure_ikev2_baseline.pcap")

    # 2. Prohibited Suite: 3DES, MD5, DH Group 2, NO_ESN
    p_bad = create_ikev2_packet(
        src="192.168.10.2", dst="192.168.20.1",
        init_spi_hex="bb22334455667788", resp_spi_hex="0000000000000000",
        exchange_type=34, is_initiator=True, msg_id=0,
        transforms_spec=[(1, 3, 168), (2, 1, None), (3, 1, None), (4, 2, None), (5, 0, None)]
    )
    wrpcap(str(out_dir / "prohibited_3des_md5.pcap"), [p_bad])
    print("Generated prohibited_3des_md5.pcap")

    # 3. Legacy IKEv1 Main Mode
    init_spi = bytes.fromhex('9988776655443322')
    resp_spi = bytes.fromhex('0000000000000000')
    # IKEv1 header: Next=1 (SA), Ver=0x10 (v1.0), Exchange=2 (Identity Protection), Flags=0, MsgID=0, Len=56
    v1_sa = bytes([0, 0, 0, 28]) + bytes([0]*8) + bytes([0, 0, 0, 16, 1, 1, 0, 1, 0, 0, 0, 8, 1, 0, 0, 12])
    v1_hdr = init_spi + resp_spi + bytes([1, 0x10, 2, 0]) + struct.pack('!I', 0) + struct.pack('!I', 28 + len(v1_sa))
    p_v1 = IP(src="192.168.10.3", dst="192.168.20.1")/UDP(sport=500, dport=500)/Raw(load=v1_hdr + v1_sa)
    wrpcap(str(out_dir / "legacy_ikev1_main_mode.pcap"), [p_v1])
    print("Generated legacy_ikev1_main_mode.pcap")

    # 4. Malformed Corrupt Packet: Truncated headers and invalid payload lengths
    p_corrupt = IP(src="192.168.10.4", dst="192.168.20.1")/UDP(sport=500, dport=500)/Raw(load=b"\x12\x34\x56\x78\x90\xab\xcd\xef\x00\x00\x00\x00\x00\x00\x00\x00\x21\x20\x22\x08\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\x00\x02")
    wrpcap(str(out_dir / "malformed_corrupt.pcap"), [p_corrupt])
    print("Generated malformed_corrupt.pcap")

    # 5. CNSA 2.0 Compliant Baseline: AES-256-GCM, PRF-SHA384, DH Group 20 (ECP-384), ESN=1
    p_cnsa1 = create_ikev2_packet(
        src="192.168.10.5", dst="192.168.20.1",
        init_spi_hex="c1c2c3c4d5d60718", resp_spi_hex="0000000000000000",
        exchange_type=34, is_initiator=True, msg_id=0,
        transforms_spec=[(1, 20, 256), (2, 6, None), (4, 20, None), (5, 1, None)]
    )
    p_cnsa2 = create_ikev2_packet(
        src="192.168.20.1", dst="192.168.10.5",
        init_spi_hex="c1c2c3c4d5d60718", resp_spi_hex="e8e7d6c5b4a39281",
        exchange_type=34, is_initiator=False, msg_id=0,
        transforms_spec=[(1, 20, 256), (2, 6, None), (4, 20, None), (5, 1, None)]
    )
    wrpcap(str(out_dir / "cnsa_2_0_compliant.pcap"), [p_cnsa1, p_cnsa2] + esp_pkts)
    print("Generated cnsa_2_0_compliant.pcap")

    # 6. Incomplete Handshake (Offer Only): Initiator offers AES-256-GCM, but responder never answered
    p_half = create_ikev2_packet(
        src="192.168.10.6", dst="192.168.20.1",
        init_spi_hex="d1d2d3d4e5f60718", resp_spi_hex="0000000000000000",
        exchange_type=34, is_initiator=True, msg_id=0,
        transforms_spec=[(1, 20, 256), (2, 5, None), (4, 19, None), (5, 1, None)]
    )
    wrpcap(str(out_dir / "incomplete_handshake_offer_only.pcap"), [p_half])
    print("Generated incomplete_handshake_offer_only.pcap")

if __name__ == "__main__":
    generate()

