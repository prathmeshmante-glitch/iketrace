import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ..schemas.common import ObservationProvenance, SeverityLevel
from ..schemas.capture import CaptureAnalysisResult
from ..schemas.crypto_inventory import CryptoAsset, CryptoInventoryReport

# Quantum threat categorization
# Shor's algorithm polynomial time breaks: RSA, Diffie-Hellman (MODP), ECDH, ECDSA
# Grover's algorithm halves symmetric security (AES-128 -> 64-bit, AES-256 -> 128-bit)

ALGORITHM_PQC_MAP = {
    # DH Groups - Vulnerable to CRQC (Cryptanalytically Relevant Quantum Computer) via Shor's Algorithm
    "DH_GROUP_1_MODP_768": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.CRITICAL, "DH_GROUP_20_ECP_384 / ML-KEM-768", "Deprecated 768-bit MODP. Broken classically and quantumly."),
    "DH_GROUP_2_MODP_1024": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.CRITICAL, "DH_GROUP_20_ECP_384 / ML-KEM-768", "Insecure 1024-bit MODP. Broken classically and quantumly."),
    "DH_GROUP_5_MODP_1536": ("DEPRECATED", "VULNERABLE_CRQC", SeverityLevel.HIGH, "DH_GROUP_20_ECP_384 / ML-KEM-768", "Deprecated 1536-bit MODP. Below 128-bit classical security."),
    "DH_GROUP_14_MODP_2048": ("COMPLIANT", "VULNERABLE_CRQC", SeverityLevel.MEDIUM, "DH_GROUP_20_ECP_384 / ML-KEM-768", "Compliant classical (112-bit security), vulnerable to store-now-decrypt-later quantum attacks."),
    "DH_GROUP_19_ECP_256": ("COMPLIANT", "VULNERABLE_CRQC", SeverityLevel.MEDIUM, "DH_GROUP_20_ECP_384 / ML-KEM-768", "Compliant classical NIST P-256 curve, vulnerable to Shor's algorithm."),
    "DH_GROUP_20_ECP_384": ("COMPLIANT", "VULNERABLE_CRQC", SeverityLevel.LOW, "ML_KEM_1024_EXPERIMENTAL_PQC", "CNSA 2.0 classical approved. Plan transition to hybrid post-quantum key exchange (IETF RFC 9370)."),
    "DH_GROUP_21_ECP_521": ("COMPLIANT", "VULNERABLE_CRQC", SeverityLevel.LOW, "ML_KEM_1024_EXPERIMENTAL_PQC", "High-assurance classical ECP curve."),
    "DH_GROUP_31_CURVE25519": ("COMPLIANT", "VULNERABLE_CRQC", SeverityLevel.MEDIUM, "ML_KEM_768_EXPERIMENTAL_PQC", "Modern high-speed Edwards curve, vulnerable to quantum discrete logarithm."),
    "ML_KEM_768_EXPERIMENTAL_PQC": ("PQC_EXPERIMENTAL", "HYBRID_POST_QUANTUM", SeverityLevel.LOW, "Standardized FIPS 203 ML-KEM-768", "Post-quantum lattice-based key encapsulation mechanism. Verify peer interoperability in lab."),
    "ML_KEM_1024_EXPERIMENTAL_PQC": ("PQC_EXPERIMENTAL", "HYBRID_POST_QUANTUM", SeverityLevel.LOW, "Standardized FIPS 203 ML-KEM-1024", "High-security post-quantum lattice-based KEM. CNSA 2.0 target."),

    # Encryption Algorithms
    "ENCR_3DES": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.CRITICAL, "ENCR_AES_GCM_16 (256-bit)", "Sweet32 collision attacks and deprecated 64-bit block size."),
    "ENCR_DES": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.CRITICAL, "ENCR_AES_GCM_16 (256-bit)", "Broken 56-bit key space."),
    "ENCR_AES_CBC": ("COMPLIANT", "QUANTUM_RESISTANT_SYMMETRIC", SeverityLevel.MEDIUM, "ENCR_AES_GCM_16", "Ensure 256-bit key length and use AEAD to eliminate padding-oracle attacks."),
    "ENCR_AES_GCM_16": ("COMPLIANT", "QUANTUM_RESISTANT_SYMMETRIC", SeverityLevel.LOW, "Maintain 256-bit key", "Standard AEAD cipher. 256-bit key preserves 128-bit quantum security against Grover's algorithm."),
    "ENCR_CHACHA20_POLY1305": ("COMPLIANT", "QUANTUM_RESISTANT_SYMMETRIC", SeverityLevel.LOW, "Maintain 256-bit key", "256-bit modern AEAD stream cipher with high quantum security margin."),

    # Hash / PRF / Integrity
    "AUTH_HMAC_MD5_96": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.CRITICAL, "AUTH_HMAC_SHA2_256_128", "Cryptographically broken MD5 collisions."),
    "AUTH_HMAC_SHA1_96": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.CRITICAL, "AUTH_HMAC_SHA2_256_128", "Deprecated SHA-1 collisions."),
    "AUTH_HMAC_SHA2_256_128": ("COMPLIANT", "QUANTUM_RESISTANT_SYMMETRIC", SeverityLevel.LOW, "AUTH_HMAC_SHA2_384_192", "Approved SHA-2 integrity."),
    "AUTH_HMAC_SHA2_384_192": ("COMPLIANT", "QUANTUM_RESISTANT_SYMMETRIC", SeverityLevel.LOW, "Maintain SHA2-384", "Approved CNSA 2.0 integrity primitive."),
    "PRF_HMAC_MD5": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.CRITICAL, "PRF_HMAC_SHA2_256", "Broken MD5 PRF."),
    "PRF_HMAC_SHA1": ("PROHIBITED", "VULNERABLE_CRQC", SeverityLevel.HIGH, "PRF_HMAC_SHA2_256", "Deprecated SHA-1 PRF."),
    "PRF_HMAC_SHA2_256": ("COMPLIANT", "QUANTUM_RESISTANT_SYMMETRIC", SeverityLevel.LOW, "PRF_HMAC_SHA2_384", "NIST approved PRF."),
    "PRF_HMAC_SHA2_384": ("COMPLIANT", "QUANTUM_RESISTANT_SYMMETRIC", SeverityLevel.LOW, "Maintain SHA2-384", "CNSA 2.0 approved PRF."),
}


class CryptoInventoryService:
    def __init__(self):
        self.cached_inventories: Dict[str, CryptoInventoryReport] = {}

    def inventory_from_capture(self, analysis: CaptureAnalysisResult) -> CryptoInventoryReport:
        assets: List[CryptoAsset] = []
        seen_keys = set()

        for s in analysis.sessions:
            # Check IKE Version
            if s.ike_version:
                v_key = f"PROTOCOL-{s.ike_version}"
                if v_key not in seen_keys:
                    seen_keys.add(v_key)
                    is_v2 = (s.ike_version == "IKEv2")
                    assets.append(CryptoAsset(
                        asset_id=f"ast-{uuid.uuid4().hex[:8]}",
                        category="PROTOCOL",
                        algorithm_name=s.ike_version,
                        key_length=None,
                        compliance_status="COMPLIANT" if is_v2 else "PROHIBITED",
                        pqc_readiness="NOT_APPLICABLE",
                        provenance=ObservationProvenance.DIRECTLY_OBSERVED,
                        source_reference=f"Session {s.session_id}",
                        negotiated_or_configured="CONFIRMED_NEGOTIATED",
                        migration_priority=SeverityLevel.LOW if is_v2 else SeverityLevel.CRITICAL,
                        recommended_target="IKEv2 (RFC 7296)",
                        transition_guidance="IKEv2 supports RFC 9370 Multiple Key Exchanges for Hybrid PQC."
                    ))

            # Check all proposals
            props = s.proposals_chosen if s.proposals_chosen else s.proposals_offered
            for prop in props:
                for tr in prop.transforms:
                    t_key = f"{tr.transform_type}-{tr.transform_name}-{tr.key_length}"
                    if t_key in seen_keys:
                        continue
                    seen_keys.add(t_key)

                    lookup = ALGORITHM_PQC_MAP.get(tr.transform_name)
                    if lookup:
                        status, pqc, priority, target, guidance = lookup
                    else:
                        status = "UNKNOWN"
                        pqc = "NOT_APPLICABLE"
                        priority = SeverityLevel.MEDIUM
                        target = "Review against organizational policy"
                        guidance = "Algorithm name is not in standard baseline registry."

                    # Check key length nuance (e.g. AES-128 vs AES-256 for Grover)
                    if tr.key_length == 128 and "AES" in tr.transform_name:
                        pqc = "VULNERABLE_CRQC"
                        priority = SeverityLevel.HIGH
                        guidance += " 128-bit symmetric key affords only ~64-bit security against Grover's algorithm. Upgrade to 256-bit."

                    assets.append(CryptoAsset(
                        asset_id=f"ast-{uuid.uuid4().hex[:8]}",
                        category=tr.transform_type,
                        algorithm_name=tr.transform_name,
                        key_length=tr.key_length,
                        compliance_status=status,
                        pqc_readiness=pqc,
                        provenance=ObservationProvenance.DIRECTLY_OBSERVED,
                        source_reference=f"Proposal #{prop.proposal_num} in Session {s.session_id}",
                        negotiated_or_configured="CONFIRMED_NEGOTIATED" if s.proposals_chosen else "PROPOSED_ONLY",
                        migration_priority=priority,
                        recommended_target=target,
                        transition_guidance=guidance
                    ))

        # Calculate metrics
        comp_count = sum(1 for a in assets if a.compliance_status == "COMPLIANT")
        dep_count = sum(1 for a in assets if a.compliance_status == "DEPRECATED")
        proh_count = sum(1 for a in assets if a.compliance_status == "PROHIBITED")
        quantum_vuln = sum(1 for a in assets if a.pqc_readiness == "VULNERABLE_CRQC")
        pqc_ready = sum(1 for a in assets if a.pqc_readiness in ("QUANTUM_RESISTANT_SYMMETRIC", "HYBRID_POST_QUANTUM"))

        tot = len(assets)
        readiness_score = round((pqc_ready / tot * 100.0), 1) if tot > 0 else 0.0

        actions: List[Dict[str, str]] = []
        if proh_count > 0:
            actions.append({
                "action": "Immediate Deprecation",
                "detail": f"Eliminate {proh_count} prohibited algorithm(s) (3DES, MD5, SHA-1, DH1-5) from active peer profiles."
            })
        if quantum_vuln > 0:
            actions.append({
                "action": "Post-Quantum Migration Roadmap",
                "detail": f"{quantum_vuln} asset(s) are vulnerable to store-now-decrypt-later quantum attacks. Plan hybrid key exchange (RFC 9370) pilot."
            })

        caveats = [
            "Assessment inventories observed cryptographic configuration proposals and handshake parameters.",
            "Presence of post-quantum algorithm identifiers in proposed configurations does not prove quantum resistance until hardware accelerators and validated implementations are confirmed in an isolated lab.",
            "No attempt is made to break or recover cryptographic keys."
        ]

        report = CryptoInventoryReport(
            inventory_id=f"INV-{uuid.uuid4().hex[:8].upper()}",
            target_id=analysis.capture_id,
            target_type="CAPTURE",
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_assets_inventoried=tot,
            compliant_assets_count=comp_count,
            deprecated_assets_count=dep_count,
            prohibited_assets_count=proh_count,
            quantum_vulnerable_assets_count=quantum_vuln,
            pqc_readiness_score_pct=readiness_score,
            assets=assets,
            migration_actions=actions,
            caveats_and_unknowns=caveats
        )

        self.cached_inventories[analysis.capture_id] = report
        return report

    def get_inventory(self, target_id: str) -> Optional[CryptoInventoryReport]:
        return self.cached_inventories.get(target_id)


crypto_inventory_service = CryptoInventoryService()
