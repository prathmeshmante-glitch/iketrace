from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ..schemas.common import (
    EvaluationOutcome,
    SeverityLevel,
    EvidenceSufficiency,
    EvidenceItem,
    ObservationProvenance,
)
from ..schemas.capture import CaptureAnalysisResult, SessionSummary, IKEProposal
from ..schemas.policy import (
    PolicyDefinition,
    PolicyRule,
    RuleEvaluationResult,
    PolicyEvaluationReport,
)

# Standard Default Security Policies
CNSA_2_0_POLICY = PolicyDefinition(
    policy_id="POL-DEF-CNSA-2.0",
    name="NSA Commercial National Security Algorithm Suite (CNSA 2.0)",
    version="2.0.0",
    author="National Security Agency / NIST",
    description="Mandates quantum-resistant and high-assurance cryptographic algorithms for National Security Systems.",
    rules=[
        PolicyRule(
            rule_id="POL-CNSA-IKE-VER",
            category="PROTOCOL_VERSION",
            title="Enforce IKEv2 Protocol Exclusively",
            description="IKEv1 is legacy and deprecated. Only IKEv2 (RFC 7296) provides modern AEAD support, cookie exchanges against DoS, and post-quantum extensions.",
            severity=SeverityLevel.CRITICAL,
            allowed_values=["IKEv2"],
            prohibited_values=["IKEv1", "IKEv1.0"],
            rationale="NIST SP 800-77 Rev. 1 explicitly mandates retiring IKEv1 due to protocol vulnerabilities and inability to safely negotiate hybrid key exchange.",
            remediation="Configure VPN gateway to require IKEv2 exclusively and disable IKEv1 phase 1 fallback.",
            limitations="Assumes IKE version is directly observable in the unencrypted IKE header."
        ),
        PolicyRule(
            rule_id="POL-CNSA-ENCR-ALG",
            category="ENCRYPTION",
            title="CNSA 2.0 Approved Encryption: AES-256-GCM",
            description="CNSA 2.0 mandates 256-bit AES-GCM (ENCR_AES_GCM_16 with 256-bit key) for both IKE SA and ESP payload data protection.",
            severity=SeverityLevel.CRITICAL,
            allowed_values=["ENCR_AES_GCM_16", "ENCR_AES_GCM_12"],
            prohibited_values=["ENCR_DES", "ENCR_3DES", "ENCR_NULL", "ENCR_AES_CBC"],
            min_key_length=256,
            rationale="Grover's algorithm halves symmetric key security; 256-bit keys ensure a minimum 128-bit quantum security margin.",
            remediation="Set encryption transforms to aes256gcm16 in strongSwan/IPsec configuration and remove CBC/3DES ciphers.",
            limitations="Key length verification requires transform attribute 14 to be present in proposal."
        ),
        PolicyRule(
            rule_id="POL-CNSA-PRF-ALG",
            category="PRF",
            title="CNSA 2.0 Approved PRF: PRF_HMAC_SHA2_384 or SHA2_512",
            description="Pseudorandom function must be PRF_HMAC_SHA2_384 or PRF_HMAC_SHA2_512 for key derivation.",
            severity=SeverityLevel.HIGH,
            allowed_values=["PRF_HMAC_SHA2_384", "PRF_HMAC_SHA2_512"],
            prohibited_values=["PRF_HMAC_MD5", "PRF_HMAC_SHA1", "PRF_HMAC_SHA2_256"],
            rationale="CNSA 2.0 requires SHA-384 or SHA-512 for asymmetric key derivation primitives.",
            remediation="Update IKE proposal PRF setting to prfsha384 or prfsha512.",
            limitations="Applies to IKE_SA proposal."
        ),
        PolicyRule(
            rule_id="POL-CNSA-DH-GROUP",
            category="DH_GROUP",
            title="CNSA 2.0 Diffie-Hellman Group: Group 20 (ECP-384) or Higher",
            description="Key exchange must employ at least DH Group 20 (384-bit random ECP) or CNSA 2.0 quantum-resistant hybrid (ML-KEM-768/1024).",
            severity=SeverityLevel.CRITICAL,
            allowed_values=["DH_GROUP_20_ECP_384", "DH_GROUP_21_ECP_521", "ML_KEM_768_EXPERIMENTAL_PQC", "ML_KEM_1024_EXPERIMENTAL_PQC"],
            prohibited_values=["DH_GROUP_1_MODP_768", "DH_GROUP_2_MODP_1024", "DH_GROUP_5_MODP_1536", "DH_GROUP_14_MODP_2048", "DH_GROUP_19_ECP_256"],
            min_dh_group=20,
            rationale="Classical DH below 384 bits does not meet CNSA 2.0 192-bit classical security equivalence.",
            remediation="Upgrade DH group configuration to ecp384 or ecp521.",
            limitations="Only observable during initial SA negotiation."
        ),
        PolicyRule(
            rule_id="POL-CNSA-REPLAY-ESN",
            category="REPLAY_PROTECTION",
            title="Mandate Extended Sequence Numbers (ESN)",
            description="ESP child SAs must negotiate Extended Sequence Numbers (ESN=1) to prevent 32-bit sequence number rollover attacks.",
            severity=SeverityLevel.MEDIUM,
            allowed_values=["ESN"],
            prohibited_values=["NO_ESN"],
            require_esn=True,
            rationale="High-speed multi-gigabit IPsec connections exhaust 32-bit sequence numbers in minutes, causing replay exposure.",
            remediation="Enable 'esn = yes' in IPsec child SA configuration.",
            limitations="Requires ESN transform in ESP proposals."
        ),
    ]
)

NIST_SP800_77_POLICY = PolicyDefinition(
    policy_id="POL-DEF-NIST-SP800-77",
    name="NIST SP 800-77 Rev. 1 Enterprise Baseline",
    version="1.2.0",
    author="National Institute of Standards and Technology",
    description="Standard enterprise IPsec guidelines recommending modern cryptography, minimum 128-bit security, and IKEv2.",
    rules=[
        PolicyRule(
            rule_id="POL-NIST-IKE-VER",
            category="PROTOCOL_VERSION",
            title="Mandate IKEv2",
            description="IKEv2 must be used for all new IPsec VPN deployments.",
            severity=SeverityLevel.HIGH,
            allowed_values=["IKEv2"],
            prohibited_values=["IKEv1", "IKEv1.0"],
            rationale="NIST SP 800-77 Rev. 1 Section 4 recommends migrating away from IKEv1.",
            remediation="Transition connection configurations to keyexchange=ikev2.",
            limitations=None
        ),
        PolicyRule(
            rule_id="POL-NIST-ENCR-ALG",
            category="ENCRYPTION",
            title="NIST Approved Encryption (AES-GCM or AES-CBC 128/256)",
            description="Encryption must be AES-GCM (128/256-bit) or AES-CBC (128/256-bit). 3DES, DES, and NULL are strictly prohibited.",
            severity=SeverityLevel.CRITICAL,
            allowed_values=["ENCR_AES_GCM_16", "ENCR_AES_GCM_12", "ENCR_AES_CBC", "ENCR_CHACHA20_POLY1305"],
            prohibited_values=["ENCR_DES", "ENCR_3DES", "ENCR_NULL"],
            min_key_length=128,
            rationale="Single DES and Triple-DES (3DES) are officially deprecated by NIST (Sweet32 64-bit block collision attacks).",
            remediation="Remove 3des and des from cryptographic suites; configure aes128gcm16 or aes256gcm16.",
            limitations=None
        ),
        PolicyRule(
            rule_id="POL-NIST-INTEG-ALG",
            category="INTEGRITY",
            title="Prohibit MD5 and SHA-1 Integrity Primitives",
            description="Integrity must use SHA-2 family (HMAC-SHA2-256/384/512). MD5 and SHA-1 are cryptographically broken.",
            severity=SeverityLevel.CRITICAL,
            allowed_values=["AUTH_HMAC_SHA2_256_128", "AUTH_HMAC_SHA2_384_192", "AUTH_HMAC_SHA2_512_256"],
            prohibited_values=["AUTH_HMAC_MD5_96", "AUTH_HMAC_SHA1_96", "AUTH_DES_MAC"],
            rationale="Collision vulnerabilities in MD5 and SHA-1 invalidate authentication guarantees.",
            remediation="Change integrity configuration to sha256 or sha384.",
            limitations="Not applicable when AEAD ciphers like AES-GCM provide integrated integrity."
        ),
        PolicyRule(
            rule_id="POL-NIST-PRF-ALG",
            category="PRF",
            title="NIST Approved Pseudorandom Function (PRF-SHA-256+)",
            description="Pseudorandom function must use HMAC with SHA-256 or higher for key derivation.",
            severity=SeverityLevel.HIGH,
            allowed_values=["PRF_HMAC_SHA2_256", "PRF_HMAC_SHA2_384", "PRF_HMAC_SHA2_512"],
            prohibited_values=["PRF_HMAC_MD5", "PRF_HMAC_SHA1"],
            rationale="NIST SP 800-77 mandates SHA-2 algorithms for all IKEv2 pseudorandom key expansions.",
            remediation="Configure IKE proposal PRF to prfsha256 or prfsha384.",
            limitations=None
        ),
        PolicyRule(
            rule_id="POL-NIST-DH-GROUP",
            category="DH_GROUP",
            title="Minimum Diffie-Hellman Group 14 (MODP 2048-bit)",
            description="Diffie-Hellman key exchange must utilize Group 14 (2048-bit MODP), Group 19 (ECP-256), or higher.",
            severity=SeverityLevel.HIGH,
            allowed_values=[
                "DH_GROUP_14_MODP_2048", "DH_GROUP_15_MODP_3072", "DH_GROUP_16_MODP_4096",
                "DH_GROUP_19_ECP_256", "DH_GROUP_20_ECP_384", "DH_GROUP_21_ECP_521",
                "DH_GROUP_31_CURVE25519"
            ],
            prohibited_values=["DH_GROUP_1_MODP_768", "DH_GROUP_2_MODP_1024", "DH_GROUP_5_MODP_1536"],
            min_dh_group=14,
            rationale="MODP groups under 2048 bits (e.g. Logjam attack) are vulnerable to discrete logarithm precomputation.",
            remediation="Configure dhgroup=modp2048 or ecp256 (curve25519).",
            limitations=None
        ),
    ]
)


class PolicyEngine:
    def __init__(self):
        self.policies: Dict[str, PolicyDefinition] = {
            CNSA_2_0_POLICY.policy_id: CNSA_2_0_POLICY,
            NIST_SP800_77_POLICY.policy_id: NIST_SP800_77_POLICY,
        }

    def register_policy(self, policy: PolicyDefinition) -> None:
        self.policies[policy.policy_id] = policy

    def get_policy(self, policy_id: str) -> Optional[PolicyDefinition]:
        return self.policies.get(policy_id)

    def list_policies(self) -> List[PolicyDefinition]:
        return list(self.policies.values())

    def evaluate_capture(
        self,
        analysis: CaptureAnalysisResult,
        policy_id: str = "POL-DEF-NIST-SP800-77"
    ) -> PolicyEvaluationReport:
        policy = self.get_policy(policy_id)
        if not policy:
            policy = NIST_SP800_77_POLICY

        rule_results: List[RuleEvaluationResult] = []
        now_str = datetime.now(timezone.utc).isoformat()

        # Consolidate observed items across all sessions
        observed_ike_versions = set()
        observed_transforms: Dict[str, List[Dict[str, Any]]] = {
            "ENCR": [],
            "PRF": [],
            "INTEG": [],
            "D-H": [],
            "ESN": [],
        }

        for s in analysis.sessions:
            if s.ike_version:
                observed_ike_versions.add(s.ike_version)
            
            # Check proposals: prefer confirmed negotiated (chosen by responder), fallback to offered
            is_negotiated = bool(s.proposals_chosen)
            proposals = s.proposals_chosen if s.proposals_chosen else s.proposals_offered
            for prop in proposals:
                for tr in prop.transforms:
                    if tr.transform_type in observed_transforms:
                        observed_transforms[tr.transform_type].append({
                            "name": tr.transform_name,
                            "id": tr.transform_id,
                            "key_len": tr.key_length,
                            "session_id": s.session_id,
                            "is_negotiated": is_negotiated,
                        })

        for rule in policy.rules:
            result = self._evaluate_rule(rule, policy.version, analysis, observed_ike_versions, observed_transforms)
            rule_results.append(result)

        passed = sum(1 for r in rule_results if r.outcome == EvaluationOutcome.PASS)
        failed = sum(1 for r in rule_results if r.outcome == EvaluationOutcome.FAIL)
        unknown = sum(1 for r in rule_results if r.outcome == EvaluationOutcome.UNKNOWN)
        na = sum(1 for r in rule_results if r.outcome == EvaluationOutcome.NOT_APPLICABLE)

        evaluable = passed + failed
        score = round((passed / evaluable * 100.0), 1) if evaluable > 0 else 0.0

        return PolicyEvaluationReport(
            policy_id=policy.policy_id,
            policy_name=policy.name,
            policy_version=policy.version,
            evaluated_at=now_str,
            target_id=analysis.capture_id,
            total_rules=len(policy.rules),
            passed_count=passed,
            failed_count=failed,
            unknown_count=unknown,
            not_applicable_count=na,
            compliance_score_pct=score,
            results=rule_results,
        )

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        policy_version: str,
        analysis: CaptureAnalysisResult,
        ike_versions: set,
        transforms: Dict[str, List[Dict[str, Any]]]
    ) -> RuleEvaluationResult:
        ev_ids = [e.id for e in analysis.evidence_items]

        # 1. PROTOCOL_VERSION evaluation
        if rule.category == "PROTOCOL_VERSION":
            if not ike_versions:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value="No IKE negotiation header observed in capture",
                    evidence_ids=[],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="Packet capture does not contain observable IKE packets or version headers.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            # Check for prohibited version
            found_prohibited = [v for v in ike_versions if v in rule.prohibited_values]
            if found_prohibited:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value=list(ike_versions),
                    evidence_ids=[e.id for e in analysis.evidence_items if "version" in e.field_name.lower()],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning=f"Prohibited protocol version(s) {found_prohibited} directly observed in exchange header.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            # Check if all observed versions are in allowed_values
            all_allowed = all(v in rule.allowed_values for v in ike_versions)
            outcome = EvaluationOutcome.PASS if all_allowed else EvaluationOutcome.FAIL
            reason = "Observed IKE version strictly matches allowed policy requirement." if all_allowed else f"Observed version {ike_versions} not in allowed list {rule.allowed_values}."

            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                policy_version=policy_version,
                category=rule.category,
                title=rule.title,
                outcome=outcome,
                severity=rule.severity,
                expected_property=f"Allowed: {rule.allowed_values}",
                observed_value=list(ike_versions),
                evidence_ids=[e.id for e in analysis.evidence_items if "version" in e.field_name.lower()],
                evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                technical_reasoning=reason,
                remediation_recommendation=rule.remediation,
                limitations=rule.limitations
            )

        # 2. ENCRYPTION evaluation
        elif rule.category == "ENCRYPTION":
            encr_obs = transforms.get("ENCR", [])
            if not encr_obs:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value="No ENCR transform observed",
                    evidence_ids=[],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="No Security Association (SA) encryption transforms were extracted from the capture.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            names = [o["name"] for o in encr_obs]
            # Check for prohibited algorithms
            prohibited_found = [n for n in names if n in rule.prohibited_values]
            if prohibited_found:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property=f"Forbidden: {rule.prohibited_values}",
                    observed_value=names,
                    evidence_ids=[e.id for e in analysis.evidence_items if "ENCR" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning=f"Prohibited encryption algorithm(s) {prohibited_found} proposed during SA negotiation.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            # Check key length if required
            if rule.min_key_length:
                key_lengths = [o["key_len"] for o in encr_obs if o["key_len"] is not None]
                if key_lengths and any(k < rule.min_key_length for k in key_lengths):
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id,
                        policy_version=policy_version,
                        category=rule.category,
                        title=rule.title,
                        outcome=EvaluationOutcome.FAIL,
                        severity=rule.severity,
                        expected_property=f"Min Key Length: {rule.min_key_length}-bit",
                        observed_value=f"Key lengths: {key_lengths}",
                        evidence_ids=[e.id for e in analysis.evidence_items if "ENCR" in e.field_name],
                        evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                        technical_reasoning=f"Encryption key length ({key_lengths}) is less than required {rule.min_key_length} bits.",
                        remediation_recommendation=rule.remediation,
                        limitations=rule.limitations
                    )

            # Check allowed values
            if rule.allowed_values and not any(n in rule.allowed_values for n in names):
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value=names,
                    evidence_ids=[e.id for e in analysis.evidence_items if "ENCR" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning=f"Observed encryption transforms {names} do not include allowed algorithm(s) {rule.allowed_values}.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            # Ensure negotiated status: if only offered by initiator and responder never replied, return UNKNOWN
            has_negotiated = any(o.get("is_negotiated", True) for o in encr_obs)
            if not has_negotiated:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed (Negotiated): {rule.allowed_values}",
                    observed_value=f"Offered only: {names}",
                    evidence_ids=[e.id for e in analysis.evidence_items if "ENCR" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="Handshake incomplete: Only initiator proposal offers were observed. Responder selection was not captured, so negotiated encryption cannot be confirmed as PASS.",
                    remediation_recommendation=rule.remediation,
                    limitations="Incomplete capture without responder response prevents confirming negotiated algorithm."
                )

            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                policy_version=policy_version,
                category=rule.category,
                title=rule.title,
                outcome=EvaluationOutcome.PASS,
                severity=rule.severity,
                expected_property=f"Allowed: {rule.allowed_values}",
                observed_value=names,
                evidence_ids=[e.id for e in analysis.evidence_items if "ENCR" in e.field_name],
                evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                technical_reasoning="All observed encryption transforms comply with declared cryptographic policy.",
                remediation_recommendation=rule.remediation,
                limitations=rule.limitations
            )

        # 3. INTEGRITY evaluation
        elif rule.category == "INTEGRITY":
            integ_obs = transforms.get("INTEG", [])
            encr_obs = transforms.get("ENCR", [])
            # If using AEAD like AES-GCM, separate INTEG transform is not applicable
            is_aead = any("GCM" in o["name"] or "CHACHA20" in o["name"] for o in encr_obs)
            if not integ_obs and is_aead:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.NOT_APPLICABLE,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value="AEAD Cipher In Use (Integrated Integrity)",
                    evidence_ids=[e.id for e in analysis.evidence_items if "ENCR" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning="AEAD encryption (e.g., AES-GCM) inherently includes cryptographic integrity; separate INTEG transform is omitted per RFC 7296.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            if not integ_obs:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value="No INTEG transform observed",
                    evidence_ids=[],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="No integrity transform was observed in the captured proposal.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            names = [o["name"] for o in integ_obs]
            prohibited_found = [n for n in names if n in rule.prohibited_values]
            if prohibited_found:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property=f"Forbidden: {rule.prohibited_values}",
                    observed_value=names,
                    evidence_ids=[e.id for e in analysis.evidence_items if "INTEG" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning=f"Prohibited integrity algorithm(s) {prohibited_found} found in negotiation proposal.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                policy_version=policy_version,
                category=rule.category,
                title=rule.title,
                outcome=EvaluationOutcome.PASS,
                severity=rule.severity,
                expected_property=f"Allowed: {rule.allowed_values}",
                observed_value=names,
                evidence_ids=[e.id for e in analysis.evidence_items if "INTEG" in e.field_name],
                evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                technical_reasoning="Observed integrity algorithms comply with policy rules.",
                remediation_recommendation=rule.remediation,
                limitations=rule.limitations
            )

        # 4. PRF evaluation
        elif rule.category == "PRF":
            prf_obs = transforms.get("PRF", [])
            if not prf_obs:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value="No PRF transform observed",
                    evidence_ids=[],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="PRF transform was not observed in capture evidence.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            names = [o["name"] for o in prf_obs]
            prohibited_found = [n for n in names if n in rule.prohibited_values]
            if prohibited_found:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property=f"Forbidden: {rule.prohibited_values}",
                    observed_value=names,
                    evidence_ids=[e.id for e in analysis.evidence_items if "PRF" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning=f"Prohibited PRF algorithm(s) {prohibited_found} observed in negotiation proposal.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            if rule.allowed_values and not any(n in rule.allowed_values for n in names):
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value=names,
                    evidence_ids=[e.id for e in analysis.evidence_items if "PRF" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning=f"Observed PRF {names} does not satisfy allowed set {rule.allowed_values}.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            # Ensure negotiated status: if only offered by initiator and responder never replied, return UNKNOWN
            has_negotiated = any(o.get("is_negotiated", True) for o in prf_obs)
            if not has_negotiated:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed (Negotiated): {rule.allowed_values}",
                    observed_value=f"Offered only: {names}",
                    evidence_ids=[e.id for e in analysis.evidence_items if "PRF" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="Handshake incomplete: Only initiator proposal offers observed. Responder selection was not captured, so negotiated PRF cannot be confirmed as PASS.",
                    remediation_recommendation=rule.remediation,
                    limitations="Incomplete capture without responder response prevents confirming negotiated algorithm."
                )

            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                policy_version=policy_version,
                category=rule.category,
                title=rule.title,
                outcome=EvaluationOutcome.PASS,
                severity=rule.severity,
                expected_property=f"Allowed: {rule.allowed_values}",
                observed_value=names,
                evidence_ids=[e.id for e in analysis.evidence_items if "PRF" in e.field_name],
                evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                technical_reasoning="All observed PRF transforms satisfy policy requirements.",
                remediation_recommendation=rule.remediation,
                limitations=rule.limitations
            )

        # 5. DH_GROUP evaluation
        elif rule.category == "DH_GROUP":
            dh_obs = transforms.get("D-H", [])
            if not dh_obs:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed: {rule.allowed_values}",
                    observed_value="No DH transform observed",
                    evidence_ids=[],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="Diffie-Hellman group transform was not observed in negotiation proposals.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            names = [o["name"] for o in dh_obs]
            prohibited_found = [n for n in names if n in rule.prohibited_values]
            if prohibited_found:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property=f"Forbidden: {rule.prohibited_values}",
                    observed_value=names,
                    evidence_ids=[e.id for e in analysis.evidence_items if "D-H" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning=f"Weak or prohibited Diffie-Hellman group(s) {prohibited_found} found in proposal.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            if rule.min_dh_group:
                ids = [o["id"] for o in dh_obs]
                if any(i < rule.min_dh_group for i in ids):
                    return RuleEvaluationResult(
                        rule_id=rule.rule_id,
                        policy_version=policy_version,
                        category=rule.category,
                        title=rule.title,
                        outcome=EvaluationOutcome.FAIL,
                        severity=rule.severity,
                        expected_property=f"Min DH Group: {rule.min_dh_group}",
                        observed_value=names,
                        evidence_ids=[e.id for e in analysis.evidence_items if "D-H" in e.field_name],
                        evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                        technical_reasoning=f"DH Group ID(s) {ids} are below minimum required group {rule.min_dh_group}.",
                        remediation_recommendation=rule.remediation,
                        limitations=rule.limitations
                    )

            # Ensure negotiated status: if only offered by initiator and responder never replied, return UNKNOWN
            has_negotiated = any(o.get("is_negotiated", True) for o in dh_obs)
            if not has_negotiated:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property=f"Allowed (Negotiated): {rule.allowed_values}",
                    observed_value=f"Offered only: {names}",
                    evidence_ids=[e.id for e in analysis.evidence_items if "D-H" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="Handshake incomplete: Only initiator proposal offers observed. Responder selection was not captured, so negotiated Diffie-Hellman group cannot be confirmed as PASS.",
                    remediation_recommendation=rule.remediation,
                    limitations="Incomplete capture without responder response prevents confirming negotiated algorithm."
                )

            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                policy_version=policy_version,
                category=rule.category,
                title=rule.title,
                outcome=EvaluationOutcome.PASS,
                severity=rule.severity,
                expected_property=f"Allowed: {rule.allowed_values}",
                observed_value=names,
                evidence_ids=[e.id for e in analysis.evidence_items if "D-H" in e.field_name],
                evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                technical_reasoning="Observed Diffie-Hellman group meets or exceeds policy security thresholds.",
                remediation_recommendation=rule.remediation,
                limitations=rule.limitations
            )

        # 6. REPLAY_PROTECTION evaluation
        elif rule.category == "REPLAY_PROTECTION":
            esn_obs = transforms.get("ESN", [])
            if not esn_obs:
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.UNKNOWN,
                    severity=rule.severity,
                    expected_property="ESN Transform in child SA",
                    observed_value="No ESN transform observed",
                    evidence_ids=[],
                    evidence_sufficiency=EvidenceSufficiency.INSUFFICIENT,
                    technical_reasoning="No ESN transform was extracted from child SA negotiation.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            names = [o["name"] for o in esn_obs]
            if rule.require_esn and not any(n == "ESN" for n in names):
                return RuleEvaluationResult(
                    rule_id=rule.rule_id,
                    policy_version=policy_version,
                    category=rule.category,
                    title=rule.title,
                    outcome=EvaluationOutcome.FAIL,
                    severity=rule.severity,
                    expected_property="ESN=1 (Extended Sequence Numbers enabled)",
                    observed_value=names,
                    evidence_ids=[e.id for e in analysis.evidence_items if "ESN" in e.field_name],
                    evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                    technical_reasoning="Proposal configured NO_ESN (32-bit sequence numbers only), failing high-speed replay requirement.",
                    remediation_recommendation=rule.remediation,
                    limitations=rule.limitations
                )

            return RuleEvaluationResult(
                rule_id=rule.rule_id,
                policy_version=policy_version,
                category=rule.category,
                title=rule.title,
                outcome=EvaluationOutcome.PASS,
                severity=rule.severity,
                expected_property="ESN=1",
                observed_value=names,
                evidence_ids=[e.id for e in analysis.evidence_items if "ESN" in e.field_name],
                evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
                technical_reasoning="Extended Sequence Numbers (ESN) correctly negotiated.",
                remediation_recommendation=rule.remediation,
                limitations=rule.limitations
            )

        # Generic fallback
        return RuleEvaluationResult(
            rule_id=rule.rule_id,
            policy_version=policy_version,
            category=rule.category,
            title=rule.title,
            outcome=EvaluationOutcome.NOT_APPLICABLE,
            severity=rule.severity,
            expected_property="N/A",
            observed_value="Not applicable to current evidence context",
            evidence_ids=[],
            evidence_sufficiency=EvidenceSufficiency.SUFFICIENT,
            technical_reasoning="Rule does not match any evaluated protocol property in this context.",
            remediation_recommendation=rule.remediation,
            limitations=rule.limitations
        )


policy_engine = PolicyEngine()
