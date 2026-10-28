import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from ..schemas.report import AssessmentReport
from ..schemas.policy import PolicyEvaluationReport
from ..schemas.drift import DriftReport
from ..schemas.crypto_inventory import CryptoInventoryReport
from .audit_service import audit_service

class ReportService:
    def __init__(self):
        self.reports: Dict[str, AssessmentReport] = {}

    def generate_assessment_report(
        self,
        title: str,
        target_id: str,
        target_type: str,
        policy_report: Optional[PolicyEvaluationReport] = None,
        drift_report: Optional[DriftReport] = None,
        crypto_inventory: Optional[CryptoInventoryReport] = None,
    ) -> AssessmentReport:
        report_id = f"REP-{uuid.uuid4().hex[:10].upper()}"
        now_str = datetime.now(timezone.utc).isoformat()

        # Audit verification
        audit_res = audit_service.verify_chain()
        last_rec = audit_service.get_records()[-1] if audit_service.get_records() else None
        audit_hash = last_rec.record_hash if last_rec else "0"*64

        # Reproducibility fingerprint
        fingerprint_data = {
            "target_id": target_id,
            "target_type": target_type,
            "policy_id": policy_report.policy_id if policy_report else None,
            "policy_version": policy_report.policy_version if policy_report else None,
            "passed_count": policy_report.passed_count if policy_report else 0,
            "failed_count": policy_report.failed_count if policy_report else 0,
            "audit_hash": audit_hash,
        }
        fingerprint = hashlib.sha256(json.dumps(fingerprint_data, sort_keys=True).encode('utf-8')).hexdigest()

        # Determine overall verdict
        verdict = "COMPLIANT"
        if policy_report and policy_report.failed_count > 0:
            verdict = "VIOLATIONS_FOUND"
        elif drift_report and drift_report.regression_detected:
            verdict = "SECURITY_REGRESSION"
        elif policy_report and policy_report.unknown_count > policy_report.passed_count:
            verdict = "INSUFFICIENT_EVIDENCE"

        # Executive summary
        exec_summary = (
            f"Defensive security assessment completed for target '{target_id}' ({target_type}). "
        )
        if policy_report:
            exec_summary += (
                f"Evaluated {policy_report.total_rules} rules under '{policy_report.policy_name}' (v{policy_report.policy_version}), "
                f"yielding a {policy_report.compliance_score_pct}% compliance score ({policy_report.passed_count} PASS, "
                f"{policy_report.failed_count} FAIL, {policy_report.unknown_count} UNKNOWN). "
            )
        if drift_report and drift_report.regression_detected:
            exec_summary += f"WARNING: Configuration drift detected with {drift_report.new_violations_count} new regression violations. "
        if crypto_inventory:
            exec_summary += f"Cryptographic inventory cataloged {crypto_inventory.total_assets_inventoried} assets with {crypto_inventory.pqc_readiness_score_pct}% post-quantum readiness score."

        limitations = [
            "The absence of a detected violation is not proof that a VPN is cryptographically secure or defect-free.",
            "IKETrace operates strictly on authorized passive packet observations and configuration metadata. It does not attempt plaintext recovery or private key extraction.",
            "Unobserved protocol phases (e.g. encrypted IKE_AUTH or internal child SA rekeys) remain UNKNOWN where evidence is absent.",
            "Local SHA-256 hash chain detects modifications against a trusted anchor; it does not replace third-party public key digital signatures."
        ]

        # Markdown representation
        md_lines = [
            f"# {title}",
            f"**Report ID:** `{report_id}` | **Generated:** {now_str} | **Verdict:** `{verdict}`",
            f"**Assessor:** IKETrace Automated Security Engine | **Target ID:** `{target_id}`",
            f"**Reproducibility Fingerprint:** `{fingerprint}`",
            "",
            "## 1. Executive Summary",
            exec_summary,
            "",
            "## 2. Policy-to-Evidence Evaluation",
        ]

        if policy_report:
            md_lines.append(f"| Rule ID | Category | Verdict | Severity | Observed Value | Expected Property |")
            md_lines.append(f"| :--- | :--- | :---: | :---: | :--- | :--- |")
            for r in policy_report.results:
                md_lines.append(f"| `{r.rule_id}` | {r.category} | **{r.outcome.value}** | {r.severity.value} | {str(r.observed_value)[:35]} | {r.expected_property[:35]} |")
            md_lines.append("")

        if drift_report:
            md_lines.extend([
                "## 3. Configuration Drift & Baseline Comparison",
                f"- **Baseline ID:** `{drift_report.baseline_id}` ({drift_report.baseline_name})",
                f"- **New Violations:** {drift_report.new_violations_count} | **Resolved:** {drift_report.resolved_violations_count}",
                f"- **Regression Status:** {'CRITICAL REGRESSION DETECTED' if drift_report.regression_detected else 'No Regression'}",
                "",
            ])

        if crypto_inventory:
            md_lines.extend([
                "## 4. Cryptographic Inventory & PQC Readiness",
                f"- **Total Assets:** {crypto_inventory.total_assets_inventoried} | **Compliant:** {crypto_inventory.compliant_assets_count} | **Quantum Vulnerable:** {crypto_inventory.quantum_vulnerable_assets_count}",
                f"- **PQC Readiness Score:** {crypto_inventory.pqc_readiness_score_pct}%",
                "",
            ])

        md_lines.extend([
            "## 5. Tamper-Evident Audit Verification",
            f"- **Chain Integrity:** {'VALID (100% Intact)' if audit_res.chain_intact else 'TAMPER DETECTED'}",
            f"- **Audit Hash Anchor:** `{audit_hash}`",
            "",
            "## 6. Engineering Limitations and Disclaimers",
        ])
        for lim in limitations:
            md_lines.append(f"- {lim}")

        md_content = "\n".join(md_lines)

        rep = AssessmentReport(
            report_id=report_id,
            title=title,
            generated_at=now_str,
            assessor="IKETrace Automated Security Engine",
            target_id=target_id,
            target_type=target_type,
            executive_summary=exec_summary,
            overall_verdict=verdict,
            policy_report=policy_report,
            drift_report=drift_report,
            crypto_inventory=crypto_inventory,
            audit_chain_verified=audit_res.chain_intact,
            audit_hash=audit_hash,
            reproducibility_fingerprint=fingerprint,
            methodology_limitations=limitations,
            markdown_content=md_content
        )

        self.reports[report_id] = rep
        # Record event in audit service
        audit_service.record_event(
            event_type="REPORT_GENERATED",
            entity_id=report_id,
            entity_type="ASSESSMENT_REPORT",
            data={"report_id": report_id, "verdict": verdict, "fingerprint": fingerprint}
        )
        return rep

    def get_report(self, report_id: str) -> Optional[AssessmentReport]:
        return self.reports.get(report_id)

    def list_reports(self) -> List[AssessmentReport]:
        return list(self.reports.values())


report_service = ReportService()
