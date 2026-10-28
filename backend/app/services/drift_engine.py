import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ..schemas.common import EvaluationOutcome, SeverityLevel
from ..schemas.policy import PolicyEvaluationReport
from ..schemas.drift import BaselineSnapshot, DriftDifference, DriftReport

class DriftEngine:
    def __init__(self):
        self.baselines: Dict[str, BaselineSnapshot] = {}

    def create_baseline(
        self,
        name: str,
        policy_report: PolicyEvaluationReport,
        target_id: str,
        observed_parameters: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> BaselineSnapshot:
        baseline_id = f"BASE-{uuid.uuid4().hex[:8].upper()}"
        outcomes_map = {r.rule_id: r.outcome.value for r in policy_report.results}

        snapshot = BaselineSnapshot(
            snapshot_id=baseline_id,
            name=name,
            created_at=datetime.now(timezone.utc).isoformat(),
            target_id=target_id,
            policy_id=policy_report.policy_id,
            policy_version=policy_report.policy_version,
            compliance_score_pct=policy_report.compliance_score_pct,
            finding_outcomes=outcomes_map,
            observed_parameters=observed_parameters or {},
            metadata=metadata or {}
        )

        self.baselines[baseline_id] = snapshot
        return snapshot

    def get_baseline(self, baseline_id: str) -> Optional[BaselineSnapshot]:
        return self.baselines.get(baseline_id)

    def list_baselines(self) -> List[BaselineSnapshot]:
        return list(self.baselines.values())

    def compare_drift(
        self,
        baseline_id: str,
        current_report: PolicyEvaluationReport
    ) -> DriftReport:
        baseline = self.get_baseline(baseline_id)
        if not baseline:
            raise ValueError(f"Baseline {baseline_id} does not exist.")

        differences: List[DriftDifference] = []
        new_violations = 0
        resolved_violations = 0
        newly_unknown = 0
        regression_detected = False

        # Map current results by rule_id
        current_map = {r.rule_id: r for r in current_report.results}

        # Check all rules in current report
        for rule_id, curr_result in current_map.items():
            base_outcome = baseline.finding_outcomes.get(rule_id)
            curr_outcome = curr_result.outcome.value

            if base_outcome is None:
                # Rule was introduced in a newer policy version
                diff = DriftDifference(
                    rule_id=rule_id,
                    category=curr_result.category,
                    title=curr_result.title,
                    severity=curr_result.severity,
                    baseline_outcome=None,
                    current_outcome=curr_outcome,
                    difference_type="CHANGED_POLICY_RULE",
                    is_regression=False,
                    technical_explanation=f"Rule {rule_id} is present in current evaluation but was absent in baseline.",
                    evidence_reference=f"Target {current_report.target_id}",
                    recommended_regression_tests=["Verify organizational policy update acceptance"]
                )
                differences.append(diff)
                continue

            if base_outcome != curr_outcome:
                # Determine difference type
                diff_type = "MODIFIED"
                is_reg = False
                explanation = ""
                recommended_tests: List[str] = []

                if base_outcome == "PASS" and curr_outcome == "FAIL":
                    diff_type = "NEW_VIOLATION"
                    is_reg = True
                    new_violations += 1
                    regression_detected = True
                    explanation = f"Security Regression: Rule {rule_id} previously PASSED in baseline but now FAILS."
                    recommended_tests = [
                        f"Run isolated regression test for {curr_result.category}",
                        "Audit recent VPN configuration deployments and peer profile changes",
                    ]
                elif base_outcome == "FAIL" and curr_outcome == "PASS":
                    diff_type = "RESOLVED_VIOLATION"
                    resolved_violations += 1
                    explanation = f"Violation Remediated: Rule {rule_id} previously FAILED and is now PASSED."
                    recommended_tests = ["Validate sustained compliance under traffic load"]
                elif curr_outcome == "UNKNOWN" and base_outcome != "UNKNOWN":
                    diff_type = "NEWLY_UNKNOWN"
                    newly_unknown += 1
                    explanation = f"Loss of Evidence Sufficiency: Rule {rule_id} had verified outcome '{base_outcome}', but current capture lacks sufficient evidence."
                    recommended_tests = ["Verify full packet capture tap placement to prevent packet loss"]
                else:
                    diff_type = "STATE_CHANGE"
                    explanation = f"Outcome shifted from '{base_outcome}' to '{curr_outcome}'."

                differences.append(DriftDifference(
                    rule_id=rule_id,
                    category=curr_result.category,
                    title=curr_result.title,
                    severity=curr_result.severity,
                    baseline_outcome=base_outcome,
                    current_outcome=curr_outcome,
                    difference_type=diff_type,
                    is_regression=is_reg,
                    technical_explanation=explanation,
                    evidence_reference=f"Target {current_report.target_id}",
                    recommended_regression_tests=recommended_tests
                ))

        summary = "No configuration drift detected."
        if regression_detected:
            summary = f"CRITICAL: Security regression detected with {new_violations} new violation(s)."
        elif resolved_violations > 0 and new_violations == 0:
            summary = f"POSITIVE: {resolved_violations} previous violation(s) successfully remediated."
        elif differences:
            summary = f"INFO: {len(differences)} rule outcome change(s) observed without new violations."

        report = DriftReport(
            drift_report_id=f"DRIFT-{uuid.uuid4().hex[:8].upper()}",
            baseline_id=baseline_id,
            baseline_name=baseline.name,
            current_target_id=current_report.target_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_rules_compared=len(current_report.results),
            new_violations_count=new_violations,
            resolved_violations_count=resolved_violations,
            newly_unknown_count=newly_unknown,
            regression_detected=regression_detected,
            differences=differences,
            summary_verdict=summary,
        )

        return report


drift_engine = DriftEngine()
