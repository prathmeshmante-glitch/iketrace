from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sklearn.ensemble import RandomForestClassifier

from ..ml.training import generate_synthetic_flow_dataset, train_baseline_model
from ..ml.evaluation import evaluate_trained_model
from ..ml.inference import predict_flow_class
from ..schemas.traffic_privacy import (
    TrafficFlowFeatures,
    ModelEvaluationReport,
    PrivacyExposureSummary,
)

class TrafficPrivacyLabService:
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.last_evaluation_report: Optional[ModelEvaluationReport] = None
        self.cached_features: List[TrafficFlowFeatures] = []
        self._initialize_default_experiment()

    def _initialize_default_experiment(self) -> None:
        """Run initial verified baseline experiment on startup."""
        feats, groups = generate_synthetic_flow_dataset(num_sessions_per_class=15)
        self.cached_features = feats
        clf, train_f, test_f, X_tr, X_te, y_tr, y_te = train_baseline_model(feats, groups)
        self.model = clf
        self.last_evaluation_report = evaluate_trained_model(clf, X_tr, X_te, y_tr, y_te, test_f)

    def run_training_experiment(self, num_sessions_per_class: int = 15) -> ModelEvaluationReport:
        feats, groups = generate_synthetic_flow_dataset(num_sessions_per_class=num_sessions_per_class)
        self.cached_features = feats
        clf, train_f, test_f, X_tr, X_te, y_tr, y_te = train_baseline_model(feats, groups)
        self.model = clf
        report = evaluate_trained_model(clf, X_tr, X_te, y_tr, y_te, test_f)
        self.last_evaluation_report = report
        return report

    def get_latest_evaluation(self) -> ModelEvaluationReport:
        if not self.last_evaluation_report:
            self._initialize_default_experiment()
        return self.last_evaluation_report

    def classify_flow(self, flow: TrafficFlowFeatures) -> Dict[str, Any]:
        if not self.model:
            self._initialize_default_experiment()
        return predict_flow_class(self.model, flow)

    def get_privacy_exposure_summary(self, target_id: str = "current-lab") -> PrivacyExposureSummary:
        report = self.get_latest_evaluation()
        highest_feat = list(report.feature_importances.keys())[0] if report.feature_importances else "mean_packet_size"

        return PrivacyExposureSummary(
            target_id=target_id,
            analyzed_flows_count=report.test_samples_count,
            identifiable_classes_count=len(report.per_class_f1),
            highest_vulnerability_leakage_feature=highest_feat,
            mitigation_recommendation=(
                "Implement constant-size ESP packet padding (e.g., pad packets to 512 or 1024-byte boundaries) "
                "to obscure payload length distributions."
            ),
            padding_recommendation="RFC 4303 Variable Length Padding & Traffic Flow Confidentiality (TFC) padding."
        )

    def extract_features_from_capture(self, analysis: Any) -> List[TrafficFlowFeatures]:
        """Deterministically extract TrafficFlowFeatures from real packets in a capture."""
        if not analysis.packets:
            return []

        # Group packets by session or flow key
        flow_groups: Dict[str, List[Any]] = {}
        for p in analysis.packets:
            key = f"{tuple(sorted([p.src_ip, p.dst_ip]))}_{p.esp_spi or (p.initiator_spi[:8] if p.initiator_spi else '0')}"
            if key not in flow_groups:
                flow_groups[key] = []
            flow_groups[key].append(p)

        features: List[TrafficFlowFeatures] = []
        for idx, (fkey, pkts) in enumerate(flow_groups.items()):
            pkts_sorted = sorted(pkts, key=lambda x: x.timestamp)
            sizes = [getattr(p, "length", getattr(p, "length_bytes", 64)) for p in pkts_sorted]
            total_bytes = sum(sizes)
            mean_sz = float(total_bytes / len(sizes))
            std_sz = float((sum((s - mean_sz) ** 2 for s in sizes) / len(sizes)) ** 0.5) if len(sizes) > 1 else 0.0
            
            dur = max(0.0, float(pkts_sorted[-1].timestamp - pkts_sorted[0].timestamp))
            iats = [float((pkts_sorted[i].timestamp - pkts_sorted[i-1].timestamp) * 1000.0) for i in range(1, len(pkts_sorted))]
            mean_iat = float(sum(iats) / len(iats)) if iats else 0.0
            std_iat = float((sum((i - mean_iat) ** 2 for i in iats) / len(iats)) ** 0.5) if len(iats) > 1 else 0.0
            min_iat = float(min(iats)) if iats else 0.0
            max_iat = float(max(iats)) if iats else 0.0

            burst_cnt = sum(1 for i in iats if i < 50.0)
            mean_burst = float(total_bytes / max(1, burst_cnt))

            first_src = pkts_sorted[0].src_ip
            fwd = sum(1 for p in pkts_sorted if p.src_ip == first_src)
            bwd = len(pkts_sorted) - fwd
            ratio = float(fwd / max(1, bwd))

            features.append(TrafficFlowFeatures(
                flow_id=f"flow-{analysis.capture_id}-{idx + 1}",
                session_id=analysis.capture_id,
                packet_count=len(pkts_sorted),
                total_bytes=total_bytes,
                duration_seconds=round(dur, 4),
                mean_packet_size=round(mean_sz, 2),
                std_packet_size=round(std_sz, 2),
                min_packet_size=min(sizes),
                max_packet_size=max(sizes),
                mean_iat_ms=round(mean_iat, 2),
                std_iat_ms=round(std_iat, 2),
                min_iat_ms=round(min_iat, 2),
                max_iat_ms=round(max_iat, 2),
                burst_count=burst_cnt,
                mean_burst_bytes=round(mean_burst, 2),
                forward_backward_ratio=round(ratio, 2),
                ground_truth_label="Unlabeled (Real Capture)"
            ))

        return features


traffic_privacy_service = TrafficPrivacyLabService()

