import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from enum import Enum

from ..core.config import settings
from ..schemas.common import ObservationProvenance, EvidenceSufficiency, EvaluationOutcome, SeverityLevel, EvidenceItem
from ..schemas.capture import CaptureAnalysisResult, SessionSummary, PacketSummary, IKEProposal, IKETransform
from ..schemas.policy import PolicyEvaluationReport, RuleEvaluationResult
from ..schemas.crypto_inventory import CryptoInventoryReport, CryptoAsset
from ..schemas.report import AssessmentReport

class AnalysisStatus(str, Enum):
    UPLOADED = "UPLOADED"
    VALIDATING = "VALIDATING"
    PROCESSING = "PROCESSING"
    READY = "READY"
    FAILED = "FAILED"


class SessionRepository:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            self.db_path = settings.capture_dir.parent / "iketrace.db"
        else:
            self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    file_hash_sha256 TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    uploaded_at TEXT NOT NULL,
                    total_packets INTEGER DEFAULT 0,
                    ike_packets INTEGER DEFAULT 0,
                    esp_packets INTEGER DEFAULT 0,
                    other_packets INTEGER DEFAULT 0,
                    session_count INTEGER DEFAULT 0,
                    parse_completeness_pct REAL DEFAULT 0.0,
                    parser_backend TEXT DEFAULT 'scapy_native',
                    parser_warnings_json TEXT DEFAULT '[]',
                    sessions_json TEXT DEFAULT '[]',
                    packets_json TEXT DEFAULT '[]',
                    evidence_items_json TEXT DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS evaluations (
                    evaluation_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    evaluated_at TEXT NOT NULL,
                    compliance_score_pct REAL NOT NULL,
                    total_rules INTEGER NOT NULL,
                    passed_count INTEGER NOT NULL,
                    failed_count INTEGER NOT NULL,
                    unknown_count INTEGER NOT NULL,
                    not_applicable_count INTEGER NOT NULL,
                    report_json TEXT NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS crypto_inventories (
                    inventory_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    pqc_readiness_score_pct REAL NOT NULL,
                    report_json TEXT NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS assessment_reports (
                    report_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    policy_id TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    markdown_content TEXT NOT NULL,
                    report_hash TEXT NOT NULL,
                    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id) ON DELETE CASCADE
                );
            """)

    def save_analysis(self, result: CaptureAnalysisResult, status: AnalysisStatus = AnalysisStatus.READY, error_message: Optional[str] = None) -> None:
        now_str = datetime.now(timezone.utc).isoformat()
        sessions_json = json.dumps([s.model_dump() for s in result.sessions], default=str)
        packets_json = json.dumps([p.model_dump() for p in result.packets], default=str)
        evidence_json = json.dumps([e.model_dump() for e in result.evidence_items], default=str)
        warnings_json = json.dumps(result.parser_warnings)

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO analyses (
                    analysis_id, filename, file_hash_sha256, file_size_bytes,
                    status, error_message, uploaded_at, total_packets,
                    ike_packets, esp_packets, other_packets, session_count,
                    parse_completeness_pct, parser_backend, parser_warnings_json,
                    sessions_json, packets_json, evidence_items_json,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    status=excluded.status,
                    error_message=excluded.error_message,
                    total_packets=excluded.total_packets,
                    ike_packets=excluded.ike_packets,
                    esp_packets=excluded.esp_packets,
                    other_packets=excluded.other_packets,
                    session_count=excluded.session_count,
                    parse_completeness_pct=excluded.parse_completeness_pct,
                    parser_warnings_json=excluded.parser_warnings_json,
                    sessions_json=excluded.sessions_json,
                    packets_json=excluded.packets_json,
                    evidence_items_json=excluded.evidence_items_json,
                    updated_at=excluded.updated_at;
            """, (
                result.capture_id,
                result.filename,
                result.file_hash_sha256 or "unknown",
                result.file_size_bytes,
                status.value,
                error_message,
                result.uploaded_at or now_str,
                result.total_packets,
                result.ike_packets,
                result.esp_packets,
                result.other_packets,
                result.session_count,
                result.parse_completeness_pct,
                result.parser_backend,
                warnings_json,
                sessions_json,
                packets_json,
                evidence_json,
                now_str,
                now_str
            ))

    def get_analysis(self, analysis_id: str) -> Optional[CaptureAnalysisResult]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
            if not row:
                return None
            return self._row_to_analysis(row)

    def list_analyses(self) -> List[CaptureAnalysisResult]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM analyses ORDER BY created_at DESC").fetchall()
            return [self._row_to_analysis(r) for r in rows]

    def delete_analysis(self, analysis_id: str) -> bool:
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,))
            return cur.rowcount > 0

    def _row_to_analysis(self, row: sqlite3.Row) -> CaptureAnalysisResult:
        sessions_data = json.loads(row["sessions_json"]) if row["sessions_json"] else []
        packets_data = json.loads(row["packets_json"]) if row["packets_json"] else []
        evidence_data = json.loads(row["evidence_items_json"]) if row["evidence_items_json"] else []
        warnings = json.loads(row["parser_warnings_json"]) if row["parser_warnings_json"] else []

        sessions = [SessionSummary.model_validate(s) for s in sessions_data]
        packets = [PacketSummary.model_validate(p) for p in packets_data]
        evidence_items = [EvidenceItem.model_validate(e) for e in evidence_data]

        return CaptureAnalysisResult(
            capture_id=row["analysis_id"],
            filename=row["filename"],
            file_hash_sha256=row["file_hash_sha256"],
            file_size_bytes=row["file_size_bytes"],
            uploaded_at=row["uploaded_at"],
            status=row["status"],
            total_packets=row["total_packets"],
            ike_packets=row["ike_packets"],
            esp_packets=row["esp_packets"],
            other_packets=row["other_packets"],
            session_count=row["session_count"],
            parse_completeness_pct=row["parse_completeness_pct"],
            parser_backend=row["parser_backend"],
            parser_warnings=warnings,
            sessions=sessions,
            packets=packets,
            evidence_items=evidence_items,
        )

    # Evaluations persistence
    def save_evaluation(self, report: PolicyEvaluationReport) -> None:
        rep_json = report.model_dump_json()
        eval_id = f"eval-{report.target_id}-{report.policy_id}"
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO evaluations (
                    evaluation_id, analysis_id, policy_id, policy_name, policy_version,
                    evaluated_at, compliance_score_pct, total_rules, passed_count,
                    failed_count, unknown_count, not_applicable_count, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(evaluation_id) DO UPDATE SET
                    evaluated_at=excluded.evaluated_at,
                    compliance_score_pct=excluded.compliance_score_pct,
                    total_rules=excluded.total_rules,
                    passed_count=excluded.passed_count,
                    failed_count=excluded.failed_count,
                    unknown_count=excluded.unknown_count,
                    not_applicable_count=excluded.not_applicable_count,
                    report_json=excluded.report_json;
            """, (
                eval_id,
                report.target_id,
                report.policy_id,
                report.policy_name,
                report.policy_version,
                report.evaluated_at,
                report.compliance_score_pct,
                report.total_rules,
                report.passed_count,
                report.failed_count,
                report.unknown_count,
                report.not_applicable_count,
                rep_json
            ))

    def get_evaluation(self, analysis_id: str, policy_id: str) -> Optional[PolicyEvaluationReport]:
        eval_id = f"eval-{analysis_id}-{policy_id}"
        with self._get_connection() as conn:
            row = conn.execute("SELECT report_json FROM evaluations WHERE evaluation_id = ?", (eval_id,)).fetchone()
            if not row:
                return None
            return PolicyEvaluationReport.model_validate_json(row["report_json"])

    def list_evaluations_for_analysis(self, analysis_id: str) -> List[PolicyEvaluationReport]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT report_json FROM evaluations WHERE analysis_id = ? ORDER BY evaluated_at DESC", (analysis_id,)).fetchall()
            return [PolicyEvaluationReport.model_validate_json(r["report_json"]) for r in rows]

    # Crypto inventory persistence
    def save_crypto_inventory(self, report: CryptoInventoryReport) -> None:
        rep_json = report.model_dump_json()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO crypto_inventories (
                    inventory_id, analysis_id, generated_at, pqc_readiness_score_pct, report_json
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(inventory_id) DO UPDATE SET
                    generated_at=excluded.generated_at,
                    pqc_readiness_score_pct=excluded.pqc_readiness_score_pct,
                    report_json=excluded.report_json;
            """, (
                report.inventory_id,
                report.target_id,
                report.generated_at,
                report.pqc_readiness_score_pct,
                rep_json
            ))

    def get_crypto_inventory(self, analysis_id: str) -> Optional[CryptoInventoryReport]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT report_json FROM crypto_inventories WHERE analysis_id = ? ORDER BY generated_at DESC LIMIT 1", (analysis_id,)).fetchone()
            if not row:
                return None
            return CryptoInventoryReport.model_validate_json(row["report_json"])

    # Reports persistence
    def save_report(self, report: AssessmentReport) -> None:
        policy_id = report.policy_report.policy_id if report.policy_report else "POL-DEF-NIST-SP800-77"
        report_hash = getattr(report, "reproducibility_fingerprint", getattr(report, "audit_hash", "none"))
        rep_json = report.model_dump_json()
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO assessment_reports (
                    report_id, analysis_id, title, policy_id, generated_at, markdown_content, report_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(report_id) DO UPDATE SET
                    title=excluded.title,
                    generated_at=excluded.generated_at,
                    markdown_content=excluded.markdown_content,
                    report_hash=excluded.report_hash;
            """, (
                report.report_id,
                report.target_id,
                report.title,
                policy_id,
                report.generated_at,
                rep_json,
                report_hash
            ))

    def list_reports_for_analysis(self, analysis_id: str) -> List[AssessmentReport]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM assessment_reports WHERE analysis_id = ? ORDER BY generated_at DESC", (analysis_id,)).fetchall()
            results = []
            for r in rows:
                content = r["markdown_content"]
                if content and content.startswith("{"):
                    try:
                        results.append(AssessmentReport.model_validate_json(content))
                        continue
                    except Exception:
                        pass
                results.append(
                    AssessmentReport(
                        report_id=r["report_id"],
                        title=r["title"],
                        generated_at=r["generated_at"],
                        assessor="IKETrace Defensive Workbench",
                        target_id=r["analysis_id"],
                        target_type="CAPTURE",
                        executive_summary="Saved assessment report",
                        overall_verdict="COMPLIANT",
                        audit_hash=r["report_hash"],
                        reproducibility_fingerprint=r["report_hash"],
                        markdown_content=content
                    )
                )
            return results

session_repository = SessionRepository()
