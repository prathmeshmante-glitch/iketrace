from typing import List, Dict, Any, Optional
from ..schemas.capture import CaptureAnalysisResult
from ..schemas.policy import PolicyEvaluationReport

class EvidenceGraphEngine:
    def generate_graph_data(
        self,
        analysis: Optional[CaptureAnalysisResult] = None,
        policy_report: Optional[PolicyEvaluationReport] = None,
        target_name: str = "Active Assessment"
    ) -> Dict[str, Any]:
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []

        # 1. Root Target Node
        root_id = "node-target-root"
        nodes.append({
            "id": root_id,
            "type": "input",
            "data": {
                "label": target_name,
                "category": "TARGET_ROOT",
                "status": "ACTIVE",
                "details": f"Target ID: {analysis.capture_id if analysis else 'Synthetic'}",
            },
            "position": {"x": 400, "y": 50}
        })

        if not analysis:
            return {"nodes": nodes, "edges": edges}

        # 2. Session Nodes
        y_session = 180
        x_start = 100
        for s_idx, session in enumerate(analysis.sessions[:4]):
            s_node_id = f"node-session-{session.session_id}"
            nodes.append({
                "id": s_node_id,
                "type": "default",
                "data": {
                    "label": f"Session: {session.ike_version or 'IKE'}",
                    "category": "SESSION",
                    "status": "OBSERVED",
                    "details": f"{session.initiator_ip} <-> {session.responder_ip} ({session.packet_count} pkts)",
                },
                "position": {"x": x_start + (s_idx * 280), "y": y_session}
            })
            edges.append({
                "id": f"edge-root-{s_node_id}",
                "source": root_id,
                "target": s_node_id,
                "label": "groups",
                "animated": True,
            })

            # 3. Direct Evidence Nodes under this Session
            y_ev = 320
            for e_idx, ev in enumerate(session.evidence_items[:3]):
                ev_node_id = f"node-ev-{ev.id}"
                nodes.append({
                    "id": ev_node_id,
                    "type": "default",
                    "data": {
                        "label": ev.field_name,
                        "category": "EVIDENCE",
                        "status": "DIRECT_OBSERVATION",
                        "details": f"Value: {ev.observed_value}\nRef: {ev.source_reference}",
                    },
                    "position": {"x": x_start + (s_idx * 280) + (e_idx * 50 - 50), "y": y_ev + (e_idx * 90)}
                })
                edges.append({
                    "id": f"edge-sess-{ev_node_id}",
                    "source": s_node_id,
                    "target": ev_node_id,
                    "label": "observed_in",
                })

        # 4. Policy Findings Nodes
        if policy_report:
            y_finding = 540
            x_find_start = 80
            for r_idx, res in enumerate(policy_report.results):
                f_node_id = f"node-finding-{res.rule_id}"
                nodes.append({
                    "id": f_node_id,
                    "type": "output",
                    "data": {
                        "label": f"{res.rule_id}: {res.outcome.value}",
                        "category": "POLICY_VERDICT",
                        "status": res.outcome.value,
                        "severity": res.severity.value,
                        "details": f"{res.title}\n{res.technical_reasoning[:80]}...",
                    },
                    "position": {"x": x_find_start + (r_idx * 220), "y": y_finding}
                })

                # Connect evidence to finding if rule matches evidence
                connected = False
                for s in analysis.sessions:
                    for ev in s.evidence_items:
                        if any(term in ev.field_name for term in [res.category, "ENCR", "PRF", "INTEG", "D-H", "ESN", "Version"]):
                            edges.append({
                                "id": f"edge-ev-{ev.id}-to-{f_node_id}",
                                "source": f"node-ev-{ev.id}",
                                "target": f_node_id,
                                "label": "verifies",
                                "animated": res.outcome.value == "FAIL",
                            })
                            connected = True
                            break
                    if connected:
                        break

                if not connected:
                    edges.append({
                        "id": f"edge-root-to-{f_node_id}",
                        "source": root_id,
                        "target": f_node_id,
                        "label": "evaluated_against",
                    })

        return {"nodes": nodes, "edges": edges}


evidence_graph_engine = EvidenceGraphEngine()
