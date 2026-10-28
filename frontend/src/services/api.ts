import {
  CaptureAnalysisResult,
  PolicyDefinition,
  PolicyEvaluationReport,
  ScenarioDefinition,
  ScenarioResult,
  BaselineSnapshot,
  DriftReport,
  ModelEvaluationReport,
  PrivacyExposureSummary,
  CryptoInventoryReport,
  AssessmentReport,
  AuditRecord,
  AuditVerificationResult
} from '../types';

const API_BASE = 'http://localhost:8000/api';

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(url, options);
  if (!res.ok) {
    let errDetail = `HTTP ${res.status} ${res.statusText}`;
    try {
      const errJson = await res.json();
      if (errJson && errJson.detail) {
        errDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail);
      }
    } catch {
      // ignore
    }
    throw new Error(errDetail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  // Health
  getHealth: () => fetchJson<{ status: string; app_name: string; version: string; offline_mode: boolean; tshark_available: boolean; tshark_executable: string }>(`${API_BASE}/health`),

  // Captures & Analyses (Session-Aware)
  uploadCapture: async (file: File): Promise<CaptureAnalysisResult> => {
    const formData = new FormData();
    formData.append('file', file);
    return fetchJson<CaptureAnalysisResult>(`${API_BASE}/captures/upload`, {
      method: 'POST',
      body: formData,
    });
  },
  listCaptures: () => fetchJson<CaptureAnalysisResult[]>(`${API_BASE}/analyses`),
  getCapture: (id: string) => fetchJson<CaptureAnalysisResult>(`${API_BASE}/analyses/${id}`),
  listAnalyses: () => fetchJson<CaptureAnalysisResult[]>(`${API_BASE}/analyses`),
  getAnalysis: (id: string) => fetchJson<CaptureAnalysisResult>(`${API_BASE}/analyses/${id}`),
  deleteAnalysis: (id: string) => fetchJson<{ status: string; analysis_id: string }>(`${API_BASE}/analyses/${id}`, { method: 'DELETE' }),
  getAnalysisProtocols: (id: string) => fetchJson<any>(`${API_BASE}/analyses/${id}/protocols`),
  getAnalysisSessions: (id: string) => fetchJson<any>(`${API_BASE}/analyses/${id}/sessions`),
  evaluateAnalysisPolicy: (id: string, policy_id: string = 'POL-DEF-NIST-SP800-77') =>
    fetchJson<PolicyEvaluationReport>(`${API_BASE}/analyses/${id}/evaluations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy_id }),
    }),
  listAnalysisEvaluations: (id: string) => fetchJson<PolicyEvaluationReport[]>(`${API_BASE}/analyses/${id}/evaluations`),
  getAnalysisFindings: (id: string, policy_id?: string) =>
    fetchJson<any>(`${API_BASE}/analyses/${id}/findings${policy_id ? `?policy_id=${encodeURIComponent(policy_id)}` : ''}`),
  getAnalysisCryptoInventory: (id: string) => fetchJson<CryptoInventoryReport>(`${API_BASE}/analyses/${id}/crypto-inventory`),
  listAnalysisReports: (id: string) => fetchJson<AssessmentReport[]>(`${API_BASE}/analyses/${id}/reports`),
  getAnalysisTrafficFlows: (id: string) => fetchJson<any>(`${API_BASE}/analyses/${id}/traffic-flows`),

  // Policies
  listPolicies: () => fetchJson<PolicyDefinition[]>(`${API_BASE}/policies`),
  getPolicy: (id: string) => fetchJson<PolicyDefinition>(`${API_BASE}/policies/${id}`),
  evaluatePolicy: (capture_id: string, policy_id: string = 'POL-DEF-NIST-SP800-77') =>
    fetchJson<PolicyEvaluationReport>(`${API_BASE}/policies/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ capture_id, policy_id }),
    }),

  // Scenarios
  listScenarios: () => fetchJson<ScenarioDefinition[]>(`${API_BASE}/scenarios`),
  runScenario: (scenario_id: string, policy_id: string = 'POL-DEF-NIST-SP800-77') =>
    fetchJson<ScenarioResult>(`${API_BASE}/scenarios/${scenario_id}/run`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy_id }),
    }),
  runAllScenarios: (policy_id: string = 'POL-DEF-NIST-SP800-77') =>
    fetchJson<ScenarioResult[]>(`${API_BASE}/scenarios/run-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ policy_id }),
    }),

  // Drift & Baselines
  listBaselines: () => fetchJson<BaselineSnapshot[]>(`${API_BASE}/drift/baselines`),
  createBaseline: (name: string, capture_id: string, policy_id: string = 'POL-DEF-NIST-SP800-77') =>
    fetchJson<BaselineSnapshot>(`${API_BASE}/drift/baselines`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, capture_id, policy_id }),
    }),
  compareDrift: (baseline_id: string, current_capture_id: string, policy_id?: string) =>
    fetchJson<DriftReport>(`${API_BASE}/drift/compare`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ baseline_id, current_capture_id, policy_id }),
    }),

  // Traffic Privacy Lab
  getMLModel: () => fetchJson<ModelEvaluationReport>(`${API_BASE}/traffic-privacy/model`),
  retrainMLModel: (num_sessions_per_class: number = 15) =>
    fetchJson<ModelEvaluationReport>(`${API_BASE}/traffic-privacy/retrain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ num_sessions_per_class }),
    }),
  getPrivacyExposure: () => fetchJson<PrivacyExposureSummary>(`${API_BASE}/traffic-privacy/exposure`),

  // Crypto Inventory
  getCryptoInventory: (target_id: string) => fetchJson<CryptoInventoryReport>(`${API_BASE}/crypto-inventory/${target_id}`),

  // Evidence Graph
  getEvidenceGraph: (target_id: string, policy_id?: string) =>
    fetchJson<{ nodes: any[]; edges: any[] }>(
      `${API_BASE}/evidence-graph/${target_id}${policy_id ? `?policy_id=${encodeURIComponent(policy_id)}` : ''}`
    ),

  // Reports
  generateReport: (title: string, target_id: string, target_type: string = 'CAPTURE', policy_id: string = 'POL-DEF-NIST-SP800-77', baseline_id?: string) =>
    fetchJson<AssessmentReport>(`${API_BASE}/reports/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, target_id, target_type, policy_id, baseline_id }),
    }),
  listReports: () => fetchJson<AssessmentReport[]>(`${API_BASE}/reports`),
  getReport: (id: string) => fetchJson<AssessmentReport>(`${API_BASE}/reports/${id}`),

  // Audit
  getAuditRecords: () => fetchJson<AuditRecord[]>(`${API_BASE}/audit/records`),
  verifyAuditChain: () => fetchJson<AuditVerificationResult>(`${API_BASE}/audit/verify`),
};
