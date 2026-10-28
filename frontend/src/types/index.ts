export type ObservationProvenance = 
  | 'DIRECTLY_OBSERVED' 
  | 'DETERMINISTICALLY_DERIVED' 
  | 'SUPPLIED_CONFIGURATION' 
  | 'EXPERIMENTALLY_VERIFIED' 
  | 'UNKNOWN_OR_UNSUPPORTED';

export type EvaluationOutcome = 'PASS' | 'FAIL' | 'UNKNOWN' | 'NOT_APPLICABLE';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type EvidenceSufficiency = 'SUFFICIENT' | 'INSUFFICIENT' | 'ABSENT';

export interface EvidenceItem {
  id: string;
  field_name: string;
  observed_value: any;
  source_reference: string;
  observation_method: string;
  provenance: ObservationProvenance;
  sufficiency: EvidenceSufficiency;
  timestamp?: number;
  limitations?: string;
  metadata?: Record<string, any>;
}

export interface IKETransform {
  transform_type: string;
  transform_id: number;
  transform_name: string;
  key_length?: number;
  attributes: Record<string, any>;
}

export interface IKEProposal {
  proposal_num: number;
  protocol_id: string;
  spi?: string;
  transforms: IKETransform[];
}

export interface PacketSummary {
  index: number;
  timestamp: number;
  length: number;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  summary: string;
  is_ike: boolean;
  is_esp: boolean;
  ike_version?: string;
  exchange_type?: string;
  message_id?: number;
  is_initiator?: boolean;
  initiator_spi?: string;
  responder_spi?: string;
  payload_types: string[];
  proposals: IKEProposal[];
  esp_spi?: string;
  esp_seq?: number;
  parser_warnings: string[];
}

export interface SessionSummary {
  session_id: string;
  initiator_ip: string;
  responder_ip: string;
  initiator_port: number;
  responder_port: number;
  initiator_spi?: string;
  responder_spi?: string;
  ike_version?: string;
  exchange_types_observed: string[];
  packet_count: number;
  start_time: number;
  end_time: number;
  duration_seconds: number;
  packets: number[];
  proposals_offered: IKEProposal[];
  proposals_chosen: IKEProposal[];
  esp_packet_count: number;
  esp_spis: string[];
  evidence_items: EvidenceItem[];
  completeness_score: number;
  limitations: string[];
}

export interface CaptureAnalysisResult {
  capture_id: string;
  filename: string;
  file_hash_sha256?: string;
  file_size_bytes: number;
  uploaded_at: string;
  status?: string;
  error_message?: string;
  total_packets: number;
  ike_packets: number;
  esp_packets: number;
  other_packets: number;
  session_count: number;
  parse_completeness_pct: number;
  parser_backend: string;
  parser_warnings: string[];
  sessions: SessionSummary[];
  packets: PacketSummary[];
  evidence_items: EvidenceItem[];
}

export interface PolicyRule {
  rule_id: string;
  category: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  allowed_values: string[];
  prohibited_values: string[];
  min_key_length?: number;
  min_dh_group?: number;
  require_esn?: boolean;
  rationale: string;
  remediation: string;
  limitations?: string;
}

export interface PolicyDefinition {
  policy_id: string;
  name: string;
  version: string;
  author: string;
  description: string;
  rules: PolicyRule[];
}

export interface RuleEvaluationResult {
  rule_id: string;
  policy_version: string;
  category: string;
  title: string;
  outcome: EvaluationOutcome;
  severity: SeverityLevel;
  expected_property: string;
  observed_value: any;
  evidence_ids: string[];
  evidence_sufficiency: EvidenceSufficiency;
  technical_reasoning: string;
  remediation_recommendation: string;
  limitations?: string;
}

export interface PolicyEvaluationReport {
  policy_id: string;
  policy_name: string;
  policy_version: string;
  evaluated_at: string;
  target_id: string;
  total_rules: number;
  passed_count: number;
  failed_count: number;
  unknown_count: number;
  not_applicable_count: number;
  compliance_score_pct: number;
  results: RuleEvaluationResult[];
}

export interface ScenarioAssertionResult {
  assertion_id: string;
  passed: boolean;
  expected: string;
  observed: string;
  details: string;
}

export interface ScenarioDefinition {
  scenario_id: string;
  name: string;
  category: string;
  description: string;
  initial_conditions: Record<string, any>;
  synthetic_input_data: Record<string, any>;
  expected_assertions: Array<{
    assertion_id: string;
    target_property: string;
    expected_outcome: string;
    description: string;
  }>;
  reproducibility_notes: string;
}

export interface ScenarioResult {
  scenario_id: string;
  scenario_name: string;
  category: string;
  executed_at: string;
  is_synthetic: boolean;
  status: 'PASSED' | 'FAILED';
  all_assertions_met: boolean;
  assertion_results: ScenarioAssertionResult[];
  generated_evidence: EvidenceItem[];
  policy_report?: PolicyEvaluationReport;
  execution_log: string[];
}

export interface BaselineSnapshot {
  snapshot_id: string;
  name: string;
  created_at: string;
  target_id: string;
  policy_id: string;
  policy_version: string;
  compliance_score_pct: number;
  finding_outcomes: Record<string, string>;
  observed_parameters: Record<string, any>;
  metadata: Record<string, any>;
}

export interface DriftDifference {
  rule_id: string;
  category: string;
  title: string;
  severity: SeverityLevel;
  baseline_outcome?: string;
  current_outcome?: string;
  difference_type: string;
  is_regression: boolean;
  technical_explanation: string;
  evidence_reference: string;
  recommended_regression_tests: string[];
}

export interface DriftReport {
  drift_report_id: string;
  baseline_id: string;
  baseline_name: string;
  current_target_id: string;
  generated_at: string;
  total_rules_compared: number;
  new_violations_count: number;
  resolved_violations_count: number;
  newly_unknown_count: number;
  regression_detected: boolean;
  differences: DriftDifference[];
  summary_verdict: string;
}

export interface ModelEvaluationReport {
  model_name: string;
  model_family: string;
  trained_at: string;
  train_samples_count: number;
  test_samples_count: number;
  cross_validation_strategy: string;
  accuracy: number;
  precision_macro: number;
  recall_macro: number;
  f1_macro: number;
  per_class_f1: Record<string, number>;
  feature_importances: Record<string, number>;
  confusion_matrix: {
    class_labels: string[];
    matrix: number[][];
  };
  prediction_vs_truth_sample: Array<{
    flow_id: string;
    session_id: string;
    mean_packet_size: number;
    mean_iat_ms: number;
    ground_truth: string;
    predicted_label: string;
    correct: boolean;
  }>;
  generalization_limitations: string;
}

export interface PrivacyExposureSummary {
  target_id: string;
  analyzed_flows_count: number;
  identifiable_classes_count: number;
  highest_vulnerability_leakage_feature: string;
  mitigation_recommendation: string;
  padding_recommendation: string;
}

export interface CryptoAsset {
  asset_id: string;
  category: string;
  algorithm_name: string;
  key_length?: number;
  compliance_status: string;
  pqc_readiness: string;
  provenance: ObservationProvenance;
  source_reference: string;
  negotiated_or_configured: string;
  migration_priority: SeverityLevel;
  recommended_target: string;
  transition_guidance: string;
}

export interface CryptoInventoryReport {
  inventory_id: string;
  target_id: string;
  target_type: string;
  generated_at: string;
  total_assets_inventoried: number;
  compliant_assets_count: number;
  deprecated_assets_count: number;
  prohibited_assets_count: number;
  quantum_vulnerable_assets_count: number;
  pqc_readiness_score_pct: number;
  assets: CryptoAsset[];
  migration_actions: Array<{ action: string; detail: string }>;
  caveats_and_unknowns: string[];
}

export interface AuditRecord {
  record_id: string;
  sequence_number: number;
  timestamp: string;
  event_type: string;
  actor: string;
  entity_id: string;
  entity_type: string;
  canonical_data_json: string;
  record_hash: string;
  previous_hash: string;
}

export interface AuditVerificationResult {
  verified_at: string;
  total_records: number;
  chain_intact: boolean;
  tampered_indices: number[];
  tampered_record_ids: string[];
  verification_message: string;
  cryptographic_guarantees: string;
}

export interface AssessmentReport {
  report_id: string;
  title: string;
  generated_at: string;
  assessor: string;
  target_id: string;
  target_type: string;
  executive_summary: string;
  overall_verdict: string;
  policy_report?: PolicyEvaluationReport;
  drift_report?: DriftReport;
  crypto_inventory?: CryptoInventoryReport;
  audit_chain_verified: boolean;
  audit_hash: string;
  reproducibility_fingerprint: string;
  methodology_limitations: string[];
  markdown_content?: string;
}
