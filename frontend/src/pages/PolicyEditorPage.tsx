import React, { useState } from 'react';
import { Play, AlertTriangle, ArrowRight } from 'lucide-react';
import { PolicyDefinition, PolicyEvaluationReport } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { TabKey } from '../components/Sidebar';

interface PolicyEditorPageProps {
  policies: PolicyDefinition[];
  activePolicyId: string;
  onSelectPolicy: (id: string) => void;
  onEvaluatePolicy: (policyId: string) => Promise<void> | void;
  evaluationReport: PolicyEvaluationReport | null;
  onNavigate: (tab: TabKey) => void;
  selectedCaptureId: string | null;
  selectedCaptureName?: string | null;
}

export const PolicyEditorPage: React.FC<PolicyEditorPageProps> = ({
  policies,
  activePolicyId,
  onSelectPolicy,
  onEvaluatePolicy,
  evaluationReport,
  onNavigate,
  selectedCaptureId,
  selectedCaptureName,
}) => {
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evalError, setEvalError] = useState<string | null>(null);

  const activePolicy = policies.find((p) => p.policy_id === activePolicyId) || policies[0];
  const activeRule = activePolicy?.rules.find((r) => r.rule_id === selectedRuleId) || activePolicy?.rules[0];

  // Find active rule evaluation result if report exists
  const activeRuleResult = evaluationReport?.results.find((r) => r.rule_id === activeRule?.rule_id);

  const handleRunEvaluation = async () => {
    if (!selectedCaptureId) {
      setEvalError('No active packet capture selected. Please upload or select a capture session from the Ingestion tab before evaluating.');
      return;
    }
    setEvalError(null);
    setIsEvaluating(true);
    try {
      await onEvaluatePolicy(activePolicy.policy_id);
    } catch (err: any) {
      setEvalError(err.message || 'Policy evaluation failed.');
    } finally {
      setIsEvaluating(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Header and Action Control */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
            Deterministic Policy Engine &amp; Rule Catalog
          </h2>
          <p style={{ color: 'var(--text-muted)' }}>
            Cryptographic policy requirements with deterministic PASS, FAIL, and UNKNOWN outcomes based strictly on verified packet evidence.
          </p>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', padding: '0.4rem 0.75rem', border: '2px solid var(--border-dark)', backgroundColor: selectedCaptureId ? 'var(--accent-lime)' : '#F3F4F6' }}>
              Target: <strong>{selectedCaptureName || selectedCaptureId || 'None (No active session)'}</strong>
            </div>

            <button
              onClick={handleRunEvaluation}
              disabled={isEvaluating}
              className="btn-brutal btn-primary"
            >
              <Play size={16} fill="white" />
              <span>{isEvaluating ? 'Evaluating Evidence...' : 'Evaluate Active Policy'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Target Not Selected Warning */}
      {evalError && (
        <div className="alert-brutal alert-danger">
          <AlertTriangle size={20} color="var(--accent-danger)" />
          <div>
            <div style={{ fontWeight: 700 }}>Evaluation Pre-requisite Missing</div>
            <div style={{ fontSize: '0.85rem' }}>{evalError}</div>
            <button
              onClick={() => onNavigate('upload')}
              className="btn-brutal btn-secondary btn-sm"
              style={{ marginTop: '0.5rem' }}
            >
              Go to Capture Ingestion &rarr;
            </button>
          </div>
        </div>
      )}

      {/* Live Policy Evaluation Result Card */}
      {evaluationReport && (
        <div
          className="card-brutal"
          style={{
            backgroundColor: '#F8FAFC',
            border: '3px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span className="badge-brutal badge-cobalt text-xs">EVALUATION COMPLETED</span>
                <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  Target: {evaluationReport.target_id} • Policy: {evaluationReport.policy_id} (v{evaluationReport.policy_version})
                </span>
              </div>
              <h3 style={{ fontSize: '1.25rem', marginTop: '0.25rem' }}>
                {evaluationReport.policy_name} Assessment Results
              </h3>
            </div>

            <button
              onClick={() => onNavigate('findings')}
              className="btn-brutal btn-secondary btn-sm"
            >
              <span>Inspect Findings &amp; Evidence</span>
              <ArrowRight size={14} />
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
            <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-surface)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>
                Compliance Score
              </div>
              <div style={{
                fontSize: '2rem',
                fontWeight: 900,
                color: evaluationReport.compliance_score_pct >= 80 ? '#16A34A' : (evaluationReport.compliance_score_pct >= 50 ? '#D97706' : '#DC2626')
              }}>
                {evaluationReport.compliance_score_pct}%
              </div>
            </div>

            <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: '#F0FDF4' }}>
              <div style={{ fontSize: '0.75rem', color: '#166534', fontWeight: 700, textTransform: 'uppercase' }}>
                Rules Passed
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#16A34A' }}>
                {evaluationReport.passed_count}
              </div>
            </div>

            <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: '#FEF2F2' }}>
              <div style={{ fontSize: '0.75rem', color: '#991B1B', fontWeight: 700, textTransform: 'uppercase' }}>
                Violations (Fail)
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#DC2626' }}>
                {evaluationReport.failed_count}
              </div>
            </div>

            <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: '#FFFBEB' }}>
              <div style={{ fontSize: '0.75rem', color: '#92400E', fontWeight: 700, textTransform: 'uppercase' }}>
                Insufficient (Unknown)
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#D97706' }}>
                {evaluationReport.unknown_count}
              </div>
            </div>

            <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: '#F3F4F6' }}>
              <div style={{ fontSize: '0.75rem', color: '#4B5563', fontWeight: 700, textTransform: 'uppercase' }}>
                Not Applicable
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 900, color: '#4B5563' }}>
                {evaluationReport.not_applicable_count}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Policy Selector Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
        {policies.map((pol) => {
          const isSelected = activePolicy?.policy_id === pol.policy_id;
          return (
            <div
              key={pol.policy_id}
              onClick={() => {
                onSelectPolicy(pol.policy_id);
                setSelectedRuleId(null);
              }}
              style={{
                border: isSelected ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                backgroundColor: isSelected ? '#F4F7FF' : 'var(--bg-surface)',
                boxShadow: isSelected ? 'var(--shadow-brutal)' : '2px 2px 0px var(--border-dark)',
                padding: '1.25rem',
                cursor: 'pointer',
                transition: 'all 0.1s ease'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span className="badge-brutal badge-cobalt text-xs">
                  v{pol.version}
                </span>
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {pol.rules.length} Rules
                </span>
              </div>
              <h3 style={{ fontSize: '1.05rem', marginBottom: '0.25rem' }}>{pol.name}</h3>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                {pol.description}
              </p>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                Authority: {pol.author}
              </div>
            </div>
          );
        })}
      </div>

      {/* Rules Table & Rule Deep Dive Split */}
      {activePolicy && (
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '1.5rem' }}>
          {/* Rules Table */}
          <div className="table-brutal-container">
            <div style={{ padding: '0.75rem 1rem', borderBottom: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)', fontWeight: 700, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>{activePolicy.name} Rules ({activePolicy.rules.length})</span>
              {evaluationReport && (
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  Showing Live Evaluation Verdicts
                </span>
              )}
            </div>
            <table className="table-brutal">
              <thead>
                <tr>
                  {evaluationReport && <th>Verdict</th>}
                  <th>Rule ID</th>
                  <th>Category</th>
                  <th>Requirement Title</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {activePolicy.rules.map((rule) => {
                  const isSelected = activeRule?.rule_id === rule.rule_id;
                  const ruleEval = evaluationReport?.results.find((r) => r.rule_id === rule.rule_id);
                  return (
                    <tr
                      key={rule.rule_id}
                      onClick={() => setSelectedRuleId(rule.rule_id)}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: isSelected ? 'var(--accent-lime)' : undefined
                      }}
                    >
                      {evaluationReport && (
                        <td>
                          {ruleEval ? (
                            <StatusBadge outcome={ruleEval.outcome} size="sm" />
                          ) : (
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>-</span>
                          )}
                        </td>
                      )}
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{rule.rule_id}</td>
                      <td>
                        <span className="badge-brutal badge-na text-xs">{rule.category}</span>
                      </td>
                      <td style={{ fontWeight: 600 }}>{rule.title}</td>
                      <td>
                        <StatusBadge severity={rule.severity} size="sm" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Rule Detail Card */}
          <div className="card-brutal" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {activeRule ? (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
                  <div>
                    <span className="badge-brutal badge-cobalt text-xs">{activeRule.category}</span>
                    <h3 style={{ fontSize: '1.1rem', marginTop: '0.25rem' }}>{activeRule.title}</h3>
                  </div>
                  <StatusBadge severity={activeRule.severity} size="sm" />
                </div>

                {/* Session Evaluation Verdict Box */}
                {activeRuleResult && (
                  <div style={{
                    padding: '0.75rem',
                    border: '2px solid var(--border-dark)',
                    backgroundColor: activeRuleResult.outcome === 'PASS' ? '#F0FDF4' : (activeRuleResult.outcome === 'FAIL' ? '#FEF2F2' : '#FFFBEB'),
                    boxShadow: '2px 2px 0px var(--border-dark)'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.75rem', textTransform: 'uppercase' }}>
                        Session Verdict
                      </span>
                      <StatusBadge outcome={activeRuleResult.outcome} size="sm" />
                    </div>
                    <div style={{ fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                      <strong>Reasoning:</strong> {activeRuleResult.technical_reasoning}
                    </div>
                    {activeRuleResult.observed_value && (
                      <div style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                        Observed: <strong>{String(activeRuleResult.observed_value)}</strong>
                      </div>
                    )}
                    {activeRuleResult.evidence_ids.length > 0 && (
                      <div style={{ fontSize: '0.72rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                        Evidence ID: {activeRuleResult.evidence_ids.join(', ')}
                      </div>
                    )}
                  </div>
                )}

                <div style={{ fontSize: '0.85rem' }}>
                  <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>Requirement Description:</div>
                  <p style={{ color: 'var(--text-muted)', lineHeight: '1.4' }}>{activeRule.description}</p>
                </div>

                <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-subtle)', border: '2px solid var(--border-dark)', fontSize: '0.8rem' }}>
                  <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>Allowed Values:</div>
                  <div style={{ fontFamily: 'var(--font-mono)', color: '#16A34A', wordBreak: 'break-all' }}>
                    {activeRule.allowed_values.join(', ') || 'N/A'}
                  </div>

                  {activeRule.prohibited_values.length > 0 && (
                    <>
                      <div style={{ fontWeight: 700, marginTop: '0.5rem', marginBottom: '0.25rem' }}>Prohibited Values:</div>
                      <div style={{ fontFamily: 'var(--font-mono)', color: '#DC2626', wordBreak: 'break-all' }}>
                        {activeRule.prohibited_values.join(', ')}
                      </div>
                    </>
                  )}
                </div>

                <div style={{ fontSize: '0.85rem' }}>
                  <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>Cryptographic Rationale:</div>
                  <p style={{ color: 'var(--text-muted)', lineHeight: '1.4' }}>{activeRule.rationale}</p>
                </div>

                <div style={{ borderLeft: '4px solid var(--accent-orange)', paddingLeft: '0.75rem', fontSize: '0.85rem' }}>
                  <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>Remediation Recommendation:</div>
                  <p style={{ color: 'var(--text-muted)', lineHeight: '1.4' }}>{activeRule.remediation}</p>
                </div>
              </>
            ) : (
              <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)' }}>
                Select a rule to view technical rationale and configuration guidance.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
