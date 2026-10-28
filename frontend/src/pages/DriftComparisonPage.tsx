import React, { useState } from 'react';
import { GitCompare, PlusCircle, AlertTriangle, CheckCircle2, HelpCircle, ArrowRight } from 'lucide-react';
import { BaselineSnapshot, DriftReport, CaptureAnalysisResult, PolicyEvaluationReport } from '../types';
import { api } from '../services/api';
import { StatusBadge } from '../components/StatusBadge';

interface DriftComparisonPageProps {
  baselines: BaselineSnapshot[];
  currentCapture: CaptureAnalysisResult | null;
  policyReport: PolicyEvaluationReport | null;
  onBaselineCreated: (b: BaselineSnapshot) => void;
}

export const DriftComparisonPage: React.FC<DriftComparisonPageProps> = ({
  baselines,
  currentCapture,
  policyReport,
  onBaselineCreated,
}) => {
  const [selectedBaselineId, setSelectedBaselineId] = useState<string>(baselines[0]?.snapshot_id || '');
  const [newBaselineName, setNewBaselineName] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [isComparing, setIsComparing] = useState(false);
  const [driftReport, setDriftReport] = useState<DriftReport | null>(null);

  const handleCreateBaseline = async () => {
    if (!currentCapture || !newBaselineName) return;
    setIsCreating(true);
    try {
      const b = await api.createBaseline(newBaselineName, currentCapture.capture_id);
      onBaselineCreated(b);
      setSelectedBaselineId(b.snapshot_id);
      setNewBaselineName('');
    } catch (e) {
      console.error(e);
    } finally {
      setIsCreating(false);
    }
  };

  const handleCompare = async () => {
    if (!selectedBaselineId || !currentCapture) return;
    setIsComparing(true);
    try {
      const rep = await api.compareDrift(selectedBaselineId, currentCapture.capture_id);
      setDriftReport(rep);
    } catch (e) {
      console.error(e);
    } finally {
      setIsComparing(false);
    }
  };

  const activeBaseline = baselines.find((b) => b.snapshot_id === selectedBaselineId) || baselines[0];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
            Configuration Drift &amp; Security Regression
          </h2>
          <p style={{ color: 'var(--text-muted)' }}>
            Compare active VPN traffic against verified assessment baselines. Detect newly introduced violations, resolved issues, and configuration changes.
          </p>
        </div>

        <button
          onClick={handleCompare}
          disabled={isComparing || !selectedBaselineId || !currentCapture}
          className="btn-brutal btn-primary"
        >
          <GitCompare size={16} />
          <span>{isComparing ? 'Comparing...' : 'Run Drift Comparison'}</span>
        </button>
      </div>

      {/* Baseline Manager Card */}
      <div className="card-brutal" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', alignItems: 'center' }}>
        {/* Baseline Selector */}
        <div>
          <label style={{ fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.5rem', display: 'block' }}>
            Select Verified Assessment Baseline:
          </label>
          <select
            value={selectedBaselineId}
            onChange={(e) => setSelectedBaselineId(e.target.value)}
            className="input-brutal"
          >
            {baselines.map((b) => (
              <option key={b.snapshot_id} value={b.snapshot_id}>
                {b.name} ({b.policy_id} • {b.compliance_score_pct}% score)
              </option>
            ))}
          </select>

          {activeBaseline && (
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontFamily: 'var(--font-mono)' }}>
              Baseline ID: {activeBaseline.snapshot_id} | Created: {new Date(activeBaseline.created_at).toLocaleDateString()}
            </div>
          )}
        </div>

        {/* Snapshot Current State Button */}
        <div style={{ borderLeft: '2px solid var(--border-dark)', paddingLeft: '1.5rem' }}>
          <label style={{ fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.5rem', display: 'block' }}>
            Establish New Baseline from Current Evaluation:
          </label>
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <input
              type="text"
              placeholder="e.g. Q4 2026 Production Baseline"
              value={newBaselineName}
              onChange={(e) => setNewBaselineName(e.target.value)}
              className="input-brutal"
              style={{ flex: 1 }}
            />
            <button
              onClick={handleCreateBaseline}
              disabled={isCreating || !newBaselineName || !currentCapture}
              className="btn-brutal btn-secondary btn-sm"
              style={{ flexShrink: 0 }}
            >
              <PlusCircle size={14} />
              <span>{isCreating ? 'Saving...' : 'Save Baseline'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Drift Comparison Report */}
      {driftReport ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Verdict Banner */}
          <div className={`alert-brutal ${driftReport.regression_detected ? 'alert-danger' : 'alert-success'}`}>
            {driftReport.regression_detected ? (
              <AlertTriangle size={24} color="var(--accent-danger)" />
            ) : (
              <CheckCircle2 size={24} color="#16A34A" />
            )}
            <div>
              <div style={{ fontSize: '1.1rem', fontWeight: 900 }}>
                {driftReport.summary_verdict}
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                Compared {driftReport.total_rules_compared} rules between Baseline '{driftReport.baseline_name}' and Target '{driftReport.current_target_id}'.
              </div>
            </div>
          </div>

          {/* Differences Table */}
          <div className="table-brutal-container">
            <div style={{ padding: '0.75rem 1rem', borderBottom: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)', fontWeight: 700 }}>
              Detected Drift Outcomes ({driftReport.differences.length} changes)
            </div>
            <table className="table-brutal">
              <thead>
                <tr>
                  <th>Diff Type</th>
                  <th>Rule ID</th>
                  <th>Category</th>
                  <th>Baseline</th>
                  <th>Current</th>
                  <th>Explanation &amp; Recommended Action</th>
                </tr>
              </thead>
              <tbody>
                {driftReport.differences.length === 0 ? (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                      Identical cryptographic outcomes. No configuration drift detected.
                    </td>
                  </tr>
                ) : (
                  driftReport.differences.map((diff, idx) => (
                    <tr
                      key={idx}
                      style={{
                        backgroundColor: diff.is_regression ? '#FFEBEA' : (diff.difference_type === 'RESOLVED_VIOLATION' ? '#F4FEE4' : undefined)
                      }}
                    >
                      <td>
                        <span className={`badge-brutal ${diff.is_regression ? 'badge-fail' : (diff.difference_type === 'RESOLVED_VIOLATION' ? 'badge-pass' : 'badge-na')} text-xs`}>
                          {diff.difference_type}
                        </span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{diff.rule_id}</td>
                      <td>{diff.category}</td>
                      <td>
                        <StatusBadge outcome={diff.baseline_outcome} size="sm" />
                      </td>
                      <td>
                        <StatusBadge outcome={diff.current_outcome} size="sm" />
                      </td>
                      <td style={{ fontSize: '0.8rem' }}>
                        <div style={{ fontWeight: 600 }}>{diff.technical_explanation}</div>
                        {diff.recommended_regression_tests.length > 0 && (
                          <div style={{ color: 'var(--accent-cobalt)', marginTop: '0.25rem', fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                            Next: {diff.recommended_regression_tests[0]}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="card-brutal" style={{ textAlign: 'center', padding: '3rem 1rem', color: 'var(--text-muted)' }}>
          Select a baseline and click "Run Drift Comparison" to analyze newly introduced regressions and resolved violations.
        </div>
      )}
    </div>
  );
};
