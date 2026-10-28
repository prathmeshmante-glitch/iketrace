import React, { useState } from 'react';
import { Search, ExternalLink, ShieldAlert, CheckCircle2, AlertTriangle, FileText, ArrowRight } from 'lucide-react';
import { PolicyEvaluationReport, RuleEvaluationResult, EvidenceItem } from '../types';
import { StatusBadge } from '../components/StatusBadge';

interface FindingInspectorPageProps {
  evaluationReport: PolicyEvaluationReport | null;
  evidenceItems: EvidenceItem[];
}

export const FindingInspectorPage: React.FC<FindingInspectorPageProps> = ({
  evaluationReport,
  evidenceItems,
}) => {
  const [filterOutcome, setFilterOutcome] = useState<string>('ALL');
  const [selectedResult, setSelectedResult] = useState<RuleEvaluationResult | null>(null);

  if (!evaluationReport) {
    return (
      <div className="card-brutal" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
        <h2>No Evaluation Report Available</h2>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
          Please run a policy evaluation from the Policy Engine or select a target capture.
        </p>
      </div>
    );
  }

  const filteredResults = evaluationReport.results.filter((r) => {
    if (filterOutcome === 'ALL') return true;
    return r.outcome === filterOutcome;
  });

  const activeResult = selectedResult || filteredResults[0] || null;

  // Find supporting evidence items for the active result
  const linkedEvidence = evidenceItems.filter((e) =>
    activeResult?.evidence_ids.includes(e.id)
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
            Finding &amp; Evidence Inspector
          </h2>
          <p style={{ color: 'var(--text-muted)' }}>
            Every security finding is deterministically linked to observable packet bytes and configuration evidence.
          </p>
        </div>

        {/* Filter Pills */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {['ALL', 'FAIL', 'PASS', 'UNKNOWN', 'NOT_APPLICABLE'].map((f) => (
            <button
              key={f}
              onClick={() => setFilterOutcome(f)}
              style={{
                fontFamily: 'var(--font-heading)',
                fontSize: '0.75rem',
                fontWeight: 700,
                padding: '0.4rem 0.75rem',
                border: '2px solid var(--border-dark)',
                backgroundColor: filterOutcome === f ? 'var(--text-main)' : 'var(--bg-surface)',
                color: filterOutcome === f ? '#FFFFFF' : 'var(--text-main)',
                boxShadow: filterOutcome === f ? 'var(--shadow-brutal-sm)' : 'none',
                cursor: 'pointer'
              }}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Findings Table & Supporting Evidence Card */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '1.5rem' }}>
        {/* Findings Table */}
        <div className="table-brutal-container">
          <div style={{ padding: '0.75rem 1rem', borderBottom: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontWeight: 700 }}>
              Evaluated Properties ({filteredResults.length})
            </span>
            <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              Policy: {evaluationReport.policy_id}
            </span>
          </div>
          <table className="table-brutal">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Rule ID</th>
                <th>Requirement</th>
                <th>Severity</th>
                <th>Sufficiency</th>
              </tr>
            </thead>
            <tbody>
              {filteredResults.map((res) => {
                const isSelected = activeResult?.rule_id === res.rule_id;
                return (
                  <tr
                    key={res.rule_id}
                    onClick={() => setSelectedResult(res)}
                    style={{
                      cursor: 'pointer',
                      backgroundColor: isSelected ? 'var(--accent-lime)' : undefined
                    }}
                  >
                    <td>
                      <StatusBadge outcome={res.outcome} size="sm" />
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{res.rule_id}</td>
                    <td style={{ fontWeight: 600 }}>{res.title}</td>
                    <td>
                      <StatusBadge severity={res.severity} size="sm" />
                    </td>
                    <td>
                      <span className={`badge-brutal ${res.evidence_sufficiency === 'SUFFICIENT' ? 'badge-pass' : 'badge-unknown'} text-xs`}>
                        {res.evidence_sufficiency}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Evidence & Technical Reasoning Inspector */}
        <div className="card-brutal" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {activeResult ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {activeResult.rule_id} • Category: {activeResult.category}
                  </div>
                  <h3 style={{ fontSize: '1.1rem', marginTop: '0.25rem' }}>{activeResult.title}</h3>
                </div>
                <StatusBadge outcome={activeResult.outcome} />
              </div>

              {/* Observed vs Expected Comparison Box */}
              <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Observed / Inferred Value:
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.85rem', margin: '0.25rem 0 0.5rem' }}>
                  {typeof activeResult.observed_value === 'object'
                    ? JSON.stringify(activeResult.observed_value)
                    : String(activeResult.observed_value)}
                </div>

                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Policy Requirement:
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-cobalt)' }}>
                  {activeResult.expected_property}
                </div>
              </div>

              {/* Technical Reasoning */}
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.25rem' }}>Technical Reasoning:</div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                  {activeResult.technical_reasoning}
                </p>
              </div>

              {/* Remediation */}
              <div style={{ borderLeft: '4px solid var(--accent-orange)', paddingLeft: '0.75rem' }}>
                <div style={{ fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.25rem' }}>Remediation Recommendation:</div>
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                  {activeResult.remediation_recommendation}
                </p>
              </div>

              {/* Linked Direct Evidence Items */}
              <div>
                <div style={{ fontWeight: 700, fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                  Linked Evidence Provenance ({linkedEvidence.length} items):
                </div>
                {linkedEvidence.length > 0 ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {linkedEvidence.map((ev) => (
                      <div
                        key={ev.id}
                        style={{
                          padding: '0.5rem 0.75rem',
                          border: '2px solid var(--border-dark)',
                          backgroundColor: 'var(--bg-surface)',
                          fontSize: '0.75rem'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 700 }}>
                          <span>{ev.field_name}</span>
                          <span className="badge-brutal badge-lime text-xs">{ev.provenance}</span>
                        </div>
                        <div style={{ fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                          Value: {String(ev.observed_value)}
                        </div>
                        <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginTop: '0.25rem' }}>
                          Reference: {ev.source_reference} ({ev.observation_method})
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    No specific packet proposal linked directly; decision evaluated from protocol header absence or baseline context.
                  </div>
                )}
              </div>
            </>
          ) : (
            <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)' }}>
              Select a finding to inspect exact supporting packet evidence and remediation steps.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
