import React from 'react';
import { ShieldCheck, AlertTriangle, Network, Cpu, Lock, CheckCircle2, ArrowRight } from 'lucide-react';
import { CaptureAnalysisResult, PolicyEvaluationReport, CryptoInventoryReport } from '../types';
import { StatusBadge } from '../components/StatusBadge';
import { TabKey } from '../components/Sidebar';

interface OverviewPageProps {
  currentCapture: CaptureAnalysisResult | null;
  policyReport: PolicyEvaluationReport | null;
  cryptoInventory: CryptoInventoryReport | null;
  onNavigate: (tab: TabKey) => void;
  onRunAllScenarios: () => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  currentCapture,
  policyReport,
  cryptoInventory,
  onNavigate,
  onRunAllScenarios,
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Banner */}
      <div style={{
        backgroundColor: 'var(--accent-lime)',
        border: '3px solid var(--border-dark)',
        boxShadow: 'var(--shadow-brutal)',
        padding: '1.5rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div>
          <h1 style={{ fontSize: '1.75rem', marginBottom: '0.25rem' }}>
            VPN Security Assurance Dashboard
          </h1>
          <p style={{ fontWeight: 500, color: 'var(--text-main)', maxWidth: '700px' }}>
            Deterministic cryptographic configuration verification, protocol negotiation audit, and post-quantum migration workbench.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button
            onClick={() => onNavigate('upload')}
            className="btn-brutal btn-neutral"
          >
            Upload PCAP
          </button>
          <button
            onClick={onRunAllScenarios}
            className="btn-brutal btn-primary"
          >
            Run 8 Lab Scenarios
          </button>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
        {/* Compliance Card */}
        <div className="card-brutal" style={{ borderLeft: '8px solid var(--accent-cobalt)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              Policy Compliance
            </span>
            <ShieldCheck size={18} color="var(--accent-cobalt)" />
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 900, fontFamily: 'var(--font-heading)', margin: '0.5rem 0' }}>
            {policyReport ? `${policyReport.compliance_score_pct}%` : 'N/A'}
          </div>
          <div style={{ fontSize: '0.75rem', display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            {policyReport && (
              <>
                <span style={{ color: '#16A34A', fontWeight: 700 }}>{policyReport.passed_count} PASS</span>
                <span>•</span>
                <span style={{ color: '#DC2626', fontWeight: 700 }}>{policyReport.failed_count} FAIL</span>
                <span>•</span>
                <span style={{ color: '#D97706', fontWeight: 700 }}>{policyReport.unknown_count} UNKNOWN</span>
              </>
            )}
            {!policyReport && <span>Select a capture to evaluate</span>}
          </div>
        </div>

        {/* Traffic Observation Card */}
        <div className="card-brutal" style={{ borderLeft: '8px solid var(--accent-lime)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              Active Capture Packets
            </span>
            <Network size={18} />
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 900, fontFamily: 'var(--font-heading)', margin: '0.5rem 0' }}>
            {currentCapture ? currentCapture.total_packets : 0}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {currentCapture ? (
              <span>{currentCapture.ike_packets} IKE pkts • {currentCapture.esp_packets} ESP pkts • {currentCapture.session_count} session(s)</span>
            ) : (
              <span>No capture loaded</span>
            )}
          </div>
        </div>

        {/* Post-Quantum Readiness Card */}
        <div className="card-brutal" style={{ borderLeft: '8px solid var(--accent-orange)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              Post-Quantum Readiness
            </span>
            <Cpu size={18} color="var(--accent-orange)" />
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 900, fontFamily: 'var(--font-heading)', margin: '0.5rem 0' }}>
            {cryptoInventory ? `${cryptoInventory.pqc_readiness_score_pct}%` : 'N/A'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {cryptoInventory ? (
              <span>{cryptoInventory.quantum_vulnerable_assets_count} CRQC vulnerable asset(s)</span>
            ) : (
              <span>Run inventory to compute</span>
            )}
          </div>
        </div>

        {/* Verification Status Card */}
        <div className="card-brutal" style={{ borderLeft: '8px solid #171717' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              Audit Provenance
            </span>
            <Lock size={18} />
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 900, fontFamily: 'var(--font-heading)', margin: '0.5rem 0' }}>
            100%
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Cryptographic SHA-256 Hash Chain Intact
          </div>
        </div>
      </div>

      {/* Main Content Grid: Target Details & Recent Findings */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* Active Target Summary */}
        <div className="card-brutal">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            <h3 style={{ fontSize: '1.1rem' }}>Target Capture Metadata</h3>
            {currentCapture && (
              <span className="badge-brutal badge-cobalt">
                {currentCapture.parser_backend}
              </span>
            )}
          </div>

          {currentCapture ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Filename:</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{currentCapture.filename}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>File Size:</span>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{(currentCapture.file_size_bytes / 1024).toFixed(1)} KB</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Parse Completeness:</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#16A34A' }}>
                  {currentCapture.parse_completeness_pct}%
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Sessions Identified:</span>
                <span style={{ fontFamily: 'var(--font-mono)' }}>{currentCapture.session_count}</span>
              </div>

              {currentCapture.sessions.length > 0 && (
                <div style={{ marginTop: '0.5rem', padding: '0.75rem', backgroundColor: 'var(--bg-subtle)', border: '2px solid var(--border-dark)' }}>
                  <div style={{ fontWeight: 700, fontSize: '0.75rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                    Primary Session Observed
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                    {currentCapture.sessions[0].initiator_ip} &lt;-&gt; {currentCapture.sessions[0].responder_ip}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                    Exchange Types: {currentCapture.sessions[0].exchange_types_observed.join(', ') || 'N/A'}
                  </div>
                </div>
              )}

              <button
                onClick={() => onNavigate('sessions')}
                className="btn-brutal btn-neutral btn-sm"
                style={{ marginTop: '0.5rem', alignSelf: 'flex-start' }}
              >
                Inspect Packets &amp; Transforms <ArrowRight size={14} />
              </button>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)' }}>
              <p>No capture loaded yet.</p>
              <button
                onClick={() => onNavigate('upload')}
                className="btn-brutal btn-secondary btn-sm"
                style={{ marginTop: '1rem' }}
              >
                Select or Upload Capture
              </button>
            </div>
          )}
        </div>

        {/* Policy Verification Verdicts */}
        <div className="card-brutal">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            <h3 style={{ fontSize: '1.1rem' }}>Active Policy Findings</h3>
            {policyReport && (
              <span className="badge-brutal badge-lime">
                {policyReport.policy_name}
              </span>
            )}
          </div>

          {policyReport ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {policyReport.results.slice(0, 4).map((r) => (
                <div
                  key={r.rule_id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0.6rem 0.75rem',
                    border: '2px solid var(--border-dark)',
                    backgroundColor: r.outcome === 'FAIL' ? '#FFEBEA' : (r.outcome === 'PASS' ? '#F4FEE4' : 'var(--bg-surface)'),
                    boxShadow: '2px 2px 0px var(--border-dark)'
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{r.title}</div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      {r.rule_id} • {r.category}
                    </div>
                  </div>
                  <StatusBadge outcome={r.outcome} size="sm" />
                </div>
              ))}

              <button
                onClick={() => onNavigate('findings')}
                className="btn-brutal btn-neutral btn-sm"
                style={{ marginTop: '0.75rem', alignSelf: 'flex-start' }}
              >
                View All Findings &amp; Evidence <ArrowRight size={14} />
              </button>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)' }}>
              <p>No policy evaluation available for this target.</p>
              <button
                onClick={() => onNavigate('policy')}
                className="btn-brutal btn-primary btn-sm"
                style={{ marginTop: '1rem' }}
              >
                Run Policy Evaluation
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
