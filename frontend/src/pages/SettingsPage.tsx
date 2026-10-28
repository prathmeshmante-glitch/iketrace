import React, { useState, useEffect } from 'react';
import { Sliders, ShieldCheck, CheckCircle2, AlertTriangle, Hash, RefreshCw, Info } from 'lucide-react';
import { AuditRecord, AuditVerificationResult } from '../types';
import { api } from '../services/api';

export const SettingsPage: React.FC = () => {
  const [healthData, setHealthData] = useState<any>(null);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  const [verificationResult, setVerificationResult] = useState<AuditVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);

  const loadData = async () => {
    try {
      const h = await api.getHealth();
      setHealthData(h);
      const recs = await api.getAuditRecords();
      setAuditRecords(recs);
      const v = await api.verifyAuditChain();
      setVerificationResult(v);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleVerify = async () => {
    setIsVerifying(true);
    try {
      const v = await api.verifyAuditChain();
      setVerificationResult(v);
    } catch (e) {
      console.error(e);
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
          Diagnostics &amp; Tamper-Evident Audit Trail
        </h2>
        <p style={{ color: 'var(--text-muted)' }}>
          System operational parameters, protocol dissector status, and SHA-256 cryptographic hash-chained audit register.
        </p>
      </div>

      {/* Diagnostics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        {/* System & Dissector Info */}
        <div className="card-brutal">
          <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            System Diagnostics
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.85rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Application Engine:</span>
              <span style={{ fontWeight: 700 }}>{healthData?.app_name || 'IKETrace'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Engine Version:</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>v{healthData?.version || '1.0.0'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Operational Mode:</span>
              <span className="badge-brutal badge-pass text-xs">OFFLINE (Zero External Calls)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Primary Dissector:</span>
              <span style={{ fontWeight: 700 }}>Scapy Native (RFC 7296 Engine)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Optional TShark Dissector:</span>
              <span className={`badge-brutal ${healthData?.tshark_available ? 'badge-pass' : 'badge-na'} text-xs`}>
                {healthData?.tshark_available ? 'INSTALLED' : 'NOT INSTALLED (FALLBACK ACTIVE)'}
              </span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Upload Safety Limit:</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>25 MB</span>
            </div>
          </div>
        </div>

        {/* Audit Verification Status Card */}
        <div className="card-brutal">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            <h3 style={{ fontSize: '1.1rem' }}>Tamper-Evident Hash Chain</h3>
            <button
              onClick={handleVerify}
              disabled={isVerifying}
              className="btn-brutal btn-neutral btn-sm"
            >
              <RefreshCw size={12} className={isVerifying ? 'animate-spin' : ''} />
              <span>Verify Chain</span>
            </button>
          </div>

          {verificationResult && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.75rem',
                border: '2px solid var(--border-dark)',
                backgroundColor: verificationResult.chain_intact ? '#F4FEE4' : '#FFEBEA'
              }}>
                {verificationResult.chain_intact ? (
                  <CheckCircle2 size={24} color="#16A34A" />
                ) : (
                  <AlertTriangle size={24} color="var(--accent-danger)" />
                )}
                <div>
                  <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>
                    {verificationResult.verification_message}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    Total audit entries chained: {verificationResult.total_records}
                  </div>
                </div>
              </div>

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                {verificationResult.cryptographic_guarantees}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="table-brutal-container">
        <div style={{ padding: '0.75rem 1rem', borderBottom: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)', fontWeight: 700 }}>
          Cryptographic Audit Register ({auditRecords.length} records)
        </div>
        <table className="table-brutal" style={{ fontSize: '0.78rem' }}>
          <thead>
            <tr>
              <th>Seq #</th>
              <th>Timestamp</th>
              <th>Event Type</th>
              <th>Entity ID</th>
              <th>Record SHA-256 Hash</th>
              <th>Previous Linked Hash</th>
            </tr>
          </thead>
          <tbody>
            {auditRecords.slice(-10).map((rec) => (
              <tr key={rec.record_id}>
                <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>#{rec.sequence_number}</td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{new Date(rec.timestamp).toLocaleTimeString()}</td>
                <td>
                  <span className="badge-brutal badge-cobalt text-xs">{rec.event_type}</span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{rec.entity_id}</td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cobalt)' }}>
                  {rec.record_hash.slice(0, 16)}...
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {rec.previous_hash.slice(0, 16)}...
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
