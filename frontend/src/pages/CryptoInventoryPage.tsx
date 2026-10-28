import React from 'react';
import { Info } from 'lucide-react';
import { CryptoInventoryReport } from '../types';
import { StatusBadge } from '../components/StatusBadge';

interface CryptoInventoryPageProps {
  inventory: CryptoInventoryReport | null;
}

export const CryptoInventoryPage: React.FC<CryptoInventoryPageProps> = ({ inventory }) => {
  if (!inventory) {
    return (
      <div className="card-brutal" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
        <h2>No Cryptographic Inventory Available</h2>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
          Please select an active packet capture or scenario to inventory negotiated cryptographic transforms.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
          Cryptographic Inventory &amp; Post-Quantum Readiness
        </h2>
        <p style={{ color: 'var(--text-muted)' }}>
          Catalog of observable cryptographic primitives, classical compliance status, Shor's / Grover's quantum threat exposure, and NIST migration roadmap.
        </p>
      </div>

      {/* KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
        <div className="card-brutal">
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Total Assets Cataloged
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 900 }}>
            {inventory.total_assets_inventoried}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Across active sessions</div>
        </div>

        <div className="card-brutal">
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Classical Compliant
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 900, color: '#16A34A' }}>
            {inventory.compliant_assets_count}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Meets NIST SP 800-77</div>
        </div>

        <div className="card-brutal">
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            Quantum Vulnerable (Shor)
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 900, color: 'var(--accent-orange)' }}>
            {inventory.quantum_vulnerable_assets_count}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Asymmetric DH / ECDH</div>
        </div>

        <div className="card-brutal">
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            PQC Readiness Score
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 900, color: 'var(--accent-cobalt)' }}>
            {inventory.pqc_readiness_score_pct}%
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Symmetric 256-bit + ML-KEM</div>
        </div>
      </div>

      {/* Caveat & Disclaimer Banner */}
      <div className="alert-brutal alert-info">
        <Info size={20} color="var(--accent-cobalt)" />
        <div>
          <div style={{ fontWeight: 700 }}>Post-Quantum Migration Methodology Disclaimer</div>
          <div style={{ fontSize: '0.8rem', lineHeight: '1.4' }}>
            Post-quantum readiness is evaluated as a configuration inventory and cryptographic transition assessment.
            It identifies classical primitives vulnerable to Store-Now-Decrypt-Later (SNDL) attacks and recommends IETF RFC 9370
            hybrid key exchange targets (e.g. ML-KEM-768/1024). It does not claim to execute quantum cryptanalysis.
          </div>
        </div>
      </div>

      {/* Cryptographic Inventory Assets Table */}
      <div className="table-brutal-container">
        <div style={{ padding: '0.75rem 1rem', borderBottom: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)', fontWeight: 700 }}>
          Cryptographic Asset Register ({inventory.assets.length} primitives)
        </div>
        <table className="table-brutal">
          <thead>
            <tr>
              <th>Category</th>
              <th>Algorithm</th>
              <th>Status</th>
              <th>PQC Threat</th>
              <th>Priority</th>
              <th>Recommended Target &amp; Migration Guidance</th>
            </tr>
          </thead>
          <tbody>
            {inventory.assets.map((asset) => (
              <tr key={asset.asset_id}>
                <td>
                  <span className="badge-brutal badge-cobalt text-xs">{asset.category}</span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                  {asset.algorithm_name} {asset.key_length ? `(${asset.key_length}-bit)` : ''}
                </td>
                <td>
                  <span className={`badge-brutal ${asset.compliance_status === 'COMPLIANT' ? 'badge-pass' : (asset.compliance_status === 'DEPRECATED' ? 'badge-unknown' : 'badge-fail')} text-xs`}>
                    {asset.compliance_status}
                  </span>
                </td>
                <td>
                  <span className={`badge-brutal ${asset.pqc_readiness === 'QUANTUM_RESISTANT_SYMMETRIC' ? 'badge-pass' : 'badge-orange'} text-xs`}>
                    {asset.pqc_readiness.replace(/_/g, ' ')}
                  </span>
                </td>
                <td>
                  <StatusBadge severity={asset.migration_priority} size="sm" />
                </td>
                <td style={{ fontSize: '0.8rem' }}>
                  <div style={{ fontWeight: 700, color: 'var(--accent-cobalt)' }}>
                    &rarr; {asset.recommended_target}
                  </div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.2rem' }}>
                    {asset.transition_guidance}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Recommended Migration Actions */}
      {inventory.migration_actions.length > 0 && (
        <div className="card-brutal">
          <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            Actionable Migration Roadmap
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {inventory.migration_actions.map((act, idx) => (
              <div key={idx} style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)' }}>
                <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{act.action}</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>{act.detail}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
