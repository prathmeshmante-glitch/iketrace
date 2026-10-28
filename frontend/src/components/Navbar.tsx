import React from 'react';
import { ShieldCheck, HardDrive, Hash, Check } from 'lucide-react';
import { CaptureAnalysisResult } from '../types';

interface NavbarProps {
  captures: CaptureAnalysisResult[];
  selectedCaptureId: string | null;
  onSelectCapture: (id: string) => void;
  auditChainIntact: boolean;
  latestAuditHash: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  captures,
  selectedCaptureId,
  onSelectCapture,
  auditChainIntact,
  latestAuditHash,
}) => {
  return (
    <header style={{
      backgroundColor: 'var(--bg-surface)',
      borderBottom: '3px solid var(--border-dark)',
      padding: '0.75rem 1.5rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      position: 'sticky',
      top: 0,
      zIndex: 50,
      boxShadow: '0 4px 0px rgba(0,0,0,0.05)'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{
          backgroundColor: 'var(--accent-lime)',
          border: '2px solid var(--border-dark)',
          boxShadow: '2px 2px 0px var(--border-dark)',
          padding: '0.4rem 0.6rem',
          display: 'flex',
          alignItems: 'center',
          fontWeight: 900,
          fontSize: '1.25rem',
          fontFamily: 'var(--font-heading)',
          letterSpacing: '-0.03em'
        }}>
          IKETrace
        </div>
        <div>
          <div style={{ fontWeight: 700, fontSize: '0.875rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            VPN Security Assurance & Cryptographic Lab
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            "See what your VPN negotiated. Prove what your security policy guarantees."
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {/* Active Target Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <label style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
            Target:
          </label>
          <select
            value={selectedCaptureId || ''}
            onChange={(e) => onSelectCapture(e.target.value)}
            style={{
              padding: '0.35rem 0.6rem',
              border: '2px solid var(--border-dark)',
              backgroundColor: 'var(--bg-surface)',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.8rem',
              fontWeight: 600,
              boxShadow: '2px 2px 0px var(--border-dark)',
              cursor: 'pointer'
            }}
          >
            <option value="">-- No Active Session (Empty State) --</option>
            {captures.map((c) => (
              <option key={c.capture_id} value={c.capture_id}>
                {c.filename} ({c.total_packets} pkts)
              </option>
            ))}
          </select>
        </div>

        {/* Audit Anchor Status */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.35rem',
          padding: '0.3rem 0.6rem',
          border: '2px solid var(--border-dark)',
          backgroundColor: auditChainIntact ? '#F4FEE4' : '#FFEBEA',
          boxShadow: '2px 2px 0px var(--border-dark)',
          fontSize: '0.75rem',
          fontFamily: 'var(--font-mono)'
        }}>
          <Hash size={13} strokeWidth={2.5} />
          <span>CHAIN:</span>
          <span style={{ fontWeight: 700 }}>
            {auditChainIntact ? 'VERIFIED' : 'TAMPERED'}
          </span>
          <span style={{ color: 'var(--text-muted)' }}>({latestAuditHash.slice(0, 8)}...)</span>
        </div>

        {/* Offline Mode Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.35rem',
          padding: '0.3rem 0.6rem',
          border: '2px solid var(--border-dark)',
          backgroundColor: 'var(--accent-lime)',
          boxShadow: '2px 2px 0px var(--border-dark)',
          fontSize: '0.75rem',
          fontFamily: 'var(--font-mono)',
          fontWeight: 700
        }}>
          <Check size={13} strokeWidth={3} />
          <span>OFFLINE LOCAL</span>
        </div>
      </div>
    </header>
  );
};
