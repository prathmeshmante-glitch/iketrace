import React from 'react';
import {
  LayoutDashboard,
  UploadCloud,
  Network,
  ShieldCheck,
  Search,
  FlaskConical,
  GitCompare,
  LockKeyhole,
  Cpu,
  Share2,
  FileText,
  Sliders
} from 'lucide-react';

export type TabKey =
  | 'overview'
  | 'upload'
  | 'sessions'
  | 'policy'
  | 'findings'
  | 'scenarios'
  | 'drift'
  | 'privacy'
  | 'crypto'
  | 'graph'
  | 'reports'
  | 'settings';

interface SidebarProps {
  activeTab: TabKey;
  onSelectTab: (tab: TabKey) => void;
  badgeCounts?: {
    findingsFailed?: number;
    sessionsCount?: number;
    scenariosCount?: number;
  };
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab, badgeCounts }) => {
  const navItems: Array<{ key: TabKey; label: string; icon: React.ReactNode; badge?: string | number; badgeColor?: string }> = [
    { key: 'overview', label: '1. Overview', icon: <LayoutDashboard size={16} /> },
    { key: 'upload', label: '2. Capture Upload', icon: <UploadCloud size={16} /> },
    { key: 'sessions', label: '3. Protocol Explorer', icon: <Network size={16} />, badge: badgeCounts?.sessionsCount },
    { key: 'policy', label: '4. Policy Engine', icon: <ShieldCheck size={16} /> },
    {
      key: 'findings',
      label: '5. Findings & Evidence',
      icon: <Search size={16} />,
      badge: badgeCounts?.findingsFailed ? `${badgeCounts.findingsFailed} FAIL` : undefined,
      badgeColor: 'var(--accent-danger)'
    },
    { key: 'scenarios', label: '6. Defensive Scenario Lab', icon: <FlaskConical size={16} />, badge: '8 Tests' },
    { key: 'drift', label: '7. Drift & Regression', icon: <GitCompare size={16} /> },
    { key: 'privacy', label: '8. Traffic Privacy Lab', icon: <LockKeyhole size={16} />, badge: 'ML' },
    { key: 'crypto', label: '9. Crypto & PQC Readiness', icon: <Cpu size={16} /> },
    { key: 'graph', label: '10. Evidence Graph', icon: <Share2 size={16} /> },
    { key: 'reports', label: '11. Assessment Reports', icon: <FileText size={16} /> },
    { key: 'settings', label: '12. Diagnostics & Audit', icon: <Sliders size={16} /> },
  ];

  return (
    <aside style={{
      width: '260px',
      backgroundColor: 'var(--bg-surface)',
      borderRight: '3px solid var(--border-dark)',
      minHeight: 'calc(100vh - 65px)',
      display: 'flex',
      flexDirection: 'column',
      padding: '1rem 0.75rem',
      gap: '0.35rem',
      flexShrink: 0
    }}>
      <div style={{
        fontSize: '0.7rem',
        fontFamily: 'var(--font-mono)',
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.1em',
        color: 'var(--text-muted)',
        padding: '0.25rem 0.5rem 0.5rem',
        borderBottom: '2px solid var(--border-dark)',
        marginBottom: '0.5rem'
      }}>
        Assurance Workbench
      </div>

      <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {navItems.map((item) => {
          const isActive = activeTab === item.key;
          return (
            <button
              key={item.key}
              onClick={() => onSelectTab(item.key)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.6rem 0.75rem',
                border: isActive ? '2px solid var(--border-dark)' : '2px solid transparent',
                backgroundColor: isActive ? 'var(--accent-lime)' : 'transparent',
                boxShadow: isActive ? '3px 3px 0px var(--border-dark)' : 'none',
                fontFamily: 'var(--font-heading)',
                fontSize: '0.85rem',
                fontWeight: isActive ? 700 : 600,
                color: 'var(--text-main)',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.1s ease',
                transform: isActive ? 'translate(-1px, -1px)' : 'none'
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.backgroundColor = 'var(--bg-subtle)';
                  e.currentTarget.style.border = '2px solid var(--border-dark)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.border = '2px solid transparent';
                }
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                {item.icon}
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span style={{
                  fontSize: '0.68rem',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  padding: '0.1rem 0.35rem',
                  border: '1px solid var(--border-dark)',
                  backgroundColor: item.badgeColor || 'var(--bg-surface)',
                  color: item.badgeColor ? '#FFFFFF' : 'var(--text-main)',
                }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div style={{ marginTop: 'auto', paddingTop: '1rem', borderTop: '2px solid var(--border-dark)' }}>
        <div style={{
          padding: '0.75rem',
          backgroundColor: '#FAF7F0',
          border: '2px solid var(--border-dark)',
          fontSize: '0.72rem',
          fontFamily: 'var(--font-mono)',
          lineHeight: '1.4'
        }}>
          <div style={{ fontWeight: 700, marginBottom: '0.25rem' }}>LEGAL NOTICE</div>
          The absence of a detected violation is not proof that a VPN is cryptographically secure.
        </div>
      </div>
    </aside>
  );
};
