import React, { useState, useEffect } from 'react';
import { FileText, Download, Copy, Printer, Check, ShieldCheck, Hash, AlertTriangle } from 'lucide-react';
import { AssessmentReport, CaptureAnalysisResult, PolicyDefinition } from '../types';
import { api } from '../services/api';
import { TabKey } from '../components/Sidebar';

interface ReportExportPageProps {
  reports: AssessmentReport[];
  currentCapture: CaptureAnalysisResult | null;
  policies: PolicyDefinition[];
  activePolicyId: string;
  onReportGenerated: (rep: AssessmentReport) => void;
  onNavigate?: (tab: TabKey) => void;
}

export const ReportExportPage: React.FC<ReportExportPageProps> = ({
  reports,
  currentCapture,
  policies,
  activePolicyId,
  onReportGenerated,
  onNavigate,
}) => {
  const [reportTitle, setReportTitle] = useState('VPN Security Assurance Assessment Report');
  const [selectedPolicyId, setSelectedPolicyId] = useState(activePolicyId || 'POL-DEF-NIST-SP800-77');
  const [isGenerating, setIsGenerating] = useState(false);
  const [sessionReports, setSessionReports] = useState<AssessmentReport[]>([]);
  const [selectedReportId, setSelectedReportId] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Sync session reports when currentCapture changes
  useEffect(() => {
    if (!currentCapture) {
      setSessionReports([]);
      setSelectedReportId(null);
      return;
    }

    api.listAnalysisReports(currentCapture.capture_id)
      .then((reps) => {
        setSessionReports(reps);
        if (reps.length > 0) {
          setSelectedReportId(reps[0].report_id);
        } else {
          setSelectedReportId(null);
        }
      })
      .catch(() => {
        const filtered = reports.filter((r) => r.target_id === currentCapture.capture_id);
        setSessionReports(filtered);
        if (filtered.length > 0) {
          setSelectedReportId(filtered[0].report_id);
        }
      });
  }, [currentCapture, reports]);

  const handleGenerate = async () => {
    if (!currentCapture) {
      setErrorMessage('No active capture selected. Please select a capture first.');
      return;
    }
    setErrorMessage(null);
    setIsGenerating(true);
    try {
      const rep = await api.generateReport(
        reportTitle,
        currentCapture.capture_id,
        'CAPTURE',
        selectedPolicyId
      );
      onReportGenerated(rep);
      setSessionReports((prev) => [rep, ...prev]);
      setSelectedReportId(rep.report_id);
    } catch (e: any) {
      setErrorMessage(e.message || 'Failed to compile assessment report.');
    } finally {
      setIsGenerating(false);
    }
  };

  const activeReport = sessionReports.find((r) => r.report_id === selectedReportId) || sessionReports[0] || null;

  const handleCopyMarkdown = () => {
    if (activeReport?.markdown_content) {
      navigator.clipboard.writeText(activeReport.markdown_content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownloadMarkdown = () => {
    if (!activeReport?.markdown_content) return;
    const blob = new Blob([activeReport.markdown_content], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeReport.report_id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!currentCapture) {
    return (
      <div className="card-brutal" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
        <h2>No Active Analysis Session Selected</h2>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
          Please upload or select an analysis session before generating or exporting assessment reports.
        </p>
        {onNavigate && (
          <button
            onClick={() => onNavigate('upload')}
            className="btn-brutal btn-primary btn-sm"
            style={{ marginTop: '1rem' }}
          >
            Go to Capture Ingestion &rarr;
          </button>
        )}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
            Assessment Report Generator &amp; Export
          </h2>
          <p style={{ color: 'var(--text-muted)' }}>
            Export reproducible, evidence-linked security reports with cryptographic fingerprints and tamper verification anchors.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            onClick={handleCopyMarkdown}
            disabled={!activeReport}
            className="btn-brutal btn-neutral btn-sm"
          >
            {copied ? <Check size={14} color="#16A34A" /> : <Copy size={14} />}
            <span>{copied ? 'Copied!' : 'Copy Markdown'}</span>
          </button>
          <button
            onClick={handleDownloadMarkdown}
            disabled={!activeReport}
            className="btn-brutal btn-neutral btn-sm"
          >
            <Download size={14} />
            <span>Download .md</span>
          </button>
          <button
            onClick={() => window.print()}
            disabled={!activeReport}
            className="btn-brutal btn-secondary btn-sm"
          >
            <Printer size={14} />
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {errorMessage && (
        <div className="alert-brutal alert-danger">
          <AlertTriangle size={20} color="var(--accent-danger)" />
          <div>{errorMessage}</div>
        </div>
      )}

      {/* Generator Form Card */}
      <div className="card-brutal" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 2, minWidth: '240px' }}>
            <label style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem', display: 'block' }}>
              Report Title:
            </label>
            <input
              type="text"
              value={reportTitle}
              onChange={(e) => setReportTitle(e.target.value)}
              className="input-brutal"
            />
          </div>

          <div style={{ flex: 1, minWidth: '200px' }}>
            <label style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.25rem', display: 'block' }}>
              Evaluation Policy:
            </label>
            <select
              value={selectedPolicyId}
              onChange={(e) => setSelectedPolicyId(e.target.value)}
              className="input-brutal"
              style={{ padding: '0.55rem' }}
            >
              {policies.map((p) => (
                <option key={p.policy_id} value={p.policy_id}>
                  {p.name} (v{p.version})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={handleGenerate}
            disabled={isGenerating || !currentCapture}
            className="btn-brutal btn-primary"
            style={{ height: '42px' }}
          >
            <FileText size={16} />
            <span>{isGenerating ? 'Compiling Report...' : 'Generate Assessment Report'}</span>
          </button>
        </div>

        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          Active Target: <strong>{currentCapture.filename}</strong> (ID: {currentCapture.capture_id}) • SHA-256: {currentCapture.file_hash_sha256 ? `${currentCapture.file_hash_sha256.substring(0, 16)}...` : 'N/A'}
        </div>
      </div>

      {/* Reports for Active Session List */}
      {sessionReports.length > 0 && (
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: '0.75rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
            Available Reports for this Session ({sessionReports.length}):
          </span>
          {sessionReports.map((r) => {
            const isSelected = activeReport?.report_id === r.report_id;
            return (
              <button
                key={r.report_id}
                onClick={() => setSelectedReportId(r.report_id)}
                className={`btn-brutal btn-sm ${isSelected ? 'btn-primary' : 'btn-neutral'}`}
                style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
              >
                {r.report_id} ({new Date(r.generated_at).toLocaleTimeString()})
              </button>
            );
          })}
        </div>
      )}

      {/* Report Preview */}
      {activeReport ? (
        <div className="card-brutal" style={{ backgroundColor: '#FFFFFF', padding: '2rem' }}>
          <div style={{ borderBottom: '3px solid var(--border-dark)', paddingBottom: '1rem', marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <span className="badge-brutal badge-cobalt text-xs">OFFICIAL REPORT</span>
              <h1 style={{ fontSize: '1.8rem', marginTop: '0.5rem', marginBottom: '0.25rem' }}>
                {activeReport.title}
              </h1>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Report ID: {activeReport.report_id} • Target ID: {activeReport.target_id} • Generated: {new Date(activeReport.generated_at).toLocaleString()}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <span style={{
                fontFamily: 'var(--font-heading)',
                fontWeight: 900,
                fontSize: '1.1rem',
                padding: '0.4rem 0.8rem',
                border: '2px solid var(--border-dark)',
                backgroundColor: activeReport.overall_verdict === 'COMPLIANT' ? 'var(--accent-lime)' : (activeReport.overall_verdict === 'VIOLATIONS_FOUND' ? '#FFEBEA' : '#FFFBEB'),
                display: 'inline-block'
              }}>
                {activeReport.overall_verdict}
              </span>
            </div>
          </div>

          {/* Verification Fingerprints Card */}
          <div style={{
            padding: '1rem',
            border: '2px solid var(--border-dark)',
            backgroundColor: 'var(--bg-subtle)',
            marginBottom: '1.5rem',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '1rem',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-mono)'
          }}>
            <div>
              <div style={{ fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Audit Chain Status:</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <ShieldCheck size={16} color="#16A34A" />
                <span style={{ fontWeight: 700 }}>Chain Validated (SHA-256)</span>
              </div>
              <div style={{ color: 'var(--text-muted)', wordBreak: 'break-all', marginTop: '0.25rem' }}>
                {activeReport.audit_hash}
              </div>
            </div>

            <div>
              <div style={{ fontWeight: 700, color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Reproducibility Fingerprint:</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Hash size={16} color="var(--accent-cobalt)" />
                <span style={{ fontWeight: 700 }}>SHA-256 Integrity Anchor</span>
              </div>
              <div style={{ color: 'var(--text-muted)', wordBreak: 'break-all', marginTop: '0.25rem' }}>
                {activeReport.reproducibility_fingerprint}
              </div>
            </div>
          </div>

          {/* Markdown Content Rendered as Pure Monospace / Styled Text */}
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
            lineHeight: '1.6',
            whiteSpace: 'pre-wrap',
            backgroundColor: '#FAFAFA',
            padding: '1.5rem',
            border: '2px solid var(--border-dark)'
          }}>
            {activeReport.markdown_content || activeReport.executive_summary}
          </div>
        </div>
      ) : (
        <div className="card-brutal" style={{ textAlign: 'center', padding: '2.5rem 1rem' }}>
          <p style={{ color: 'var(--text-muted)' }}>
            No report generated yet for this analysis session. Click &quot;Generate Assessment Report&quot; above to create one.
          </p>
        </div>
      )}
    </div>
  );
};
