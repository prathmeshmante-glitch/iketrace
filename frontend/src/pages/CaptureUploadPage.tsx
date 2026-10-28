import React, { useState, useRef } from 'react';
import { UploadCloud, File, AlertCircle, CheckCircle2, ShieldAlert, ArrowRight, Database, Hash, Trash2 } from 'lucide-react';
import { CaptureAnalysisResult } from '../types';
import { api } from '../services/api';
import { TabKey } from '../components/Sidebar';

interface CaptureUploadPageProps {
  captures: CaptureAnalysisResult[];
  onCaptureUploaded: (capture: CaptureAnalysisResult) => void;
  onSelectCapture: (id: string) => void;
  selectedCaptureId: string | null;
  onNavigate: (tab: TabKey) => void;
  onDeleteCapture?: (id: string) => void;
}

export const CaptureUploadPage: React.FC<CaptureUploadPageProps> = ({
  captures,
  onCaptureUploaded,
  onSelectCapture,
  selectedCaptureId,
  onNavigate,
  onDeleteCapture,
}) => {
  const [isUploading, setIsUploading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = async (file: File) => {
    setIsUploading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    try {
      const res = await api.uploadCapture(file);
      onCaptureUploaded(res);
      onSelectCapture(res.capture_id);
      setSuccessMsg(`Successfully uploaded and analyzed '${file.name}' (${res.total_packets} packets). Session ID: ${res.capture_id}`);
    } catch (err: any) {
      setErrorMsg(err.message || 'Capture upload or dissection failed.');
    } finally {
      setIsUploading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  // Separate user captures from bundled fixtures
  const userCaptures = captures.filter(c => !c.filename.includes('fixture_') && !c.filename.includes('baseline.pcap') && !c.filename.includes('prohibited_') && !c.capture_id.startsWith('fixture-'));
  const fixtureCaptures = captures.filter(c => !userCaptures.includes(c));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
          Packet Capture Ingestion &amp; Session Management
        </h2>
        <p style={{ color: 'var(--text-muted)' }}>
          Authorized offline ingestion of PCAP and PCAPNG captures. Magic byte validation, parse safety limits, cryptographic SHA-256 fingerprinting, and session isolation.
        </p>
      </div>

      {errorMsg && (
        <div className="alert-brutal alert-danger">
          <AlertCircle size={20} color="var(--accent-danger)" />
          <div>
            <div style={{ fontWeight: 700 }}>Upload / Dissection Error</div>
            <div style={{ fontSize: '0.85rem' }}>{errorMsg}</div>
          </div>
        </div>
      )}

      {successMsg && (
        <div className="alert-brutal alert-success">
          <CheckCircle2 size={20} color="#16A34A" />
          <div>
            <div style={{ fontWeight: 700 }}>Analysis Session Ready</div>
            <div style={{ fontSize: '0.85rem' }}>{successMsg}</div>
          </div>
        </div>
      )}

      {/* Upload Dropzone & Laboratory Fixtures Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '1.5rem' }}>
        {/* Dropzone */}
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          style={{
            border: '3px dashed var(--border-dark)',
            backgroundColor: 'var(--bg-surface)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '2.5rem 1.5rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '1rem',
            cursor: 'pointer'
          }}
          onClick={() => fileInputRef.current?.click()}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
            accept=".pcap,.pcapng,.cap"
            style={{ display: 'none' }}
          />
          <div style={{
            padding: '1rem',
            backgroundColor: 'var(--accent-lime)',
            border: '2px solid var(--border-dark)',
            boxShadow: '2px 2px 0px var(--border-dark)'
          }}>
            <UploadCloud size={32} />
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1.1rem', fontFamily: 'var(--font-heading)' }}>
              Drag &amp; Drop PCAP / PCAPNG File
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              Standard PCAP (0xa1b2c3d4) or PCAPNG (0x0a0d0d0a). Max file size 25MB.
            </div>
          </div>
          <button
            type="button"
            className="btn-brutal btn-primary"
            disabled={isUploading}
          >
            {isUploading ? 'Dissecting Packets...' : 'Select File from Computer'}
          </button>
        </div>

        {/* Pre-Loaded Laboratory Fixtures */}
        <div className="card-brutal">
          <h3 style={{ fontSize: '1rem', marginBottom: '0.5rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            Pre-Loaded Laboratory Fixtures
          </h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            Explicitly load an authorized synthetic trace for testing and demonstration:
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '240px', overflowY: 'auto' }}>
            {fixtureCaptures.length > 0 ? (
              fixtureCaptures.map((cap) => {
                const isActive = selectedCaptureId === cap.capture_id;
                return (
                  <div
                    key={cap.capture_id}
                    onClick={() => onSelectCapture(cap.capture_id)}
                    style={{
                      padding: '0.6rem 0.75rem',
                      border: isActive ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                      backgroundColor: isActive ? 'var(--accent-lime)' : 'var(--bg-surface)',
                      boxShadow: '2px 2px 0px var(--border-dark)',
                      cursor: 'pointer',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      transition: 'all 0.1s ease'
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 700, fontSize: '0.82rem' }}>{cap.filename}</div>
                      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {cap.total_packets} pkts • {cap.ike_packets} IKE • {cap.esp_packets} ESP
                      </div>
                    </div>
                    {isActive ? (
                      <span className="badge-brutal badge-cobalt text-xs">ACTIVE</span>
                    ) : (
                      <button
                        className="btn-brutal btn-neutral btn-sm"
                        style={{ fontSize: '0.7rem', padding: '0.2rem 0.5rem' }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectCapture(cap.capture_id);
                        }}
                      >
                        Load
                      </button>
                    )}
                  </div>
                );
              })
            ) : (
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'center', padding: '1rem' }}>
                No fixtures loaded yet.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Uploaded Analyses Session History */}
      <div className="card-brutal">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1.1rem' }}>Available Analysis Sessions ({captures.length})</h3>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Persistent SQLite storage (`iketrace.db`). Select a session to isolate its evaluation, inventory, and reports.
            </span>
          </div>
        </div>

        <div className="table-brutal-container">
          <table className="table-brutal">
            <thead>
              <tr>
                <th>Status</th>
                <th>Analysis ID</th>
                <th>Display Filename</th>
                <th>SHA-256 Fingerprint</th>
                <th>Packets</th>
                <th>Sessions</th>
                <th>Ingested At</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {captures.length > 0 ? (
                captures.map((cap) => {
                  const isActive = selectedCaptureId === cap.capture_id;
                  return (
                    <tr
                      key={cap.capture_id}
                      style={{
                        backgroundColor: isActive ? '#F4FEE4' : undefined,
                        cursor: 'pointer'
                      }}
                      onClick={() => onSelectCapture(cap.capture_id)}
                    >
                      <td>
                        {isActive ? (
                          <span className="badge-brutal badge-cobalt text-xs">ACTIVE</span>
                        ) : (
                          <span className="badge-brutal badge-pass text-xs">{cap.status || 'READY'}</span>
                        )}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
                        {cap.capture_id}
                      </td>
                      <td style={{ fontWeight: 600 }}>{cap.filename}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {cap.file_hash_sha256 ? `${cap.file_hash_sha256.substring(0, 16)}...` : 'N/A'}
                      </td>
                      <td>
                        <span style={{ fontFamily: 'var(--font-mono)' }}>{cap.total_packets}</span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}> ({cap.ike_packets} IKE)</span>
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)' }}>{cap.session_count}</td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {new Date(cap.uploaded_at).toLocaleTimeString()}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '0.5rem' }}>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectCapture(cap.capture_id);
                            }}
                            className={`btn-brutal btn-sm ${isActive ? 'btn-primary' : 'btn-neutral'}`}
                            style={{ padding: '0.2rem 0.5rem', fontSize: '0.75rem' }}
                          >
                            {isActive ? 'Active' : 'Select'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    No packet captures uploaded yet. Drop a PCAP above or load a fixture.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Capture Dissection Overview */}
      {selectedCaptureId && (
        <div className="card-brutal">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <h3 style={{ fontSize: '1.1rem' }}>Active Session: Dissection Verification</h3>
              <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                Target: {selectedCaptureId}
              </span>
            </div>
            <button
              onClick={() => onNavigate('sessions')}
              className="btn-brutal btn-secondary btn-sm"
            >
              Explore Sessions &amp; Timeline <ArrowRight size={14} />
            </button>
          </div>

          {(() => {
            const cap = captures.find((c) => c.capture_id === selectedCaptureId);
            if (!cap) return null;
            return (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
                  <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Total Packets</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 900 }}>{cap.total_packets}</div>
                  </div>
                  <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>IKE Negotiations</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 900, color: 'var(--accent-cobalt)' }}>{cap.ike_packets}</div>
                  </div>
                  <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Encrypted ESP</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 900 }}>{cap.esp_packets}</div>
                  </div>
                  <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Parse Completeness</div>
                    <div style={{ fontSize: '1.5rem', fontWeight: 900, color: '#16A34A' }}>{cap.parse_completeness_pct}%</div>
                  </div>
                </div>

                {cap.parser_warnings.length > 0 && (
                  <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: '#FFFBEB' }}>
                    <div style={{ fontWeight: 700, fontSize: '0.85rem', color: '#B45309', marginBottom: '0.25rem' }}>
                      Dissection Warnings / Robustness Notes:
                    </div>
                    <ul style={{ paddingLeft: '1.25rem', fontSize: '0.8rem', color: '#92400E' }}>
                      {cap.parser_warnings.map((w, i) => (
                        <li key={i}>{w}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
};
