import React, { useState, useEffect } from 'react';
import { Share2, Network, ShieldCheck, CheckCircle2, XCircle, ArrowRight, Info } from 'lucide-react';
import { api } from '../services/api';
import { CaptureAnalysisResult } from '../types';

interface EvidenceGraphPageProps {
  currentCapture: CaptureAnalysisResult | null;
}

export const EvidenceGraphPage: React.FC<EvidenceGraphPageProps> = ({ currentCapture }) => {
  const [graphData, setGraphData] = useState<{ nodes: any[]; edges: any[] }>({ nodes: [], edges: [] });
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (!currentCapture) return;
    setIsLoading(true);
    api.getEvidenceGraph(currentCapture.capture_id)
      .then((data) => {
        setGraphData(data);
        if (data.nodes.length > 0) {
          setSelectedNode(data.nodes[0]);
        }
      })
      .catch((e) => console.error(e))
      .finally(() => setIsLoading(false));
  }, [currentCapture]);

  if (!currentCapture) {
    return (
      <div className="card-brutal" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
        <h2>No Target Capture Selected</h2>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
          Please select or upload a capture to generate the interactive evidence graph.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
            Interactive Evidence Graph
          </h2>
          <p style={{ color: 'var(--text-muted)' }}>
            Trace topological relationships connecting Target &rarr; Sessions &rarr; Direct Packet Observations &rarr; Security Policy Verdicts.
          </p>
        </div>
        <span className="badge-brutal badge-cobalt">
          {graphData.nodes.length} Nodes • {graphData.edges.length} Relationships
        </span>
      </div>

      {/* Visual Graph Canvas & Node Inspector Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 0.7fr', gap: '1.5rem' }}>
        {/* Interactive Canvas */}
        <div
          style={{
            minHeight: '520px',
            backgroundColor: 'var(--bg-canvas)',
            border: '3px solid var(--border-dark)',
            boxShadow: 'var(--shadow-brutal)',
            padding: '1.5rem',
            position: 'relative',
            overflow: 'auto',
            backgroundImage: 'radial-gradient(#171717 1px, transparent 1px)',
            backgroundSize: '20px 20px'
          }}
        >
          {isLoading ? (
            <div style={{ textAlign: 'center', paddingTop: '10rem', fontWeight: 700 }}>
              Synthesizing Evidence Graph Relationships...
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              {/* Layer 1: Target Root */}
              <div style={{ display: 'flex', justifyContent: 'center' }}>
                {graphData.nodes.filter((n) => n.data.category === 'TARGET_ROOT').map((n) => (
                  <div
                    key={n.id}
                    onClick={() => setSelectedNode(n)}
                    style={{
                      border: selectedNode?.id === n.id ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                      backgroundColor: 'var(--accent-lime)',
                      boxShadow: 'var(--shadow-brutal)',
                      padding: '0.75rem 1.25rem',
                      fontFamily: 'var(--font-heading)',
                      fontWeight: 900,
                      cursor: 'pointer'
                    }}
                  >
                    {n.data.label}
                  </div>
                ))}
              </div>

              {/* Layer 2: Sessions */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
                {graphData.nodes.filter((n) => n.data.category === 'SESSION').map((n) => (
                  <div
                    key={n.id}
                    onClick={() => setSelectedNode(n)}
                    style={{
                      border: selectedNode?.id === n.id ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                      backgroundColor: 'var(--bg-surface)',
                      boxShadow: '3px 3px 0px var(--border-dark)',
                      padding: '0.6rem 1rem',
                      cursor: 'pointer',
                      fontSize: '0.85rem'
                    }}
                  >
                    <div style={{ fontWeight: 700 }}>{n.data.label}</div>
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{n.data.details}</div>
                  </div>
                ))}
              </div>

              {/* Layer 3: Direct Evidence Items */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                {graphData.nodes.filter((n) => n.data.category === 'EVIDENCE').map((n) => (
                  <div
                    key={n.id}
                    onClick={() => setSelectedNode(n)}
                    style={{
                      border: selectedNode?.id === n.id ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                      backgroundColor: '#EBF1FF',
                      boxShadow: '2px 2px 0px var(--border-dark)',
                      padding: '0.5rem 0.75rem',
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                      maxWidth: '180px'
                    }}
                  >
                    <div style={{ fontWeight: 700 }}>{n.data.label}</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--accent-cobalt)', wordBreak: 'break-all' }}>
                      {n.data.details.split('\n')[0]}
                    </div>
                  </div>
                ))}
              </div>

              {/* Layer 4: Policy Verdicts */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: '1rem', flexWrap: 'wrap' }}>
                {graphData.nodes.filter((n) => n.data.category === 'POLICY_VERDICT').map((n) => {
                  const isPass = n.data.status === 'PASS';
                  return (
                    <div
                      key={n.id}
                      onClick={() => setSelectedNode(n)}
                      style={{
                        border: selectedNode?.id === n.id ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                        backgroundColor: isPass ? '#F4FEE4' : '#FFEBEA',
                        boxShadow: '2px 2px 0px var(--border-dark)',
                        padding: '0.5rem 0.75rem',
                        cursor: 'pointer',
                        fontSize: '0.75rem'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontWeight: 700 }}>
                        {isPass ? <CheckCircle2 size={12} color="#16A34A" /> : <XCircle size={12} color="#DC2626" />}
                        <span>{n.data.label}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Node Inspector Detail Card */}
        <div className="card-brutal" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h3 style={{ fontSize: '1.1rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            Node Property Inspector
          </h3>

          {selectedNode ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
              <div>
                <span className="badge-brutal badge-cobalt text-xs">{selectedNode.data.category}</span>
                <div style={{ fontWeight: 900, fontSize: '1.1rem', marginTop: '0.25rem' }}>
                  {selectedNode.data.label}
                </div>
              </div>

              <div style={{ padding: '0.75rem', border: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)' }}>
                <div style={{ fontWeight: 700, fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Details &amp; Reference:
                </div>
                <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', marginTop: '0.25rem', whiteSpace: 'pre-wrap' }}>
                  {selectedNode.data.details}
                </pre>
              </div>

              {selectedNode.data.status && (
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Status:</span>
                  <span style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{selectedNode.data.status}</span>
                </div>
              )}

              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', borderTop: '1px solid var(--border-dark)', paddingTop: '0.75rem' }}>
                Node ID: <code style={{ fontSize: '0.7rem' }}>{selectedNode.id}</code>
              </div>
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)' }}>
              Click any node in the graph to inspect its evidence provenance and relationships.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
