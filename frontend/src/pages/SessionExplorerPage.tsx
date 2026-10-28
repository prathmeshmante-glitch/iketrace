import React, { useState } from 'react';
import { Network, Layers, Shield, FileText, ArrowRight } from 'lucide-react';
import { CaptureAnalysisResult, SessionSummary, PacketSummary } from '../types';

interface SessionExplorerPageProps {
  capture: CaptureAnalysisResult | null;
}

export const SessionExplorerPage: React.FC<SessionExplorerPageProps> = ({ capture }) => {
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<number | null>(null);

  if (!capture) {
    return (
      <div className="card-brutal" style={{ textAlign: 'center', padding: '3rem 1rem' }}>
        <h2>No Capture Selected</h2>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
          Please upload a PCAP capture or select a laboratory fixture to inspect sessions and packets.
        </p>
      </div>
    );
  }

  const activeSession: SessionSummary | undefined = capture.sessions.find(
    (s) => s.session_id === (selectedSessionId || capture.sessions[0]?.session_id)
  );

  const activePacket: PacketSummary | undefined = capture.packets.find(
    (p) => p.index === selectedPacketIndex
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.5rem', marginBottom: '0.25rem' }}>
          Protocol &amp; Session Explorer
        </h2>
        <p style={{ color: 'var(--text-muted)' }}>
          Detailed dissection of candidate IKEv1/v2 exchanges, proposal substructures, transform attributes, and ESP sessions.
        </p>
      </div>

      {/* Sessions Grid */}
      <div className="card-brutal">
        <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}>
          Identified VPN Sessions ({capture.sessions.length})
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
          {capture.sessions.map((sess) => {
            const isSelected = activeSession?.session_id === sess.session_id;
            return (
              <div
                key={sess.session_id}
                onClick={() => setSelectedSessionId(sess.session_id)}
                style={{
                  border: isSelected ? '3px solid var(--accent-cobalt)' : '2px solid var(--border-dark)',
                  backgroundColor: isSelected ? '#F4F7FF' : 'var(--bg-surface)',
                  boxShadow: isSelected ? 'var(--shadow-brutal)' : '2px 2px 0px var(--border-dark)',
                  padding: '1rem',
                  cursor: 'pointer',
                  transition: 'all 0.1s ease'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <span className="badge-brutal badge-cobalt text-xs">
                    {sess.ike_version || 'ESP Flow'}
                  </span>
                  <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    {sess.packet_count} packets ({sess.duration_seconds}s)
                  </span>
                </div>

                <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, fontSize: '0.85rem' }}>
                  {sess.initiator_ip}:{sess.initiator_port} &rarr; {sess.responder_ip}:{sess.responder_port}
                </div>

                {sess.initiator_spi && (
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '0.25rem' }}>
                    SPI: {sess.initiator_spi.slice(0, 8)}... / {sess.responder_spi?.slice(0, 8) || '00000000'}...
                  </div>
                )}

                <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Exchanges: {sess.exchange_types_observed.join(', ') || 'ESP Traffic'}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Packet Timeline & Transform Inspector Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '1.5rem' }}>
        {/* Packet Timeline Table */}
        <div className="table-brutal-container">
          <div style={{ padding: '0.75rem 1rem', borderBottom: '2px solid var(--border-dark)', backgroundColor: 'var(--bg-subtle)', fontWeight: 700 }}>
            Packet Timeline ({capture.packets.length} packets)
          </div>
          <table className="table-brutal">
            <thead>
              <tr>
                <th>#</th>
                <th>Time (s)</th>
                <th>Protocol</th>
                <th>Summary</th>
                <th>Len</th>
              </tr>
            </thead>
            <tbody>
              {capture.packets.map((pkt) => {
                const isSelected = selectedPacketIndex === pkt.index;
                return (
                  <tr
                    key={pkt.index}
                    onClick={() => setSelectedPacketIndex(pkt.index)}
                    style={{
                      cursor: 'pointer',
                      backgroundColor: isSelected ? 'var(--accent-lime)' : undefined
                    }}
                  >
                    <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{pkt.index}</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{pkt.timestamp.toFixed(4)}</td>
                    <td>
                      <span className={`badge-brutal ${pkt.is_ike ? 'badge-cobalt' : (pkt.is_esp ? 'badge-orange' : 'badge-na')} text-xs`}>
                        {pkt.protocol}
                      </span>
                    </td>
                    <td style={{ fontSize: '0.8rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {pkt.summary}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{pkt.length}B</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Selected Packet & Transform Deep Dive */}
        <div className="card-brutal" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <h3 style={{ fontSize: '1.1rem', borderBottom: '2px solid var(--border-dark)', paddingBottom: '0.5rem' }}>
            {activePacket ? `Packet #${activePacket.index} Inspector` : 'Proposal & Transform Inspector'}
          </h3>

          {activePacket ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.85rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Summary: </span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>{activePacket.summary}</span>
              </div>

              {activePacket.is_ike && (
                <>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Exchange:</span>
                    <span style={{ fontWeight: 700 }}>{activePacket.exchange_type || 'N/A'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Role:</span>
                    <span>{activePacket.is_initiator ? 'Initiator' : 'Responder'}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Message ID:</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{activePacket.message_id ?? 0}</span>
                  </div>
                  <div>
                    <span style={{ color: 'var(--text-muted)' }}>Payloads: </span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>{activePacket.payload_types.join(', ') || 'None'}</span>
                  </div>

                  {/* Proposals & Transforms */}
                  {activePacket.proposals.length > 0 && (
                    <div style={{ marginTop: '0.5rem', border: '2px solid var(--border-dark)', padding: '0.75rem', backgroundColor: 'var(--bg-subtle)' }}>
                      <div style={{ fontWeight: 700, fontSize: '0.8rem', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
                        Extracted Proposal Substructures ({activePacket.proposals.length})
                      </div>
                      {activePacket.proposals.map((prop) => (
                        <div key={prop.proposal_num} style={{ marginBottom: '0.5rem' }}>
                          <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cobalt)' }}>
                            Proposal #{prop.proposal_num} ({prop.protocol_id})
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.25rem' }}>
                            {prop.transforms.map((tr, idx) => (
                              <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                                <span style={{ fontWeight: 600 }}>[{tr.transform_type}]</span>
                                <span>{tr.transform_name} {tr.key_length ? `(${tr.key_length}-bit)` : ''}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}

              {activePacket.is_esp && (
                <div style={{ border: '2px solid var(--border-dark)', padding: '0.75rem', backgroundColor: '#FFF7ED' }}>
                  <div style={{ fontWeight: 700, fontSize: '0.8rem', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
                    ESP Encapsulated Payload
                  </div>
                  <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
                    SPI: {activePacket.esp_spi} | Seq: {activePacket.esp_seq}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: '#C2410C', marginTop: '0.5rem' }}>
                    NOTE: Payload is protected by authenticated encryption. Cleartext is never accessed or recovered.
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2rem 1rem', color: 'var(--text-muted)' }}>
              Click any packet in the timeline to inspect its cryptographic headers and proposals.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
