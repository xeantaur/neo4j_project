import React from 'react';
import type { CytoscapeEdgeData } from '../graph/transformGraphData';
import { Tag } from '../common/Badge';
import {
  formatObservedBytes,
  formatObservedPackets,
  formatEpochSeconds,
  formatObservationWindow,
} from '../../utils/formatters';
import { ArrowRight, Shield } from 'lucide-react';

interface CommunicationEdgePanelProps {
  edge: CytoscapeEdgeData;
  onSelectCenter?: (address: string) => void;
  onSetPathEndpoints?: (source: string, target: string) => void;
}

export const CommunicationEdgePanel: React.FC<CommunicationEdgePanelProps> = ({
  edge,
  onSelectCenter,
  onSetPathEndpoints,
}) => {
  // Strip node ID prefixes (e.g., 'ip:192.168.1.1' -> '192.168.1.1')
  const cleanSource = edge.source.replace(/^ip:/, '');
  const cleanTarget = edge.target.replace(/^ip:/, '');

  const hasMetrics =
    edge.observed_packet_count !== null ||
    edge.observed_bytes !== null ||
    edge.first_seen !== null ||
    edge.last_seen !== null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Endpoints & Direction */}
      <div>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Directional Communication
        </span>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            marginTop: '0.35rem',
            fontFamily: 'var(--font-family-mono)',
            fontSize: '0.95rem',
            fontWeight: 600,
          }}
        >
          <span style={{ color: 'var(--accent-cyan)' }}>{cleanSource}</span>
          <ArrowRight size={14} color="var(--text-muted)" />
          <span style={{ color: 'var(--accent-amber)' }}>{cleanTarget}</span>
        </div>
      </div>

      {/* Action Buttons */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {onSelectCenter && (
          <>
            <button
              className="btn-secondary"
              onClick={() => onSelectCenter(cleanSource)}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
            >
              Center on Source
            </button>
            <button
              className="btn-secondary"
              onClick={() => onSelectCenter(cleanTarget)}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
            >
              Center on Target
            </button>
          </>
        )}
        {onSetPathEndpoints && (
          <button
            className="btn-primary"
            onClick={() => onSetPathEndpoints(cleanSource, cleanTarget)}
            style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
          >
            Find Shortest Path
          </button>
        )}
      </div>

      {/* Protocol & Transport Ports */}
      <div>
        <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
          Protocol & Transport Ports
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.6rem' }}>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Protocol</div>
            <div style={{ marginTop: '0.2rem' }}>
              <Tag label={edge.protocol || 'Unknown'} variant="cyan" />
            </div>
          </div>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Source Port</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)', marginTop: '0.1rem' }}>
              {edge.src_port !== null ? edge.src_port : '—'}
            </div>
          </div>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Dest Port</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--accent-emerald)', fontFamily: 'var(--font-family-mono)', marginTop: '0.1rem' }}>
              {edge.dst_port !== null ? edge.dst_port : '—'}
            </div>
          </div>
        </div>
      </div>

      {/* Traffic Volume & Measurement Metrics */}
      <div>
        <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
          Observed Volume & Time
        </h4>
        {!hasMetrics ? (
          <div className="info-banner" style={{ fontSize: '0.8rem', padding: '0.6rem 0.75rem' }}>
            Detailed packet, frame-byte, and timing metrics are unavailable for this legacy/basic communication aggregate.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' }}>
              <div className="card" style={{ padding: '0.6rem' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Observed Packets</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>
                  {formatObservedPackets(edge.observed_packet_count)}
                </div>
              </div>
              <div className="card" style={{ padding: '0.6rem' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Observed Frame Bytes</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--accent-cyan)', fontFamily: 'var(--font-family-mono)' }}>
                  {formatObservedBytes(edge.observed_bytes)}
                </div>
              </div>
            </div>

            <div className="card" style={{ padding: '0.6rem', fontSize: '0.75rem', fontFamily: 'var(--font-family-mono)', display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>First Seen: </span>
                <span style={{ color: 'var(--text-primary)' }}>{formatEpochSeconds(edge.first_seen)}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Last Seen: </span>
                <span style={{ color: 'var(--text-primary)' }}>{formatEpochSeconds(edge.last_seen)}</span>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Duration: </span>
                <span style={{ color: 'var(--text-primary)' }}>{formatObservationWindow(edge.observed_window_seconds)}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Aggregate Identity Key */}
      <div>
        <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <Shield size={13} color="var(--text-muted)" />
          <span>Deterministic Flow Identity Key</span>
        </h4>
        <div
          style={{
            padding: '0.5rem 0.65rem',
            backgroundColor: 'var(--bg-canvas)',
            borderRadius: 'var(--radius-sm)',
            border: '1px solid var(--border-subtle)',
            fontFamily: 'var(--font-family-mono)',
            fontSize: '0.72rem',
            color: edge.flow_key ? 'var(--text-primary)' : 'var(--text-muted)',
            wordBreak: 'break-all',
          }}
        >
          {edge.flow_key || 'None (Legacy basic aggregate)'}
        </div>
        <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
          Deterministic SHA-256 identity key for this directional communication aggregate.
        </p>
      </div>
    </div>
  );
};
