import React from 'react';

interface Layer2DetailPanelProps {
  identifier: string;
}

export const Layer2DetailPanel: React.FC<Layer2DetailPanelProps> = ({ identifier }) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      <div>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          Observed Layer 2 Identifier
        </span>
        <div style={{ fontSize: '1.15rem', fontWeight: 600, fontFamily: 'var(--font-family-mono)', color: '#cbd5e1', wordBreak: 'break-all' }}>
          {identifier}
        </div>
      </div>

      <div className="card" style={{ padding: '0.9rem' }}>
        <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.4rem' }}>
          Entity Classification
        </h4>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
          This node represents an observed Layer 2 identifier (such as an interface MAC address or resolved local name like a gateway or broadcast tag) co-observed with IP endpoints in the captured network traffic.
        </p>
      </div>

      <div className="info-banner" style={{ fontSize: '0.8rem' }}>
        ℹ Layer 2 identifiers participate in <code className="font-mono">OBSERVED_WITH</code> and <code className="font-mono">L2_COMMUNICATED_TO</code> relationships in the graph.
      </div>
    </div>
  );
};
