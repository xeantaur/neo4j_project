import React from 'react';

export const GraphLegend: React.FC = () => {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1.25rem',
        padding: '0.5rem 0.75rem',
        backgroundColor: 'rgba(17, 24, 39, 0.85)',
        backdropFilter: 'blur(4px)',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-subtle)',
        fontSize: '0.75rem',
        color: 'var(--text-secondary)',
        flexWrap: 'wrap',
      }}
    >
      {/* IP Address */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '12px',
            height: '10px',
            backgroundColor: '#111827',
            border: '1.5px solid #38bdf8',
            borderRadius: '2px',
          }}
        />
        <span>IP Address</span>
      </div>

      {/* Center IP */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '12px',
            height: '10px',
            backgroundColor: '#111827',
            border: '2px solid #f59e0b',
            borderRadius: '2px',
          }}
        />
        <span>Center IP</span>
      </div>

      {/* Layer 2 Identifier */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '14px',
            height: '8px',
            backgroundColor: '#1e293b',
            border: '1.5px solid #94a3b8',
            borderRadius: '9999px',
          }}
        />
        <span>Layer 2 Identifier</span>
      </div>

      {/* COMMUNICATED_TO */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '18px',
            height: '2px',
            backgroundColor: '#0284c7',
            position: 'relative',
          }}
        >
          <span
            style={{
              position: 'absolute',
              right: 0,
              top: '-3px',
              width: 0,
              height: 0,
              borderTop: '4px solid transparent',
              borderBottom: '4px solid transparent',
              borderLeft: '5px solid #0284c7',
            }}
          />
        </span>
        <span>COMMUNICATED_TO</span>
      </div>

      {/* OBSERVED_WITH */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '18px',
            height: '0',
            borderTop: '2px dashed #64748b',
          }}
        />
        <span>OBSERVED_WITH</span>
      </div>
    </div>
  );
};
