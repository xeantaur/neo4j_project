import React from 'react';

export const GraphLegend: React.FC = () => {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1.1rem',
        padding: '0.45rem 0.85rem',
        backgroundColor: 'rgba(17, 23, 34, 0.88)',
        backdropFilter: 'blur(8px)',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-card)',
        boxShadow: 'var(--shadow-md)',
        fontSize: '0.72rem',
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
            backgroundColor: '#111722',
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
            backgroundColor: '#151c28',
            border: '2px solid #f59e0b',
            borderRadius: '2px',
          }}
        />
        <span style={{ color: '#fde68a', fontWeight: 500 }}>Center IP</span>
      </div>

      {/* Layer 2 Identifier */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '14px',
            height: '8px',
            backgroundColor: '#151c28',
            border: '1.5px solid #64748b',
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
        <span className="font-mono" style={{ fontSize: '0.7rem' }}>COMMUNICATED_TO</span>
      </div>

      {/* OBSERVED_WITH */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '18px',
            height: '0',
            borderTop: '2px dashed #475569',
          }}
        />
        <span className="font-mono" style={{ fontSize: '0.7rem' }}>OBSERVED_WITH</span>
      </div>
    </div>
  );
};
