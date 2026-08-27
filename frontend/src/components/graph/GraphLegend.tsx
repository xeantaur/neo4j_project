import React from 'react';

export const GraphLegend: React.FC = () => {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '1.1rem',
        padding: '0.4rem 0.8rem',
        backgroundColor: 'rgba(255, 255, 255, 0.94)',
        backdropFilter: 'blur(8px)',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-card)',
        boxShadow: 'var(--shadow-sm)',
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
            backgroundColor: '#ffffff',
            border: '1.5px solid #0284c7',
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
            backgroundColor: '#ffffff',
            border: '2px solid #d97706',
            borderRadius: '2px',
          }}
        />
        <span style={{ color: '#92400e', fontWeight: 600 }}>Center IP</span>
      </div>

      {/* Layer 2 Identifier */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '14px',
            height: '8px',
            backgroundColor: '#f1f5f9',
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
            backgroundColor: '#2563eb',
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
              borderLeft: '5px solid #2563eb',
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
            borderTop: '2px dashed #94a3b8',
          }}
        />
        <span className="font-mono" style={{ fontSize: '0.7rem' }}>OBSERVED_WITH</span>
      </div>
    </div>
  );
};
