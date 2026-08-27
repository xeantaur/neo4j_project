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
            border: '1.5px solid #94a3b8',
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
            backgroundColor: '#eff6ff',
            border: '1.5px solid #2563eb',
            borderRadius: '2px',
          }}
        />
        <span style={{ color: '#1e40af', fontWeight: 600 }}>Center IP</span>
      </div>

      {/* Layer 2 Identifier */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <span
          style={{
            display: 'inline-block',
            width: '14px',
            height: '8px',
            backgroundColor: '#f3f4f6',
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
            backgroundColor: '#64748b',
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
              borderLeft: '5px solid #64748b',
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
            borderTop: '2px dashed #cbd5e1',
          }}
        />
        <span className="font-mono" style={{ fontSize: '0.7rem' }}>OBSERVED_WITH</span>
      </div>
    </div>
  );
};
