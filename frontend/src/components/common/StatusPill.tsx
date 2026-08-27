import React from 'react';

interface StatusPillProps {
  label: string;
  status: 'ok' | 'ready' | 'degraded' | 'error' | 'loading';
  detail?: string;
}

export const StatusPill: React.FC<StatusPillProps> = ({ label, status, detail }) => {
  let dotColor = '#64748b';
  let textColor = '#334155';
  let bgColor = '#f8fafc';
  let borderColor = '#e2e8f0';

  if (status === 'ok' || status === 'ready') {
    dotColor = '#059669';
    textColor = '#065f46';
    bgColor = '#ecfdf5';
    borderColor = '#a7f3d0';
  } else if (status === 'degraded') {
    dotColor = '#d97706';
    textColor = '#92400e';
    bgColor = '#fffbeb';
    borderColor = '#fde68a';
  } else if (status === 'error') {
    dotColor = '#dc2626';
    textColor = '#991b1b';
    bgColor = '#fef2f2';
    borderColor = '#fecaca';
  } else if (status === 'loading') {
    dotColor = '#2563eb';
    textColor = '#1e40af';
    bgColor = '#eff6ff';
    borderColor = '#bfdbfe';
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.4rem',
        padding: '0.18rem 0.55rem',
        borderRadius: 'var(--radius-full)',
        backgroundColor: bgColor,
        border: `1px solid ${borderColor}`,
        fontSize: '0.72rem',
        fontWeight: 500,
        color: textColor,
        letterSpacing: '0.01em',
        transition: 'all 0.15s ease',
      }}
      title={detail || label}
    >
      <span
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          backgroundColor: dotColor,
        }}
      />
      <span>{label}</span>
    </div>
  );
};
