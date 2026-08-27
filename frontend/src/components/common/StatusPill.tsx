import React from 'react';

interface StatusPillProps {
  label: string;
  status: 'ok' | 'ready' | 'degraded' | 'error' | 'loading';
  detail?: string;
}

export const StatusPill: React.FC<StatusPillProps> = ({ label, status, detail }) => {
  let dotColor = '#9ca3af';

  if (status === 'ok' || status === 'ready') {
    dotColor = '#059669';
  } else if (status === 'degraded') {
    dotColor = '#d97706';
  } else if (status === 'error') {
    dotColor = '#dc2626';
  } else if (status === 'loading') {
    dotColor = '#2563eb';
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        fontSize: '0.75rem',
        fontWeight: 500,
        color: 'var(--text-secondary)',
      }}
      title={detail || label}
    >
      <span
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          backgroundColor: dotColor,
          flexShrink: 0,
        }}
      />
      <span>{label}</span>
    </div>
  );
};
