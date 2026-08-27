import React from 'react';

interface StatusPillProps {
  label: string;
  status: 'ok' | 'ready' | 'degraded' | 'error' | 'loading';
  detail?: string;
  onDark?: boolean;
}

export const StatusPill: React.FC<StatusPillProps> = ({ label, status, detail, onDark = false }) => {
  let dotColor = '#9ca3af';

  if (status === 'ok' || status === 'ready') {
    dotColor = '#10b981';
  } else if (status === 'degraded') {
    dotColor = '#f59e0b';
  } else if (status === 'error') {
    dotColor = '#ef4444';
  } else if (status === 'loading') {
    dotColor = '#3b82f6';
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        fontSize: '0.78rem',
        fontWeight: 500,
        color: onDark ? '#d1d5db' : 'var(--text-secondary)',
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
