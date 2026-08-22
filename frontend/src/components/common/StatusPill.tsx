import React from 'react';

interface StatusPillProps {
  label: string;
  status: 'ok' | 'ready' | 'degraded' | 'error' | 'loading';
  detail?: string;
}

export const StatusPill: React.FC<StatusPillProps> = ({ label, status, detail }) => {
  let dotColor = '#64748b';
  let textColor = '#cbd5e1';
  let bgColor = 'rgba(100, 116, 139, 0.15)';
  let borderColor = '#334155';

  if (status === 'ok' || status === 'ready') {
    dotColor = '#10b981';
    textColor = '#6ee7b7';
    bgColor = 'rgba(16, 185, 129, 0.12)';
    borderColor = 'rgba(16, 185, 129, 0.3)';
  } else if (status === 'degraded') {
    dotColor = '#f59e0b';
    textColor = '#fde68a';
    bgColor = 'rgba(245, 158, 11, 0.12)';
    borderColor = 'rgba(245, 158, 11, 0.3)';
  } else if (status === 'error') {
    dotColor = '#f43f5e';
    textColor = '#fda4af';
    bgColor = 'rgba(244, 63, 94, 0.12)';
    borderColor = 'rgba(244, 63, 94, 0.3)';
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.4rem',
        padding: '0.2rem 0.6rem',
        borderRadius: '9999px',
        backgroundColor: bgColor,
        border: `1px solid ${borderColor}`,
        fontSize: '0.75rem',
        fontWeight: 500,
        color: textColor,
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
