import React from 'react';

interface StatusPillProps {
  label: string;
  status: 'ok' | 'ready' | 'degraded' | 'error' | 'loading';
  detail?: string;
}

export const StatusPill: React.FC<StatusPillProps> = ({ label, status, detail }) => {
  let dotColor = '#64748b';
  let textColor = '#cbd5e1';
  let bgColor = 'rgba(255, 255, 255, 0.04)';
  let borderColor = 'var(--border-subtle)';

  if (status === 'ok' || status === 'ready') {
    dotColor = '#10b981';
    textColor = '#6ee7b7';
    bgColor = 'var(--accent-emerald-dim)';
    borderColor = 'var(--accent-emerald-border)';
  } else if (status === 'degraded') {
    dotColor = '#f59e0b';
    textColor = '#fde68a';
    bgColor = 'var(--accent-amber-dim)';
    borderColor = 'var(--accent-amber-border)';
  } else if (status === 'error') {
    dotColor = '#f43f5e';
    textColor = '#fda4af';
    bgColor = 'var(--accent-rose-dim)';
    borderColor = 'var(--accent-rose-border)';
  } else if (status === 'loading') {
    dotColor = '#6366f1';
    textColor = '#c7d2fe';
    bgColor = 'var(--accent-primary-dim)';
    borderColor = 'var(--accent-primary-border)';
  }

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.45rem',
        padding: '0.2rem 0.65rem',
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
          boxShadow: status === 'ok' || status === 'ready' ? '0 0 6px rgba(16, 185, 129, 0.4)' : 'none',
        }}
      />
      <span>{label}</span>
    </div>
  );
};
