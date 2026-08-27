import React from 'react';

interface PriorityBadgeProps {
  priority: number | null;
}

export const PriorityBadge: React.FC<PriorityBadgeProps> = ({ priority }) => {
  let label = 'Unknown';
  let className = 'badge-priority-unknown';
  let bg = 'var(--priority-unknown-bg)';
  let color = 'var(--priority-unknown-text)';
  let border = 'var(--priority-unknown-border)';

  if (priority === 1) {
    label = 'Priority 1';
    className = 'badge-priority-1';
    bg = 'var(--priority-1-bg)';
    color = 'var(--priority-1-text)';
    border = 'var(--priority-1-border)';
  } else if (priority === 2) {
    label = 'Priority 2';
    className = 'badge-priority-2';
    bg = 'var(--priority-2-bg)';
    color = 'var(--priority-2-text)';
    border = 'var(--priority-2-border)';
  } else if (priority === 3) {
    label = 'Priority 3';
    className = 'badge-priority-3';
    bg = 'var(--priority-3-bg)';
    color = 'var(--priority-3-text)';
    border = 'var(--priority-3-border)';
  } else if (priority !== null) {
    label = `Priority ${priority}`;
  }

  return (
    <span
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.15rem 0.5rem',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${border}`,
        fontSize: '0.72rem',
        fontWeight: 600,
        letterSpacing: '0.02em',
      }}
    >
      {label}
    </span>
  );
};

interface TagProps {
  label: string;
  variant?: 'cyan' | 'slate' | 'amber' | 'emerald' | 'indigo' | 'rose';
}

export const Tag: React.FC<TagProps> = ({ label, variant = 'slate' }) => {
  let bg = 'rgba(255, 255, 255, 0.05)';
  let color = 'var(--text-secondary)';
  let border = 'var(--border-subtle)';

  if (variant === 'cyan') {
    bg = 'var(--accent-cyan-dim)';
    color = '#7dd3fc';
    border = 'var(--accent-cyan-border)';
  } else if (variant === 'amber') {
    bg = 'var(--accent-amber-dim)';
    color = '#fde68a';
    border = 'var(--accent-amber-border)';
  } else if (variant === 'emerald') {
    bg = 'var(--accent-emerald-dim)';
    color = '#6ee7b7';
    border = 'var(--accent-emerald-border)';
  } else if (variant === 'indigo') {
    bg = 'var(--accent-primary-dim)';
    color = '#a5b4fc';
    border = 'var(--accent-primary-border)';
  } else if (variant === 'rose') {
    bg = 'var(--accent-rose-dim)';
    color = '#fda4af';
    border = 'var(--accent-rose-border)';
  }

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0.12rem 0.45rem',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${border}`,
        fontSize: '0.72rem',
        fontWeight: 500,
        fontFamily: 'var(--font-family-mono)',
        lineHeight: 1.3,
      }}
    >
      {label}
    </span>
  );
};
