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
        display: 'inline-block',
        padding: '0.15rem 0.5rem',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${border}`,
        fontSize: '0.75rem',
        fontWeight: 600,
      }}
    >
      {label}
    </span>
  );
};

interface TagProps {
  label: string;
  variant?: 'cyan' | 'slate' | 'amber' | 'emerald';
}

export const Tag: React.FC<TagProps> = ({ label, variant = 'slate' }) => {
  let bg = 'rgba(100, 116, 139, 0.15)';
  let color = '#cbd5e1';
  let border = '#334155';

  if (variant === 'cyan') {
    bg = 'rgba(56, 189, 248, 0.12)';
    color = '#7dd3fc';
    border = 'rgba(56, 189, 248, 0.3)';
  } else if (variant === 'amber') {
    bg = 'rgba(245, 158, 11, 0.12)';
    color = '#fde68a';
    border = 'rgba(245, 158, 11, 0.3)';
  } else if (variant === 'emerald') {
    bg = 'rgba(16, 185, 129, 0.12)';
    color = '#6ee7b7';
    border = 'rgba(16, 185, 129, 0.3)';
  }

  return (
    <span
      style={{
        display: 'inline-block',
        padding: '0.1rem 0.45rem',
        borderRadius: 'var(--radius-sm)',
        backgroundColor: bg,
        color: color,
        border: `1px solid ${border}`,
        fontSize: '0.75rem',
        fontWeight: 500,
        fontFamily: 'var(--font-family-mono)',
      }}
    >
      {label}
    </span>
  );
};
