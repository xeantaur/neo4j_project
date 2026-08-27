import React from 'react';

interface PaginationProps {
  offset: number;
  limit: number;
  total: number;
  onPageChange: (newOffset: number) => void;
  itemLabel?: string;
}

export const Pagination: React.FC<PaginationProps> = ({
  offset,
  limit,
  total,
  onPageChange,
  itemLabel = 'records',
}) => {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const startItem = total === 0 ? 0 : offset + 1;
  const endItem = Math.min(offset + limit, total);

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0.6rem 0.2rem',
        fontSize: '0.8rem',
        color: 'var(--text-secondary)',
        flexWrap: 'wrap',
        gap: '0.5rem',
      }}
    >
      <div>
        Showing <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'var(--font-family-mono)' }}>{startItem}</span> to{' '}
        <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'var(--font-family-mono)' }}>{endItem}</span> of{' '}
        <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontFamily: 'var(--font-family-mono)' }}>{total}</span> {itemLabel}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
        <button
          className="btn-secondary"
          disabled={offset <= 0}
          onClick={() => onPageChange(Math.max(0, offset - limit))}
          style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
        >
          Previous
        </button>

        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
          Page <strong style={{ color: 'var(--text-primary)' }}>{currentPage}</strong> of <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong>
        </span>

        <button
          className="btn-secondary"
          disabled={offset + limit >= total}
          onClick={() => onPageChange(offset + limit)}
          style={{ padding: '0.25rem 0.65rem', fontSize: '0.75rem' }}
        >
          Next
        </button>
      </div>
    </div>
  );
};
