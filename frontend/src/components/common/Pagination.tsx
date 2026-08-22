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
        padding: '0.75rem 0',
        fontSize: '0.85rem',
        color: 'var(--text-secondary)',
        flexWrap: 'wrap',
        gap: '0.5rem',
      }}
    >
      <div>
        Showing <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{startItem}</span> to{' '}
        <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{endItem}</span> of{' '}
        <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{total}</span> {itemLabel}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <button
          className="btn-secondary"
          disabled={offset <= 0}
          onClick={() => onPageChange(Math.max(0, offset - limit))}
          style={{ padding: '0.25rem 0.6rem', fontSize: '0.8rem' }}
        >
          Previous
        </button>

        <span>
          Page {currentPage} of {totalPages}
        </span>

        <button
          className="btn-secondary"
          disabled={offset + limit >= total}
          onClick={() => onPageChange(offset + limit)}
          style={{ padding: '0.25rem 0.6rem', fontSize: '0.8rem' }}
        >
          Next
        </button>
      </div>
    </div>
  );
};
