import React from 'react';
import { StatusPill } from '../common/StatusPill';

export type ActiveView = 'overview' | 'network' | 'alerts' | 'correlations' | 'path' | 'import';

interface HeaderProps {
  activeView: ActiveView;
  onViewChange: (view: ActiveView) => void;
  apiStatus: 'ok' | 'error' | 'loading';
  dbStatus: 'ready' | 'error' | 'loading';
  onRetryHealth?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeView,
  onViewChange,
  apiStatus,
  dbStatus,
  onRetryHealth,
}) => {
  const navItems: { id: ActiveView; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'network', label: 'Network Explorer' },
    { id: 'alerts', label: 'Alert Explorer' },
    { id: 'correlations', label: 'Correlations' },
    { id: 'path', label: 'Path Finder' },
    { id: 'import', label: 'Import Data' },
  ];

  return (
    <header
      style={{
        backgroundColor: 'var(--bg-surface)',
        borderBottom: '1px solid var(--border-subtle)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}
    >
      <div
        style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '0 1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '48px',
        }}
      >
        {/* Text-Only Product Identity */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <h1 style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            Network Traffic & Security Graph
          </h1>
          <span
            style={{
              fontSize: '0.7rem',
              fontWeight: 500,
              padding: '0.05rem 0.35rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: '#e5e7eb',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-family-mono)',
            }}
          >
            v1.2.1
          </span>
        </div>

        {/* Understated Health & Readiness Indicators */}
        <div
          style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', cursor: 'pointer' }}
          onClick={onRetryHealth}
          title="Click to re-verify connectivity"
        >
          <StatusPill
            label={apiStatus === 'ok' ? 'API Liveness' : apiStatus === 'loading' ? 'API Checking...' : 'API Offline'}
            status={apiStatus}
          />
          <StatusPill
            label={dbStatus === 'ready' ? 'Neo4j Connected' : dbStatus === 'loading' ? 'Neo4j Checking...' : 'Neo4j 503'}
            status={dbStatus}
          />
        </div>
      </div>

      {/* Understated Text Navigation Bar */}
      <div
        style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '0 1.5rem',
          display: 'flex',
          gap: '1.25rem',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-surface)',
          overflowX: 'auto',
        }}
      >
        {navItems.map((item) => {
          const isActive = activeView === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              style={{
                padding: '0.5rem 0',
                fontSize: '0.8rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--text-primary)' : 'var(--text-muted)',
                backgroundColor: 'transparent',
                borderBottom: isActive ? '2px solid var(--accent-primary)' : '2px solid transparent',
                borderRadius: 0,
                whiteSpace: 'nowrap',
                transition: 'color 0.12s ease',
              }}
            >
              {item.label}
            </button>
          );
        })}
      </div>
    </header>
  );
};
