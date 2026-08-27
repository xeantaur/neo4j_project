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
        backgroundColor: '#171a1f',
        borderBottom: '1px solid #0f1115',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}
    >
      {/* Top Application Bar */}
      <div
        style={{
          maxWidth: '1440px',
          margin: '0 auto',
          padding: '0 2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '46px',
        }}
      >
        {/* Text-Only Product Identity */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <h1 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#f9fafb', letterSpacing: '-0.01em' }}>
            Network Traffic & Security Graph
          </h1>
          <span
            style={{
              fontSize: '0.72rem',
              fontWeight: 500,
              padding: '0.1rem 0.4rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'rgba(255, 255, 255, 0.08)',
              color: '#9ca3af',
              border: '1px solid rgba(255, 255, 255, 0.12)',
              fontFamily: 'var(--font-family-mono)',
            }}
          >
            v1.2.1
          </span>
        </div>

        {/* Understated Status Indicators */}
        <div
          style={{ display: 'flex', alignItems: 'center', gap: '1rem', cursor: 'pointer' }}
          onClick={onRetryHealth}
          title="Click to re-verify connectivity"
        >
          <StatusPill
            label={apiStatus === 'ok' ? 'API Liveness' : apiStatus === 'loading' ? 'API Checking...' : 'API Offline'}
            status={apiStatus}
            onDark
          />
          <StatusPill
            label={dbStatus === 'ready' ? 'Neo4j Connected' : dbStatus === 'loading' ? 'Neo4j Checking...' : 'Neo4j 503'}
            status={dbStatus}
            onDark
          />
        </div>
      </div>

      {/* Navigation Bar */}
      <div
        style={{
          maxWidth: '1440px',
          margin: '0 auto',
          padding: '0 2rem',
          display: 'flex',
          gap: '1.5rem',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          backgroundColor: '#171a1f',
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
                padding: '0.55rem 0',
                fontSize: '0.85rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? '#ffffff' : '#9ca3af',
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
