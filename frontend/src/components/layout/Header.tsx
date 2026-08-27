import React from 'react';
import { Shield, Network, AlertTriangle, GitCompare, Route, Activity, Upload } from 'lucide-react';
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
  const navItems: { id: ActiveView; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: 'Overview', icon: <Activity size={15} /> },
    { id: 'network', label: 'Network Explorer', icon: <Network size={15} /> },
    { id: 'alerts', label: 'Alert Explorer', icon: <AlertTriangle size={15} /> },
    { id: 'correlations', label: 'Correlations', icon: <GitCompare size={15} /> },
    { id: 'path', label: 'Path Finder', icon: <Route size={15} /> },
    { id: 'import', label: 'Import Data', icon: <Upload size={15} /> },
  ];

  return (
    <header
      style={{
        backgroundColor: 'var(--bg-card)',
        borderBottom: '1px solid var(--border-card)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        boxShadow: '0 2px 8px rgba(0, 0, 0, 0.4)',
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
          height: '54px',
        }}
      >
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '32px',
              height: '32px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-primary-dim)',
              color: 'var(--accent-primary)',
              border: '1px solid var(--accent-primary-border)',
            }}
          >
            <Shield size={17} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <h1 style={{ fontSize: '0.95rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
              Network Traffic & Security Graph
            </h1>
            <span
              style={{
                fontSize: '0.68rem',
                fontWeight: 600,
                padding: '0.1rem 0.4rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                color: 'var(--text-muted)',
                border: '1px solid var(--border-subtle)',
                fontFamily: 'var(--font-family-mono)',
              }}
            >
              v1.2.1
            </span>
          </div>
        </div>

        {/* System Health / Readiness Pills */}
        <div
          style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', cursor: 'pointer' }}
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

      {/* Navigation Tabs Bar */}
      <div
        style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '0 1.25rem',
          display: 'flex',
          gap: '0.35rem',
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
                display: 'flex',
                alignItems: 'center',
                gap: '0.45rem',
                padding: '0.55rem 0.85rem',
                fontSize: '0.8rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                backgroundColor: isActive ? 'var(--accent-primary-dim)' : 'transparent',
                borderBottom: isActive ? '2px solid var(--accent-primary)' : '2px solid transparent',
                borderRadius: 'var(--radius-sm) var(--radius-sm) 0 0',
                whiteSpace: 'nowrap',
                transition: 'all 0.15s ease',
              }}
            >
              <span style={{ color: isActive ? 'var(--accent-primary)' : 'var(--text-muted)' }}>
                {item.icon}
              </span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
