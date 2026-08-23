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
    { id: 'overview', label: 'Overview', icon: <Activity size={16} /> },
    { id: 'network', label: 'Network Explorer', icon: <Network size={16} /> },
    { id: 'alerts', label: 'Alert Explorer', icon: <AlertTriangle size={16} /> },
    { id: 'correlations', label: 'Correlations', icon: <GitCompare size={16} /> },
    { id: 'path', label: 'Path Finder', icon: <Route size={16} /> },
    { id: 'import', label: 'Import Data', icon: <Upload size={16} /> },
  ];

  return (
    <header
      style={{
        backgroundColor: 'var(--bg-card)',
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
          padding: '0 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '56px',
        }}
      >
        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '32px',
              height: '32px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-cyan-dim)',
              color: 'var(--accent-cyan)',
              border: '1px solid rgba(56, 189, 248, 0.3)',
            }}
          >
            <Shield size={18} />
          </div>
          <div>
            <h1 style={{ fontSize: '1rem', fontWeight: 600, letterSpacing: '-0.01em' }}>
              Network Traffic & Security Graph
            </h1>
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

      {/* Navigation Tabs */}
      <div
        style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '0 1.25rem',
          display: 'flex',
          gap: '0.25rem',
          borderTop: '1px solid var(--border-subtle)',
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
                gap: '0.5rem',
                padding: '0.65rem 1rem',
                fontSize: '0.85rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                borderBottom: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                borderRadius: 0,
                whiteSpace: 'nowrap',
                transition: 'all 0.15s ease',
              }}
            >
              {item.icon}
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
