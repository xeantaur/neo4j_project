import React from 'react';
import { Network, AlertTriangle, GitCompare, Route, Activity, Upload } from 'lucide-react';
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
    { id: 'overview', label: 'Overview', icon: <Activity size={14} /> },
    { id: 'network', label: 'Network Explorer', icon: <Network size={14} /> },
    { id: 'alerts', label: 'Alert Explorer', icon: <AlertTriangle size={14} /> },
    { id: 'correlations', label: 'Correlations', icon: <GitCompare size={14} /> },
    { id: 'path', label: 'Path Finder', icon: <Route size={14} /> },
    { id: 'import', label: 'Import Data', icon: <Upload size={14} /> },
  ];

  return (
    <header
      style={{
        backgroundColor: '#ffffff',
        borderBottom: '1px solid var(--border-card)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        boxShadow: '0 1px 3px 0 rgba(0, 0, 0, 0.04)',
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
          height: '52px',
        }}
      >
        {/* Professional Product Brand Mark */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '30px',
              height: '30px',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--accent-primary)',
              color: '#ffffff',
              boxShadow: 'var(--shadow-sm)',
            }}
          >
            {/* Minimalist Abstract Graph Geometric Mark */}
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="6" cy="6" r="3" />
              <circle cx="18" cy="6" r="3" />
              <circle cx="12" cy="18" r="3" />
              <line x1="8.5" y1="7.5" x2="15.5" y2="7.5" />
              <line x1="7.5" y1="8.5" x2="10.5" y2="15.5" />
              <line x1="16.5" y1="8.5" x2="13.5" y2="15.5" />
            </svg>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.4rem' }}>
              <span style={{ fontSize: '1rem', fontWeight: 700, letterSpacing: '-0.03em', color: 'var(--text-primary)' }}>
                GraphSec
              </span>
              <span style={{ fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-muted)' }}>
                Analytics
              </span>
            </div>
            <span style={{ color: 'var(--border-hover)', fontSize: '0.85rem' }}>|</span>
            <h1 style={{ fontSize: '0.82rem', fontWeight: 500, color: 'var(--text-secondary)', letterSpacing: '0.01em' }}>
              Network Traffic & Security Graph
            </h1>
            <span
              style={{
                fontSize: '0.68rem',
                fontWeight: 600,
                padding: '0.1rem 0.35rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: '#f1f5f9',
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
          style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}
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
          gap: '0.25rem',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: '#ffffff',
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
                gap: '0.4rem',
                padding: '0.5rem 0.8rem',
                fontSize: '0.78rem',
                fontWeight: isActive ? 600 : 500,
                color: isActive ? 'var(--accent-primary)' : 'var(--text-secondary)',
                backgroundColor: isActive ? 'var(--accent-primary-dim)' : 'transparent',
                borderBottom: isActive ? '2px solid var(--accent-primary)' : '2px solid transparent',
                borderRadius: 'var(--radius-sm) var(--radius-sm) 0 0',
                whiteSpace: 'nowrap',
                transition: 'all 0.12s ease',
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
