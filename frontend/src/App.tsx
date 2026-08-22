import React, { useState, useEffect, useCallback } from 'react';
import { getHealth, getReady } from './api/system';
import { Header } from './components/layout/Header';
import type { ActiveView } from './components/layout/Header';
import { OverviewPage } from './pages/OverviewPage';
import { NetworkExplorerPage } from './pages/NetworkExplorerPage';
import { AlertExplorerPage } from './pages/AlertExplorerPage';
import { CorrelationsPage } from './pages/CorrelationsPage';
import { PathFinderPage } from './pages/PathFinderPage';

export const App: React.FC = () => {
  const [activeView, setActiveView] = useState<ActiveView>('overview');

  // System status
  const [apiStatus, setApiStatus] = useState<'ok' | 'error' | 'loading'>('loading');
  const [dbStatus, setDbStatus] = useState<'ready' | 'error' | 'loading'>('loading');

  // Cross-view investigation context
  const [centerIp, setCenterIp] = useState<string | null>(null);
  const [pathSourceIp, setPathSourceIp] = useState<string | null>(null);
  const [pathTargetIp, setPathTargetIp] = useState<string | null>(null);

  // Check system health and readiness
  const checkHealth = useCallback(() => {
    getHealth()
      .then((res) => {
        setApiStatus(res.status === 'ok' ? 'ok' : 'error');
      })
      .catch(() => {
        setApiStatus('error');
      });

    getReady()
      .then((res) => {
        setDbStatus(res.status === 'ready' && res.database === 'connected' ? 'ready' : 'error');
      })
      .catch(() => {
        setDbStatus('error');
      });
  }, []);

  useEffect(() => {
    checkHealth();
    // Conservative check every 60 seconds
    const interval = setInterval(checkHealth, 60000);
    return () => clearInterval(interval);
  }, [checkHealth]);

  // Unified navigation handler
  const handleNavigate = (
    view: ActiveView,
    context?: { centerIp?: string; sourceIp?: string; targetIp?: string }
  ) => {
    if (context?.centerIp) setCenterIp(context.centerIp);
    if (context?.sourceIp) setPathSourceIp(context.sourceIp);
    if (context?.targetIp) setPathTargetIp(context.targetIp);
    setActiveView(view);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', backgroundColor: 'var(--bg-app)' }}>
      <Header
        activeView={activeView}
        onViewChange={setActiveView}
        apiStatus={apiStatus}
        dbStatus={dbStatus}
        onRetryHealth={checkHealth}
      />

      {/* Database Offline Warning Banner */}
      {dbStatus === 'error' && (
        <div
          className="warning-banner"
          style={{
            margin: '0.75rem 1.25rem 0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            ⚠️ <strong>Neo4j Database Unavailable (HTTP 503):</strong> The FastAPI backend is running, but the Neo4j instance is unreachable or unconfigured. Queries will fail until Neo4j is available.
          </div>
          <button
            className="btn-secondary"
            onClick={checkHealth}
            style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
          >
            Retry Connection
          </button>
        </div>
      )}

      {/* Main Content Area */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        {activeView === 'overview' && <OverviewPage onNavigate={handleNavigate} />}
        {activeView === 'network' && (
          <NetworkExplorerPage
            initialCenterIp={centerIp}
            onNavigate={handleNavigate}
          />
        )}
        {activeView === 'alerts' && <AlertExplorerPage onNavigate={handleNavigate} />}
        {activeView === 'correlations' && <CorrelationsPage onNavigate={handleNavigate} />}
        {activeView === 'path' && (
          <PathFinderPage
            initialSourceIp={pathSourceIp}
            initialTargetIp={pathTargetIp}
            onNavigate={handleNavigate}
          />
        )}
      </main>

      {/* Footer */}
      <footer
        style={{
          padding: '1rem 1.25rem',
          borderTop: '1px solid var(--border-subtle)',
          backgroundColor: 'var(--bg-card)',
          color: 'var(--text-muted)',
          fontSize: '0.75rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}
      >
        <div>
          <span>Network Traffic & Security Alert Analysis</span> — Modernized Portfolio Project
        </div>
        <div style={{ display: 'flex', gap: '1rem' }}>
          <span>Neo4j 5.x Graph Model</span>
          <span>•</span>
          <span>FastAPI Backend</span>
          <span>•</span>
          <span>React + Cytoscape.js Frontend</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
