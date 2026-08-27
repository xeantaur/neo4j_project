import React, { useState, useEffect, useCallback } from 'react';
import { getHealth, getReady } from './api/system';
import { Header } from './components/layout/Header';
import type { ActiveView } from './components/layout/Header';
import { OverviewPage } from './pages/OverviewPage';
import { NetworkExplorerPage } from './pages/NetworkExplorerPage';
import { AlertExplorerPage } from './pages/AlertExplorerPage';
import { CorrelationsPage } from './pages/CorrelationsPage';
import { PathFinderPage } from './pages/PathFinderPage';
import { ImportDataPage } from './pages/ImportDataPage';

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

  // Clear cross-view investigation context upon successful workspace replacement
  const handleImportSuccess = () => {
    setCenterIp(null);
    setPathSourceIp(null);
    setPathTargetIp(null);
  };

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
            margin: '0.85rem 1.5rem 0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '1rem',
          }}
        >
          <div>
            <strong>Neo4j Database Unavailable (HTTP 503):</strong> The FastAPI backend is running, but the Neo4j instance is unreachable or unconfigured. Queries will fail until Neo4j is available.
          </div>
          <button
            className="btn-secondary"
            onClick={checkHealth}
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem', flexShrink: 0 }}
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
        {activeView === 'import' && (
          <ImportDataPage
            onNavigate={handleNavigate}
            onImportSuccess={handleImportSuccess}
          />
        )}
      </main>

      {/* Enterprise SaaS Footer */}
      <footer
        style={{
          padding: '0.85rem 1.5rem',
          borderTop: '1px solid var(--border-card)',
          backgroundColor: 'var(--bg-card)',
          color: 'var(--text-muted)',
          fontSize: '0.75rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>GraphSec Analytics Platform</span>
          <span>—</span>
          <span>Cybersecurity Traffic & IDS Relationship Engine</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontFamily: 'var(--font-family-mono)', fontSize: '0.72rem' }}>
          <span>Neo4j 5.x Graph</span>
          <span style={{ opacity: 0.3 }}>•</span>
          <span>FastAPI Service</span>
          <span style={{ opacity: 0.3 }}>•</span>
          <span>React 19 + Cytoscape.js</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
