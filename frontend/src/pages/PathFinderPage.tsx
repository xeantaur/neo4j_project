import React, { useState, useEffect } from 'react';
import { getShortestPath } from '../api/graph';
import type { PathResponse } from '../api/types';
import { Tag } from '../components/common/Badge';
import { Skeleton } from '../components/common/Skeleton';
import type { ActiveView } from '../components/layout/Header';
import { Route, ArrowRight, Network } from 'lucide-react';

interface PathFinderPageProps {
  initialSourceIp?: string | null;
  initialTargetIp?: string | null;
  onNavigate?: (view: ActiveView, context?: { centerIp?: string }) => void;
}

export const PathFinderPage: React.FC<PathFinderPageProps> = ({
  initialSourceIp,
  initialTargetIp,
  onNavigate,
}) => {
  const [source, setSource] = useState<string>(initialSourceIp || '');
  const [target, setTarget] = useState<string>(initialTargetIp || '');
  const [maxHops, setMaxHops] = useState<number>(5);

  const [pathResult, setPathResult] = useState<PathResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialSourceIp) setSource(initialSourceIp);
    if (initialTargetIp) setTarget(initialTargetIp);
  }, [initialSourceIp, initialTargetIp]);

  const handleSearchPath = (e: React.FormEvent) => {
    e.preventDefault();
    if (!source.trim() || !target.trim()) {
      setError('Please provide both Source and Destination IP addresses.');
      return;
    }

    setLoading(true);
    setError(null);
    setPathResult(null);

    getShortestPath(source.trim(), target.trim(), maxHops)
      .then((res) => {
        setPathResult(res);
        setLoading(false);
      })
      .catch((err: Error) => {
        setError(err.message || 'Failed to calculate communication path');
        setLoading(false);
      });
  };

  return (
    <div style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '1.75rem 2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Communication Path Finder
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.2rem' }}>
          Discover the shortest directional Layer 3 communication path connecting two observed endpoints.
        </p>
      </div>

      <div className="info-banner">
        <span>ℹ</span>
        <div>
          <strong>Reachability Notice:</strong> Calculated paths trace directional <code className="font-mono" style={{ backgroundColor: '#dbeafe', color: '#1e40af', padding: '0.1rem 0.35rem', borderRadius: 'var(--radius-sm)' }}>COMMUNICATED_TO</code> relationships in the graph. This reflects observed communication flows in captured traffic rather than real-time packet routing or traceroute paths.
        </div>
      </div>

      {/* Query Form */}
      <form onSubmit={handleSearchPath} className="card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', alignItems: 'flex-end' }}>
          <div>
            <label htmlFor="source-ip" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 500 }}>
              Origin Source IP
            </label>
            <input
              id="source-ip"
              type="text"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              placeholder="e.g. 192.168.1.100"
              style={{ width: '100%', fontFamily: 'var(--font-family-mono)', fontSize: '0.825rem', padding: '0.38rem 0.65rem' }}
            />
          </div>

          <div>
            <label htmlFor="target-ip" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 500 }}>
              Destination Target IP
            </label>
            <input
              id="target-ip"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g. 10.0.0.5"
              style={{ width: '100%', fontFamily: 'var(--font-family-mono)', fontSize: '0.825rem', padding: '0.38rem 0.65rem' }}
            />
          </div>

          <div>
            <label htmlFor="max-hops" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.35rem', fontWeight: 500 }}>
              Max Search Depth (Hops: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>{maxHops}</strong>)
            </label>
            <input
              id="max-hops"
              type="range"
              min="1"
              max="10"
              value={maxHops}
              onChange={(e) => setMaxHops(Number(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent-primary)' }}
            />
          </div>

          <div>
            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
              style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.45rem', fontSize: '0.825rem', padding: '0.42rem 0.85rem' }}
            >
              <Route size={15} />
              <span>{loading ? 'Finding Path...' : 'Find Path'}</span>
            </button>
          </div>
        </div>
      </form>

      {/* Error Message */}
      {error && (
        <div className="warning-banner" style={{ borderLeftColor: 'var(--accent-rose)', color: 'var(--accent-rose)' }}>
          <strong>Path Query Result:</strong>
          <div style={{ marginTop: '0.25rem' }}>{error}</div>
        </div>
      )}

      {/* Loading Skeleton */}
      {loading && (
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem', padding: '1.5rem' }}>
          <Skeleton height="24px" width="40%" />
          <Skeleton height="60px" width="100%" />
          <Skeleton height="80px" width="100%" />
        </div>
      )}

      {/* Path Results */}
      {pathResult && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div className="card" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem' }}>
              <div>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Observed Communication Path
                </span>
                <h3 style={{ fontSize: '1.1rem', color: 'var(--accent-cyan)' }}>
                  {pathResult.length} {pathResult.length === 1 ? 'Hop' : 'Hops'} from {pathResult.source} to {pathResult.target}
                </h3>
              </div>
            </div>

            {/* Horizontal Node-Link Chain Visualizer */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                overflowX: 'auto',
                padding: '1rem 0.5rem',
                backgroundColor: 'var(--bg-app)',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {pathResult.hops.map((hopIp, index) => {
                const isSource = index === 0;
                const isTarget = index === pathResult.hops.length - 1;
                const protocol = index < pathResult.protocols.length ? pathResult.protocols[index] : null;

                return (
                  <React.Fragment key={`${hopIp}-${index}`}>
                    {/* Node Card */}
                    <div
                      style={{
                        padding: '0.6rem 0.9rem',
                        backgroundColor: 'var(--bg-card)',
                        border: `1.5px solid ${isSource ? 'var(--accent-cyan)' : isTarget ? 'var(--accent-amber)' : 'var(--border-card)'}`,
                        borderRadius: 'var(--radius-sm)',
                        display: 'flex',
                        flexDirection: 'column',
                        alignItems: 'center',
                        gap: '0.2rem',
                        minWidth: '130px',
                      }}
                    >
                      <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                        {isSource ? 'Origin' : isTarget ? 'Destination' : `Hop ${index}`}
                      </span>
                      <span className="font-mono" style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                        {hopIp}
                      </span>
                      {onNavigate && (
                        <button
                          className="btn-secondary"
                          onClick={() => onNavigate('network', { centerIp: hopIp })}
                          style={{ fontSize: '0.7rem', padding: '0.1rem 0.35rem', marginTop: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                          title="Inspect in graph"
                        >
                          <Network size={10} />
                          <span>Inspect</span>
                        </button>
                      )}
                    </div>

                    {/* Edge Arrow with Protocol */}
                    {index < pathResult.hops.length - 1 && (
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.2rem', minWidth: '70px' }}>
                        {protocol && <Tag label={protocol} variant="cyan" />}
                        <div style={{ display: 'flex', alignItems: 'center', color: 'var(--accent-cyan)' }}>
                          <div style={{ width: '40px', height: '2px', backgroundColor: 'var(--accent-cyan)' }} />
                          <ArrowRight size={14} style={{ marginLeft: '-4px' }} />
                        </div>
                      </div>
                    )}
                  </React.Fragment>
                );
              })}
            </div>
          </div>

          {/* Hop-by-hop Detailed Breakdown */}
          <div className="card" style={{ padding: '1.25rem' }}>
            <h4 style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.75rem' }}>
              Step-by-Step Hop Sequence
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {pathResult.hops.slice(0, -1).map((hopSrc, i) => {
                const hopDst = pathResult.hops[i + 1];
                const proto = pathResult.protocols[i] || 'Unknown';
                return (
                  <div
                    key={i}
                    style={{
                      padding: '0.6rem 0.8rem',
                      backgroundColor: 'var(--bg-app)',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      fontSize: '0.85rem',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                      <span style={{ color: 'var(--text-muted)', fontWeight: 600 }}>Step {i + 1}:</span>
                      <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{hopSrc}</span>
                      <span style={{ color: 'var(--text-muted)' }}>➔</span>
                      <span className="font-mono" style={{ color: 'var(--accent-amber)' }}>{hopDst}</span>
                    </div>
                    <div>
                      <Tag label={`Protocol: ${proto}`} variant="slate" />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
