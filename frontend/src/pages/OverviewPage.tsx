import React, { useEffect, useState } from 'react';
import { listIPs, listLayer2, listCommunications } from '../api/network';
import { listAlertFacts } from '../api/alerts';
import { listTrafficAlertCorrelations } from '../api/correlations';
import type { ActiveView } from '../components/layout/Header';
import { Skeleton } from '../components/common/Skeleton';
import { Network, AlertTriangle, GitCompare, Route, Database, Shield } from 'lucide-react';

interface OverviewPageProps {
  onNavigate: (view: ActiveView, context?: { centerIp?: string; sourceIp?: string; targetIp?: string }) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ onNavigate }) => {
  const [ipCount, setIpCount] = useState<number | null>(null);
  const [l2Count, setL2Count] = useState<number | null>(null);
  const [alertCount, setAlertCount] = useState<number | null>(null);
  const [commCount, setCommCount] = useState<number | null>(null);
  const [corrCount, setCorrCount] = useState<number | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isCancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      listIPs(1, 0).then((r) => r.total).catch(() => null),
      listLayer2(1, 0).then((r) => r.total).catch(() => null),
      listAlertFacts({ limit: 1, offset: 0 }).then((r) => r.total).catch(() => null),
      listCommunications({ limit: 1, offset: 0 }).then((r) => r.total).catch(() => null),
      listTrafficAlertCorrelations(1, 0).then((r) => r.total).catch(() => null),
    ])
      .then(([ips, l2s, alerts, comms, corrs]) => {
        if (!isCancelled) {
          setIpCount(ips);
          setL2Count(l2s);
          setAlertCount(alerts);
          setCommCount(comms);
          setCorrCount(corrs);
          setLoading(false);
        }
      })
      .catch((err: Error) => {
        if (!isCancelled) {
          setError(err.message || 'Failed to load entity counts');
          setLoading(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, []);

  const metricCards = [
    {
      title: 'Observed IP Addresses',
      count: ipCount,
      description: 'Canonical IPv4 and IPv6 endpoints',
      icon: <Network size={20} color="var(--accent-cyan)" />,
      actionLabel: 'Explore Network',
      onClick: () => onNavigate('network'),
    },
    {
      title: 'Layer 2 Identifiers',
      count: l2Count,
      description: 'MAC addresses and resolved names',
      icon: <Database size={20} color="#94a3b8" />,
      actionLabel: 'Browse Network',
      onClick: () => onNavigate('network'),
    },
    {
      title: 'Security Alert Facts',
      count: alertCount,
      description: 'Normalized rule metadata bindings',
      icon: <AlertTriangle size={20} color="var(--accent-rose)" />,
      actionLabel: 'Inspect Alert Facts',
      onClick: () => onNavigate('alerts'),
    },
    {
      title: 'L3 Communications',
      count: commCount,
      description: 'Directional IP-to-IP flows with protocols',
      icon: <Shield size={20} color="var(--accent-emerald)" />,
      actionLabel: 'Investigate Paths',
      onClick: () => onNavigate('path'),
    },
    {
      title: 'Traffic / Alert Correlations',
      count: corrCount,
      description: 'Communications with matching alert facts',
      icon: <GitCompare size={20} color="var(--accent-amber)" />,
      actionLabel: 'View Correlations',
      onClick: () => onNavigate('correlations'),
    },
  ];

  return (
    <div style={{ maxWidth: '1400px', margin: '0 auto', padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Welcome Banner */}
      <div>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 600, letterSpacing: '-0.01em' }}>
          Network & Security Graph Overview
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
          Interactive cybersecurity graph exploration and relationship analysis powered by Neo4j and FastAPI.
        </p>
      </div>

      {error && (
        <div className="warning-banner">
          {error} (Ensure backend API is running on port 8000 and Neo4j is connected)
        </div>
      )}

      {/* Semantic Notice */}
      <div className="info-banner">
        ℹ <strong>AlertFact Semantic Note:</strong> Security alert facts represent unique normalized rule bindings between observed source-target endpoints, not discrete timestamped event occurrences.
      </div>

      {/* Metric Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '1rem',
        }}
      >
        {metricCards.map((card, idx) => (
          <div
            key={idx}
            className="card"
            style={{
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '1rem',
              transition: 'border-color 0.15s ease',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  {card.title}
                </span>
                <div style={{ padding: '0.35rem', backgroundColor: 'rgba(255, 255, 255, 0.03)', borderRadius: 'var(--radius-sm)' }}>
                  {card.icon}
                </div>
              </div>
              <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>
                {loading ? <Skeleton height="32px" width="80px" /> : card.count !== null ? card.count : '—'}
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                {card.description}
              </p>
            </div>

            <button
              className="btn-secondary"
              onClick={card.onClick}
              style={{
                width: '100%',
                fontSize: '0.8rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.4rem',
              }}
            >
              <span>{card.actionLabel}</span>
              <span>➔</span>
            </button>
          </div>
        ))}
      </div>

      {/* Quick Navigation Cards */}
      <div>
        <h3 style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}>Investigation Workflows</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Network size={18} color="var(--accent-cyan)" />
              <h4 style={{ fontSize: '0.95rem' }}>Network Explorer</h4>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Visualize bounded local graph neighborhoods (depth 1 or 2) around specific IP addresses with distinct Layer 2 and Layer 3 relationships.
            </p>
            <button
              className="btn-primary"
              onClick={() => onNavigate('network')}
              style={{ marginTop: 'auto', alignSelf: 'flex-start', fontSize: '0.8rem' }}
            >
              Open Network Explorer
            </button>
          </div>

          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={18} color="var(--accent-rose)" />
              <h4 style={{ fontSize: '0.95rem' }}>Alert Explorer</h4>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Filter and inspect normalized security alert facts by signature ID, priority rating, protocol, or endpoint address.
            </p>
            <button
              className="btn-secondary"
              onClick={() => onNavigate('alerts')}
              style={{ marginTop: 'auto', alignSelf: 'flex-start', fontSize: '0.8rem' }}
            >
              Open Alert Explorer
            </button>
          </div>

          <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Route size={18} color="var(--accent-emerald)" />
              <h4 style={{ fontSize: '0.95rem' }}>Communication Path Finder</h4>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Query the shortest directional Layer 3 communication paths connecting two observed endpoints within up to 10 hops.
            </p>
            <button
              className="btn-secondary"
              onClick={() => onNavigate('path')}
              style={{ marginTop: 'auto', alignSelf: 'flex-start', fontSize: '0.8rem' }}
            >
              Open Path Finder
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
