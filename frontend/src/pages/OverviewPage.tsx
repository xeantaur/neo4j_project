import React, { useEffect, useState } from 'react';
import {
  listIPs,
  listLayer2,
  listCommunications,
  getTrafficAnalyticsSummary,
  listEndpointAnalytics,
} from '../api/network';
import type { EndpointAnalyticsSortBy } from '../api/network';
import { listAlertFacts } from '../api/alerts';
import { listTrafficAlertCorrelations } from '../api/correlations';
import type {
  ActiveView,
} from '../components/layout/Header';
import type {
  TrafficAnalyticsSummaryResponse,
  EndpointAnalyticsResponse,
} from '../api/types';
import { Skeleton } from '../components/common/Skeleton';
import { Tag } from '../components/common/Badge';
import {
  formatObservedBytes,
  formatObservedPackets,
  formatEpochSeconds,
} from '../utils/formatters';
import {
  Network,
  AlertTriangle,
  GitCompare,
  Route,
  Database,
  Shield,
  Activity,
  BarChart2,
  ArrowUpRight,
  ArrowDownLeft,
} from 'lucide-react';

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

  // Traffic Analytics State
  const [analyticsSummary, setAnalyticsSummary] = useState<TrafficAnalyticsSummaryResponse | null>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState<boolean>(true);
  const [analyticsError, setAnalyticsError] = useState<string | null>(null);

  // Endpoint Rankings State
  const [endpointSort, setEndpointSort] = useState<EndpointAnalyticsSortBy>('fan_out');
  const [endpoints, setEndpoints] = useState<EndpointAnalyticsResponse[]>([]);
  const [endpointsLoading, setEndpointsLoading] = useState<boolean>(true);

  // Initial load for counts and analytics summary
  useEffect(() => {
    let isCancelled = false;
    setLoading(true);
    setError(null);
    setAnalyticsLoading(true);

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

    getTrafficAnalyticsSummary()
      .then((summary) => {
        if (!isCancelled) {
          setAnalyticsSummary(summary);
          setAnalyticsLoading(false);
        }
      })
      .catch((err: Error) => {
        if (!isCancelled) {
          setAnalyticsError(err.message || 'Failed to load traffic analytics');
          setAnalyticsLoading(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, []);

  // Fetch Endpoint Rankings on sort change
  useEffect(() => {
    let isCancelled = false;
    setEndpointsLoading(true);

    listEndpointAnalytics(endpointSort, 10, 0)
      .then((res) => {
        if (!isCancelled) {
          setEndpoints(res.items);
          setEndpointsLoading(false);
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setEndpoints([]);
          setEndpointsLoading(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [endpointSort]);

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
      description: 'Unique normalized alert facts',
      icon: <AlertTriangle size={20} color="var(--accent-rose)" />,
      actionLabel: 'Inspect Alert Facts',
      onClick: () => onNavigate('alerts'),
    },
    {
      title: 'L3 Communications',
      count: commCount,
      description: 'Directional communication aggregates with observed protocol context',
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

  const getMetricModeNotice = (mode: string) => {
    switch (mode) {
      case 'none':
        return 'No traffic communication aggregates are currently loaded.';
      case 'basic':
        return 'Traffic topology is available. Detailed packet, frame-byte, and time metrics are unavailable for the basic/legacy traffic format.';
      case 'enriched':
        return 'Detailed traffic metrics are available for the current workspace.';
      case 'mixed':
        return 'Detailed metrics are partial and cover only enriched communication aggregates.';
      default:
        return null;
    }
  };

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
        ℹ <strong>AlertFact Semantic Note:</strong> Security alert facts represent unique normalized alert facts between observed source-target endpoints, not discrete timestamped event occurrences.
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

      {/* --- Traffic Analytics Section (Phase 7D) --- */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Activity size={18} color="var(--accent-cyan)" />
              <span>Traffic Analytics & Volume Metrics</span>
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
              Factual volume measurements, protocol distributions, and endpoint communication rankings.
            </p>
          </div>

          {analyticsSummary && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Mode:</span>
              <Tag
                label={(analyticsSummary.traffic_metrics_mode || 'none').toUpperCase()}
                variant={
                  analyticsSummary.traffic_metrics_mode === 'enriched'
                    ? 'emerald'
                    : analyticsSummary.traffic_metrics_mode === 'mixed'
                    ? 'amber'
                    : analyticsSummary.traffic_metrics_mode === 'basic'
                    ? 'cyan'
                    : 'slate'
                }
              />
            </div>
          )}
        </div>

        {analyticsSummary && (
          <div className="info-banner" style={{ fontSize: '0.85rem' }}>
            ℹ <strong>Traffic Metric Mode:</strong> {getMetricModeNotice(analyticsSummary.traffic_metrics_mode || 'none')}
          </div>
        )}

        {analyticsError && (
          <div className="warning-banner" style={{ fontSize: '0.85rem' }}>
            Traffic analytics unavailable: {analyticsError}
          </div>
        )}

        {/* Volume Summary Cards */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '1rem',
          }}
        >
          <div className="card" style={{ padding: '1rem' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.3rem' }}>
              Communication Aggregates
            </div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-family-mono)', color: 'var(--text-primary)' }}>
              {analyticsLoading ? (
                <Skeleton height="28px" width="60px" />
              ) : analyticsSummary ? (
                analyticsSummary.total_communication_aggregates
              ) : (
                '—'
              )}
            </div>
            {analyticsSummary && analyticsSummary.traffic_metrics_mode === 'mixed' && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-amber)', marginTop: '0.2rem' }}>
                {analyticsSummary.enriched_communication_aggregates} enriched / {analyticsSummary.basic_communication_aggregates} basic
              </div>
            )}
          </div>

          <div className="card" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.3rem' }}>
                Observed Frame Bytes
              </div>
              {analyticsSummary?.traffic_metrics_mode === 'mixed' && (
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-amber)', fontStyle: 'italic' }}>partial</span>
              )}
            </div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-family-mono)', color: 'var(--accent-cyan)' }}>
              {analyticsLoading ? (
                <Skeleton height="28px" width="100px" />
              ) : (
                formatObservedBytes(analyticsSummary?.total_observed_bytes)
              )}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Cumulative Layer 2 frame bytes
            </div>
          </div>

          <div className="card" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.3rem' }}>
                Observed Packets
              </div>
              {analyticsSummary?.traffic_metrics_mode === 'mixed' && (
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-amber)', fontStyle: 'italic' }}>partial</span>
              )}
            </div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-family-mono)', color: 'var(--text-primary)' }}>
              {analyticsLoading ? (
                <Skeleton height="28px" width="80px" />
              ) : (
                formatObservedPackets(analyticsSummary?.total_observed_packets)
              )}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Observed network packet count
            </div>
          </div>

          <div className="card" style={{ padding: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.3rem' }}>
                Observation Window
              </div>
              {analyticsSummary?.traffic_metrics_mode === 'mixed' && (
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-amber)', fontStyle: 'italic' }}>partial</span>
              )}
            </div>
            <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-family-mono)', color: 'var(--text-primary)', marginTop: '0.25rem' }}>
              {analyticsLoading ? (
                <Skeleton height="20px" width="140px" />
              ) : analyticsSummary?.first_observed != null ? (
                <div>
                  <div>{formatEpochSeconds(analyticsSummary.first_observed)}</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.15rem' }}>
                    to {formatEpochSeconds(analyticsSummary.last_observed)}
                  </div>
                </div>
              ) : (
                '—'
              )}
            </div>
          </div>
        </div>

        {/* Ranked Distributions Grids */}
        {analyticsSummary && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
            {/* Top Protocols */}
            <div className="card" style={{ padding: '1rem' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <BarChart2 size={14} color="var(--accent-cyan)" />
                <span>Top Protocols</span>
              </h4>
              {(!analyticsSummary.protocol_distribution || analyticsSummary.protocol_distribution.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No protocol distributions observed</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {analyticsSummary.protocol_distribution.slice(0, 6).map((proto) => (
                    <div
                      key={proto.protocol}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0.4rem 0.6rem',
                        backgroundColor: 'var(--bg-canvas)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.8rem',
                      }}
                    >
                      <Tag label={proto.protocol} variant="cyan" />
                      <div style={{ display: 'flex', gap: '0.75rem', fontFamily: 'var(--font-family-mono)', fontSize: '0.75rem' }}>
                        <span>{proto.communication_aggregate_count} aggs</span>
                        {proto.observed_bytes != null && (
                          <span style={{ color: 'var(--text-muted)' }}>{formatObservedBytes(proto.observed_bytes)}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Top Destination Ports */}
            <div className="card" style={{ padding: '1rem' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Shield size={14} color="var(--accent-emerald)" />
                <span>Top Destination Ports</span>
              </h4>
              {(!analyticsSummary.destination_port_distribution || analyticsSummary.destination_port_distribution.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No destination ports recorded</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {analyticsSummary.destination_port_distribution.slice(0, 6).map((port) => (
                    <div
                      key={port.dst_port}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0.4rem 0.6rem',
                        backgroundColor: 'var(--bg-canvas)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.8rem',
                      }}
                    >
                      <span className="font-mono" style={{ fontWeight: 600, color: 'var(--accent-emerald)' }}>
                        Port {port.dst_port}
                      </span>
                      <div style={{ display: 'flex', gap: '0.75rem', fontFamily: 'var(--font-family-mono)', fontSize: '0.75rem' }}>
                        <span>{port.communication_aggregate_count} aggs</span>
                        {port.observed_bytes != null && (
                          <span style={{ color: 'var(--text-muted)' }}>{formatObservedBytes(port.observed_bytes)}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Top Fan-Out Sources */}
            <div className="card" style={{ padding: '1rem' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <ArrowUpRight size={14} color="var(--accent-cyan)" />
                <span>Top Fan-Out Sources</span>
              </h4>
              {(!analyticsSummary.top_fan_out || analyticsSummary.top_fan_out.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No fan-out metrics observed</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {analyticsSummary.top_fan_out.slice(0, 6).map((item) => (
                    <div
                      key={item.address}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0.4rem 0.6rem',
                        backgroundColor: 'var(--bg-canvas)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.8rem',
                      }}
                    >
                      <button
                        onClick={() => onNavigate('network', { centerIp: item.address })}
                        className="btn-secondary"
                        style={{
                          fontFamily: 'var(--font-family-mono)',
                          padding: '0.15rem 0.4rem',
                          fontSize: '0.75rem',
                          color: 'var(--accent-cyan)',
                        }}
                      >
                        {item.address}
                      </button>
                      <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {item.distinct_destination_ips} peers
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Top Fan-In Destinations */}
            <div className="card" style={{ padding: '1rem' }}>
              <h4 style={{ fontSize: '0.85rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <ArrowDownLeft size={14} color="var(--accent-amber)" />
                <span>Top Fan-In Destinations</span>
              </h4>
              {(!analyticsSummary.top_fan_in || analyticsSummary.top_fan_in.length === 0) ? (
                <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>No fan-in metrics observed</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                  {analyticsSummary.top_fan_in.slice(0, 6).map((item) => (
                    <div
                      key={item.address}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '0.4rem 0.6rem',
                        backgroundColor: 'var(--bg-canvas)',
                        borderRadius: 'var(--radius-sm)',
                        fontSize: '0.8rem',
                      }}
                    >
                      <button
                        onClick={() => onNavigate('network', { centerIp: item.address })}
                        className="btn-secondary"
                        style={{
                          fontFamily: 'var(--font-family-mono)',
                          padding: '0.15rem 0.4rem',
                          fontSize: '0.75rem',
                          color: 'var(--accent-amber)',
                        }}
                      >
                        {item.address}
                      </button>
                      <span className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                        {item.distinct_source_ips} peers
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* --- Endpoint Rankings Table --- */}
        <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Endpoint Rankings</h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Factual endpoint ranking by cardinality and observed traffic volume metrics.
              </p>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <label htmlFor="endpoint-sort-select" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Sort By:
              </label>
              <select
                id="endpoint-sort-select"
                value={endpointSort}
                onChange={(e) => setEndpointSort(e.target.value as EndpointAnalyticsSortBy)}
                style={{ fontSize: '0.8rem', padding: '0.25rem 0.5rem' }}
              >
                <option value="fan_out">Fan-Out (Outbound Peers)</option>
                <option value="fan_in">Fan-In (Inbound Peers)</option>
                <option value="observed_bytes_sent">Observed Bytes Sent</option>
                <option value="observed_bytes_received">Observed Bytes Received</option>
                <option value="observed_packets_sent">Observed Packets Sent</option>
                <option value="observed_packets_received">Observed Packets Received</option>
              </select>
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Outbound Peers</th>
                  <th>Inbound Peers</th>
                  <th>Distinct Dst Ports</th>
                  <th>Bytes Sent</th>
                  <th>Bytes Received</th>
                  <th>Mode</th>
                </tr>
              </thead>
              <tbody>
                {endpointsLoading ? (
                  Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i}>
                      <td><Skeleton height="18px" width="110px" /></td>
                      <td><Skeleton height="18px" width="50px" /></td>
                      <td><Skeleton height="18px" width="50px" /></td>
                      <td><Skeleton height="18px" width="50px" /></td>
                      <td><Skeleton height="18px" width="70px" /></td>
                      <td><Skeleton height="18px" width="70px" /></td>
                      <td><Skeleton height="18px" width="60px" /></td>
                    </tr>
                  ))
                ) : endpoints.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>
                      No endpoint analytics records available.
                    </td>
                  </tr>
                ) : (
                  endpoints.map((ep) => (
                    <tr key={ep.address}>
                      <td>
                        <button
                          onClick={() => onNavigate('network', { centerIp: ep.address })}
                          className="btn-secondary"
                          style={{
                            fontFamily: 'var(--font-family-mono)',
                            fontSize: '0.8rem',
                            padding: '0.15rem 0.45rem',
                            color: 'var(--accent-cyan)',
                          }}
                          title="Center in Network Explorer"
                        >
                          {ep.address}
                        </button>
                      </td>
                      <td className="font-mono">{ep.distinct_outbound_peers}</td>
                      <td className="font-mono">{ep.distinct_inbound_peers}</td>
                      <td className="font-mono">{ep.distinct_destination_ports}</td>
                      <td className="font-mono">{formatObservedBytes(ep.observed_bytes_sent)}</td>
                      <td className="font-mono">{formatObservedBytes(ep.observed_bytes_received)}</td>
                      <td>
                        <Tag
                          label={ep.traffic_metrics_mode}
                          variant={
                            ep.traffic_metrics_mode === 'enriched'
                              ? 'emerald'
                              : ep.traffic_metrics_mode === 'mixed'
                              ? 'amber'
                              : ep.traffic_metrics_mode === 'basic'
                              ? 'cyan'
                              : 'slate'
                          }
                        />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
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
