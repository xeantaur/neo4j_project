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
  formatHumanDateTime,
  formatEpochSeconds,
} from '../utils/formatters';
import {
  Network,
  AlertTriangle,
  Route,
  Activity,
  ArrowRight,
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

  // Traffic Analytics (Phase 7D)
  const [analyticsSummary, setAnalyticsSummary] = useState<TrafficAnalyticsSummaryResponse | null>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState<boolean>(true);
  const [analyticsError, setAnalyticsError] = useState<string | null>(null);

  // Endpoint Rankings
  const [endpoints, setEndpoints] = useState<EndpointAnalyticsResponse[]>([]);
  const [endpointSort, setEndpointSort] = useState<EndpointAnalyticsSortBy>('fan_out');
  const [endpointsLoading, setEndpointsLoading] = useState<boolean>(true);

  // Initial load for counts and analytics summary
  useEffect(() => {
    let isCancelled = false;
    setLoading(true);
    setError(null);

    Promise.allSettled([
      listIPs(1, 0),
      listLayer2(1, 0),
      listAlertFacts({ limit: 1, offset: 0 }),
      listCommunications({ limit: 1, offset: 0 }),
      listTrafficAlertCorrelations(1, 0),
    ])
      .then(([ips, l2, alerts, comms, corrs]) => {
        if (isCancelled) return;
        if (ips.status === 'fulfilled') setIpCount(ips.value.total);
        if (l2.status === 'fulfilled') setL2Count(l2.value.total);
        if (alerts.status === 'fulfilled') setAlertCount(alerts.value.total);
        if (comms.status === 'fulfilled') setCommCount(comms.value.total);
        if (corrs.status === 'fulfilled') setCorrCount(corrs.value.total);
        setLoading(false);
      })
      .catch((err: Error) => {
        if (!isCancelled) {
          setError(err.message || 'Failed to load entity statistics');
          setLoading(false);
        }
      });

    // Fetch Traffic Analytics Summary
    setAnalyticsLoading(true);
    getTrafficAnalyticsSummary()
      .then((res) => {
        if (!isCancelled) {
          setAnalyticsSummary(res);
          setAnalyticsLoading(false);
        }
      })
      .catch((err: Error) => {
        if (!isCancelled) {
          setAnalyticsError(err.message || 'Failed to load traffic analytics summary');
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

    listEndpointAnalytics(endpointSort, 8, 0)
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
      description: 'Canonical IPv4 and IPv6 network endpoints',
    },
    {
      title: 'Layer 2 Identifiers',
      count: l2Count,
      description: 'MAC addresses and resolved interface names',
    },
    {
      title: 'Security Alert Facts',
      count: alertCount,
      description: 'Normalized source-to-target security alert facts',
    },
    {
      title: 'L3 Communications',
      count: commCount,
      description: 'Directional communication aggregates with protocol context',
    },
    {
      title: 'Traffic / Alert Correlations',
      count: corrCount,
      description: 'Observed traffic flows matching security alert facts',
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
    <div style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '2rem 2.5rem', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Page Title & Subtitle */}
      <div>
        <h2 style={{ fontSize: '1.45rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Network & Security Graph Overview
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
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
        <span>ℹ</span>
        <div>
          <strong>AlertFact Semantic Note:</strong> Security alert facts represent unique normalized alert facts between observed source-target endpoints, not discrete timestamped event occurrences.
        </div>
      </div>

      {/* Primary KPI Area - Data Surfaces without CTA buttons */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1rem',
        }}
      >
        {metricCards.map((card, idx) => (
          <div
            key={idx}
            className="card"
            style={{
              padding: '1.2rem 1.35rem',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '0.4rem',
            }}
          >
            <div>
              <div style={{ fontSize: '0.74rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                {card.title}
              </div>
              <div style={{ fontSize: '1.85rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)', marginTop: '0.35rem', letterSpacing: '-0.02em' }}>
                {loading ? <Skeleton height="32px" width="70px" /> : card.count !== null ? card.count : '—'}
              </div>
            </div>
            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
              {card.description}
            </p>
          </div>
        ))}
      </div>

      {/* --- Traffic Analytics Section (Phase 7D) --- */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Activity size={18} color="var(--accent-primary)" />
              <span>Traffic Analytics & Volume Metrics</span>
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              Factual volume measurements, protocol distributions, and endpoint communication rankings.
            </p>
          </div>

          {analyticsSummary && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>Mode:</span>
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
          <div className="info-banner" style={{ fontSize: '0.82rem' }}>
            <span>ℹ</span>
            <div>
              <strong>Traffic Metric Mode:</strong> {getMetricModeNotice(analyticsSummary.traffic_metrics_mode || 'none')}
            </div>
          </div>
        )}

        {analyticsError && (
          <div className="warning-banner" style={{ fontSize: '0.82rem' }}>
            Traffic analytics unavailable: {analyticsError}
          </div>
        )}

        {/* Unified Volume Summary Surface */}
        <div
          className="card"
          style={{
            padding: 0,
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            overflow: 'hidden',
          }}
        >
          {/* Column 1: Communication Aggregates */}
          <div style={{ padding: '1.25rem 1.4rem', borderRight: '1px solid var(--border-subtle)' }}>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
              Communication Aggregates
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 600, fontFamily: 'var(--font-family-mono)', color: 'var(--text-primary)', marginTop: '0.35rem' }}>
              {analyticsLoading ? (
                <Skeleton height="28px" width="60px" />
              ) : analyticsSummary ? (
                analyticsSummary.total_communication_aggregates
              ) : (
                '—'
              )}
            </div>
            {analyticsSummary && analyticsSummary.traffic_metrics_mode === 'mixed' ? (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-amber)', marginTop: '0.25rem' }}>
                {analyticsSummary.enriched_communication_aggregates} enriched / {analyticsSummary.basic_communication_aggregates} basic
              </div>
            ) : (
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                Distinct L3 directional flows
              </div>
            )}
          </div>

          {/* Column 2: Observed Frame Bytes */}
          <div style={{ padding: '1.25rem 1.4rem', borderRight: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
                Observed Frame Bytes
              </div>
              {analyticsSummary?.traffic_metrics_mode === 'mixed' && (
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-amber)', fontStyle: 'italic' }}>partial</span>
              )}
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 600, fontFamily: 'var(--font-family-mono)', color: 'var(--text-primary)', marginTop: '0.35rem' }}>
              {analyticsLoading ? (
                <Skeleton height="28px" width="100px" />
              ) : (
                formatObservedBytes(analyticsSummary?.total_observed_bytes)
              )}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              Cumulative Layer 2 frame bytes
            </div>
          </div>

          {/* Column 3: Observed Packets */}
          <div style={{ padding: '1.25rem 1.4rem', borderRight: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
                Observed Packets
              </div>
              {analyticsSummary?.traffic_metrics_mode === 'mixed' && (
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-amber)', fontStyle: 'italic' }}>partial</span>
              )}
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 600, fontFamily: 'var(--font-family-mono)', color: 'var(--text-primary)', marginTop: '0.35rem' }}>
              {analyticsLoading ? (
                <Skeleton height="28px" width="80px" />
              ) : (
                formatObservedPackets(analyticsSummary?.total_observed_packets)
              )}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              Observed network packet count
            </div>
          </div>

          {/* Column 4: Observation Window */}
          <div style={{ padding: '1.25rem 1.4rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
                Observation Window
              </div>
              {analyticsSummary?.traffic_metrics_mode === 'mixed' && (
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-amber)', fontStyle: 'italic' }}>partial</span>
              )}
            </div>
            <div style={{ fontSize: '0.82rem', fontFamily: 'var(--font-family-mono)', color: 'var(--text-primary)', marginTop: '0.45rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              {analyticsLoading ? (
                <Skeleton height="20px" width="140px" />
              ) : analyticsSummary?.first_observed != null ? (
                <>
                  <div title={`Epoch: ${analyticsSummary.first_observed} (${formatEpochSeconds(analyticsSummary.first_observed)})`}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>First: </span>
                    <span>{formatHumanDateTime(analyticsSummary.first_observed)}</span>
                  </div>
                  <div title={`Epoch: ${analyticsSummary.last_observed} (${formatEpochSeconds(analyticsSummary.last_observed)})`}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>Last: </span>
                    <span>{formatHumanDateTime(analyticsSummary.last_observed)}</span>
                  </div>
                </>
              ) : (
                '—'
              )}
            </div>
          </div>
        </div>

        {/* Ranked Distributions - Unified Shared Analytics Surface */}
        {analyticsSummary && (
          <div className="card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <h4 style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Traffic Distributions & Endpoint Rankings
            </h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '2rem' }}>
              {/* Top Protocols */}
              <div>
                <div style={{ fontSize: '0.74rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', paddingBottom: '0.45rem', borderBottom: '1px solid var(--border-subtle)', marginBottom: '0.45rem' }}>
                  Top Protocols
                </div>
                {(!analyticsSummary.protocol_distribution || analyticsSummary.protocol_distribution.length === 0) ? (
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', padding: '0.5rem 0' }}>No protocol distributions observed</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {analyticsSummary.protocol_distribution.slice(0, 6).map((proto) => (
                      <div
                        key={proto.protocol}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '0.45rem 0',
                          borderBottom: '1px solid #f3f4f6',
                          fontSize: '0.82rem',
                        }}
                      >
                        <Tag label={proto.protocol} variant="slate" />
                        <div style={{ display: 'flex', gap: '0.75rem', fontFamily: 'var(--font-family-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
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
              <div>
                <div style={{ fontSize: '0.74rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', paddingBottom: '0.45rem', borderBottom: '1px solid var(--border-subtle)', marginBottom: '0.45rem' }}>
                  Top Destination Ports
                </div>
                {(!analyticsSummary.destination_port_distribution || analyticsSummary.destination_port_distribution.length === 0) ? (
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', padding: '0.5rem 0' }}>No destination ports recorded</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {analyticsSummary.destination_port_distribution.slice(0, 6).map((port) => (
                      <div
                        key={port.dst_port}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '0.45rem 0',
                          borderBottom: '1px solid #f3f4f6',
                          fontSize: '0.82rem',
                        }}
                      >
                        <span className="font-mono" style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                          Port {port.dst_port}
                        </span>
                        <div style={{ display: 'flex', gap: '0.75rem', fontFamily: 'var(--font-family-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
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
              <div>
                <div style={{ fontSize: '0.74rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', paddingBottom: '0.45rem', borderBottom: '1px solid var(--border-subtle)', marginBottom: '0.45rem' }}>
                  Top Fan-Out Sources
                </div>
                {(!analyticsSummary.top_fan_out || analyticsSummary.top_fan_out.length === 0) ? (
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', padding: '0.5rem 0' }}>No fan-out metrics observed</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {analyticsSummary.top_fan_out.slice(0, 6).map((item) => (
                      <div
                        key={item.address}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '0.45rem 0',
                          borderBottom: '1px solid #f3f4f6',
                          fontSize: '0.82rem',
                        }}
                      >
                        <button
                          onClick={() => onNavigate('network', { centerIp: item.address })}
                          style={{
                            fontFamily: 'var(--font-family-mono)',
                            padding: 0,
                            fontSize: '0.82rem',
                            color: 'var(--accent-primary)',
                            textDecoration: 'none',
                          }}
                        >
                          {item.address}
                        </button>
                        <span className="font-mono" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                          {item.distinct_destination_ips} peers
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Top Fan-In Destinations */}
              <div>
                <div style={{ fontSize: '0.74rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', paddingBottom: '0.45rem', borderBottom: '1px solid var(--border-subtle)', marginBottom: '0.45rem' }}>
                  Top Fan-In Destinations
                </div>
                {(!analyticsSummary.top_fan_in || analyticsSummary.top_fan_in.length === 0) ? (
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', padding: '0.5rem 0' }}>No fan-in metrics observed</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column' }}>
                    {analyticsSummary.top_fan_in.slice(0, 6).map((item) => (
                      <div
                        key={item.address}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '0.45rem 0',
                          borderBottom: '1px solid #f3f4f6',
                          fontSize: '0.82rem',
                        }}
                      >
                        <button
                          onClick={() => onNavigate('network', { centerIp: item.address })}
                          style={{
                            fontFamily: 'var(--font-family-mono)',
                            padding: 0,
                            fontSize: '0.82rem',
                            color: 'var(--accent-primary)',
                            textDecoration: 'none',
                          }}
                        >
                          {item.address}
                        </button>
                        <span className="font-mono" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                          {item.distinct_source_ips} peers
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* --- Endpoint Rankings Table --- */}
        <div className="card" style={{ padding: '1.25rem 1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Endpoint Rankings</h4>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
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
                style={{ fontSize: '0.8rem', padding: '0.3rem 0.6rem' }}
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

          <div className="table-container" style={{ marginTop: '0.25rem' }}>
            <table>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Out Peers</th>
                  <th>In Peers</th>
                  <th>Dst Ports</th>
                  <th>Bytes Sent</th>
                  <th>Bytes Rcvd</th>
                  <th>Mode</th>
                  <th>Action</th>
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
                      <td><Skeleton height="18px" width="50px" /></td>
                    </tr>
                  ))
                ) : endpoints.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>
                      No endpoint analytics records available.
                    </td>
                  </tr>
                ) : (
                  endpoints.map((ep) => (
                    <tr key={ep.address}>
                      <td>
                        <button
                          onClick={() => onNavigate('network', { centerIp: ep.address })}
                          style={{
                            fontFamily: 'var(--font-family-mono)',
                            fontSize: '0.82rem',
                            fontWeight: 500,
                            color: 'var(--accent-primary)',
                            backgroundColor: 'transparent',
                            padding: 0,
                            textAlign: 'left',
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
                      <td>
                        <button
                          className="btn-secondary"
                          onClick={() => onNavigate('network', { centerIp: ep.address })}
                          style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                        >
                          Graph
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Investigation Workflows */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <h3 style={{ fontSize: '1.15rem', fontWeight: 600 }}>Investigation Workflows</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
          <div
            className="card"
            style={{
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '0.75rem',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <Network size={18} color="var(--accent-primary)" />
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Interactive Graph Explorer</h4>
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                Inspect 1-hop and 2-hop neighborhoods, discover Layer 2 device associations, and investigate deterministic flow keys.
              </p>
            </div>
            <button
              className="btn-secondary"
              onClick={() => onNavigate('network')}
              style={{ fontSize: '0.8rem', alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            >
              <span>Open Network Explorer</span>
              <ArrowRight size={14} />
            </button>
          </div>

          <div
            className="card"
            style={{
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '0.75rem',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <AlertTriangle size={18} color="var(--accent-rose)" />
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Security Alert Fact Analysis</h4>
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                Filter normalized alert facts by priority, classification, and endpoint address to assess threat exposure.
              </p>
            </div>
            <button
              className="btn-secondary"
              onClick={() => onNavigate('alerts')}
              style={{ fontSize: '0.8rem', alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            >
              <span>Open Alert Explorer</span>
              <ArrowRight size={14} />
            </button>
          </div>

          <div
            className="card"
            style={{
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              gap: '0.75rem',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                <Route size={18} color="var(--accent-primary)" />
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Deterministic Path Finder</h4>
              </div>
              <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                Compute shortest communication paths between any two observed endpoints with complete protocol validation.
              </p>
            </div>
            <button
              className="btn-secondary"
              onClick={() => onNavigate('path')}
              style={{ fontSize: '0.8rem', alignSelf: 'flex-start', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            >
              <span>Open Path Finder</span>
              <ArrowRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
