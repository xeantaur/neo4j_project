import React, { useEffect, useState } from 'react';
import { listTrafficAlertCorrelations } from '../api/correlations';
import type { TrafficAlertCorrelationResponse } from '../api/types';
import { PriorityBadge, Tag } from '../components/common/Badge';
import { Pagination } from '../components/common/Pagination';
import { Skeleton } from '../components/common/Skeleton';
import type { ActiveView } from '../components/layout/Header';
import { Network, Route } from 'lucide-react';

interface CorrelationsPageProps {
  onNavigate?: (view: ActiveView, context?: { centerIp?: string; sourceIp?: string; targetIp?: string }) => void;
}

export const CorrelationsPage: React.FC<CorrelationsPageProps> = ({ onNavigate }) => {
  const [correlations, setCorrelations] = useState<TrafficAlertCorrelationResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [offset, setOffset] = useState<number>(0);
  const [limit] = useState<number>(50);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isCancelled = false;
    setLoading(true);
    setError(null);

    listTrafficAlertCorrelations(limit, offset)
      .then((res) => {
        if (!isCancelled) {
          setCorrelations(res.items);
          setTotal(res.total);
          setLoading(false);
        }
      })
      .catch((err: Error) => {
        if (!isCancelled) {
          setError(err.message);
          setCorrelations([]);
          setTotal(0);
          setLoading(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [limit, offset]);

  return (
    <div style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '1.75rem 2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h2 style={{ fontSize: '1.35rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Traffic & Security Alert Correlations
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: '0.2rem' }}>
          Observed Layer 3 communications whose source-target endpoints match generated security alert facts.
        </p>
      </div>

      <div className="info-banner">
        <span>ℹ</span>
        <div>
          <strong>Correlation Notice:</strong> Rows represent observed communication flows alongside matching security alert facts sharing identical source-target endpoints. Co-occurrence indicates relationship overlap in the graph, not proven causality.
        </div>
      </div>

      {error && (
        <div className="warning-banner">
          {error}
        </div>
      )}

      {/* Correlation Records Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Priority</th>
              <th>Source IP</th>
              <th>Target IP</th>
              <th>Traffic Protocol</th>
              <th>Traffic Ports</th>
              <th>Alert Protocol</th>
              <th>SID</th>
              <th>Alert Message</th>
              <th>Flow Key</th>
              <th style={{ width: '150px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  <td><Skeleton height="20px" width="70px" /></td>
                  <td><Skeleton height="20px" width="90px" /></td>
                  <td><Skeleton height="20px" width="90px" /></td>
                  <td><Skeleton height="20px" width="50px" /></td>
                  <td><Skeleton height="20px" width="70px" /></td>
                  <td><Skeleton height="20px" width="50px" /></td>
                  <td><Skeleton height="20px" width="60px" /></td>
                  <td><Skeleton height="20px" width="80%" /></td>
                  <td><Skeleton height="20px" width="60px" /></td>
                  <td><Skeleton height="20px" width="110px" /></td>
                </tr>
              ))
            ) : correlations.length === 0 ? (
              <tr>
                <td colSpan={10} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                  No correlated traffic-alert records found in the graph.
                </td>
              </tr>
            ) : (
              correlations.map((corr, idx) => (
                <tr key={corr.traffic_flow_key ? `${corr.fact_key}-${corr.traffic_flow_key}` : `${corr.fact_key}-${corr.traffic_protocol}-${idx}`}>
                  <td>
                    <PriorityBadge priority={corr.priority} />
                  </td>
                  <td>
                    <span className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      {corr.source_ip}
                    </span>
                  </td>
                  <td>
                    <span className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      {corr.target_ip}
                    </span>
                  </td>
                  <td>
                    <Tag label={corr.traffic_protocol} variant="slate" />
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                    {corr.traffic_src_port != null || corr.traffic_dst_port != null
                      ? `${corr.traffic_src_port ?? '—'} → ${corr.traffic_dst_port ?? '—'}`
                      : '—'}
                  </td>
                  <td>
                    {corr.alert_protocol ? (
                      <Tag label={corr.alert_protocol} variant="slate" />
                    ) : (
                      '—'
                    )}
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                    {corr.sid !== null ? corr.sid : '—'}
                  </td>
                  <td style={{ fontWeight: 500 }}>
                    {corr.message || '—'}
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }} title={corr.traffic_flow_key || undefined}>
                    {corr.traffic_flow_key ? `${corr.traffic_flow_key.slice(0, 8)}…` : '—'}
                  </td>
                  <td>
                    {onNavigate && (
                      <div style={{ display: 'flex', gap: '0.35rem' }}>
                        <button
                          className="btn-secondary"
                          onClick={() => onNavigate('network', { centerIp: corr.source_ip })}
                          style={{ fontSize: '0.75rem', padding: '0.2rem 0.45rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                          title="Explore Source IP in Graph"
                        >
                          <Network size={12} />
                          <span>Graph</span>
                        </button>
                        <button
                          className="btn-secondary"
                          onClick={() => onNavigate('path', { sourceIp: corr.source_ip, targetIp: corr.target_ip })}
                          style={{ fontSize: '0.75rem', padding: '0.2rem 0.45rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                          title="Find Path"
                        >
                          <Route size={12} />
                          <span>Path</span>
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {!loading && total > 0 && (
        <Pagination
          offset={offset}
          limit={limit}
          total={total}
          onPageChange={setOffset}
          itemLabel="correlation records"
        />
      )}
    </div>
  );
};
