import React, { useEffect, useState } from 'react';
import { getIPDetail, listIPPeers } from '../../api/network';
import type { IPDetailResponse, PeerResponse } from '../../api/types';
import { Tag } from '../common/Badge';
import { Skeleton } from '../common/Skeleton';
import { Pagination } from '../common/Pagination';
import {
  formatObservedBytes,
  formatObservedPackets,
  formatEpochSeconds,
} from '../../utils/formatters';

interface IPDetailPanelProps {
  address: string;
  onSelectCenter?: (address: string) => void;
  onSetPathSource?: (address: string) => void;
  onSetPathTarget?: (address: string) => void;
}

export const IPDetailPanel: React.FC<IPDetailPanelProps> = ({
  address,
  onSelectCenter,
  onSetPathSource,
  onSetPathTarget,
}) => {
  const [detail, setDetail] = useState<IPDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Peers state
  const [peers, setPeers] = useState<PeerResponse[]>([]);
  const [peerTotal, setPeerTotal] = useState<number>(0);
  const [peerOffset, setPeerOffset] = useState<number>(0);
  const [peerDirection, setPeerDirection] = useState<'all' | 'outbound' | 'inbound'>('all');
  const [peersLoading, setPeersLoading] = useState<boolean>(false);

  // Fetch IP details
  useEffect(() => {
    let isCancelled = false;
    setLoading(true);
    setError(null);

    getIPDetail(address)
      .then((res) => {
        if (!isCancelled) {
          setDetail(res);
          setLoading(false);
        }
      })
      .catch((err: Error) => {
        if (!isCancelled) {
          setError(err.message);
          setLoading(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [address]);

  // Fetch Peers
  useEffect(() => {
    let isCancelled = false;
    setPeersLoading(true);

    listIPPeers(address, peerDirection, 10, peerOffset)
      .then((res) => {
        if (!isCancelled) {
          setPeers(res.items);
          setPeerTotal(res.total);
          setPeersLoading(false);
        }
      })
      .catch(() => {
        if (!isCancelled) {
          setPeers([]);
          setPeersLoading(false);
        }
      });

    return () => {
      isCancelled = true;
    };
  }, [address, peerDirection, peerOffset]);

  if (loading) {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <Skeleton height="24px" width="70%" />
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <Skeleton height="60px" />
          <Skeleton height="60px" />
        </div>
        <Skeleton height="80px" />
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="warning-banner">
        {error || `Could not load details for ${address}`}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Address Header */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Observed IP Address
          </span>
          <Tag
            label={(detail.traffic_metrics_mode || 'none').toUpperCase()}
            variant={
              detail.traffic_metrics_mode === 'enriched'
                ? 'emerald'
                : detail.traffic_metrics_mode === 'mixed'
                ? 'amber'
                : detail.traffic_metrics_mode === 'basic'
                ? 'cyan'
                : 'slate'
            }
          />
        </div>
        <div style={{ fontSize: '1.2rem', fontWeight: 600, fontFamily: 'var(--font-family-mono)', color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
          {detail.address}
        </div>
      </div>

      {/* Action Buttons */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {onSelectCenter && (
          <button
            className="btn-primary"
            onClick={() => onSelectCenter(detail.address)}
            style={{ fontSize: '0.8rem', padding: '0.35rem 0.7rem' }}
          >
            Investigate as Center
          </button>
        )}
        {onSetPathSource && (
          <button
            className="btn-secondary"
            onClick={() => onSetPathSource(detail.address)}
            style={{ fontSize: '0.8rem', padding: '0.35rem 0.7rem' }}
          >
            Path From Here
          </button>
        )}
        {onSetPathTarget && (
          <button
            className="btn-secondary"
            onClick={() => onSetPathTarget(detail.address)}
            style={{ fontSize: '0.8rem', padding: '0.35rem 0.7rem' }}
          >
            Path To Here
          </button>
        )}
      </div>

      {/* Topology Cardinalities */}
      <div>
        <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
          Communication Topology
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.6rem' }}>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Outbound Aggregates</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>
              {detail.outbound_flows ?? 0}
            </div>
          </div>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Inbound Aggregates</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>
              {detail.inbound_flows ?? 0}
            </div>
          </div>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Outbound Peers</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--accent-cyan)', fontFamily: 'var(--font-family-mono)' }}>
              {detail.distinct_outbound_peers ?? 0}
            </div>
          </div>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Inbound Peers</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--accent-amber)', fontFamily: 'var(--font-family-mono)' }}>
              {detail.distinct_inbound_peers ?? 0}
            </div>
          </div>
          <div className="card" style={{ padding: '0.6rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Distinct Dst Ports</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--accent-emerald)', fontFamily: 'var(--font-family-mono)' }}>
              {detail.distinct_destination_ports ?? 0}
            </div>
          </div>
        </div>
      </div>

      {/* Traffic Volume & Time Metrics */}
      {detail.traffic_metrics_mode === 'basic' ? (
        <div className="info-banner" style={{ fontSize: '0.8rem', padding: '0.6rem 0.75rem' }}>
          Detailed packet/frame-byte/time metrics are unavailable for basic traffic.
        </div>
      ) : detail.traffic_metrics_mode === 'enriched' || detail.traffic_metrics_mode === 'mixed' ? (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
            <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
              Traffic Volume & Time
            </h4>
            {detail.traffic_metrics_mode === 'mixed' && (
              <span style={{ fontSize: '0.7rem', color: 'var(--accent-amber)', fontStyle: 'italic' }}>partial</span>
            )}
          </div>

          {detail.traffic_metrics_mode === 'mixed' && (
            <div className="info-banner" style={{ fontSize: '0.75rem', padding: '0.4rem 0.6rem', marginBottom: '0.5rem' }}>
              Measured values cover enriched communication aggregates only.
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.6rem' }}>
            <div className="card" style={{ padding: '0.6rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Bytes Sent</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--accent-cyan)', fontFamily: 'var(--font-family-mono)' }}>
                {formatObservedBytes(detail.observed_bytes_sent)}
              </div>
            </div>
            <div className="card" style={{ padding: '0.6rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Bytes Received</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>
                {formatObservedBytes(detail.observed_bytes_received)}
              </div>
            </div>
            <div className="card" style={{ padding: '0.6rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Packets Sent</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>
                {formatObservedPackets(detail.observed_packets_sent)}
              </div>
            </div>
            <div className="card" style={{ padding: '0.6rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Packets Received</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'var(--font-family-mono)' }}>
                {formatObservedPackets(detail.observed_packets_received)}
              </div>
            </div>
          </div>

          {(detail.first_observed != null || detail.last_observed != null) && (
            <div className="card" style={{ padding: '0.6rem', marginTop: '0.6rem', fontSize: '0.75rem', fontFamily: 'var(--font-family-mono)' }}>
              <div style={{ color: 'var(--text-muted)' }}>First Seen: {formatEpochSeconds(detail.first_observed)}</div>
              <div style={{ color: 'var(--text-muted)', marginTop: '0.15rem' }}>Last Seen: {formatEpochSeconds(detail.last_observed)}</div>
            </div>
          )}
        </div>
      ) : null}

      {/* Security Alert Context */}
      <div>
        <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
          Security Alert Facts
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div className="card" style={{ padding: '0.75rem', borderColor: detail.alerts_originated > 0 ? 'var(--accent-rose-dim)' : 'var(--border-subtle)' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Originated</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 600, color: detail.alerts_originated > 0 ? 'var(--accent-rose)' : 'var(--text-primary)' }}>
              {detail.alerts_originated}
            </div>
          </div>
          <div className="card" style={{ padding: '0.75rem', borderColor: detail.alerts_targeted > 0 ? 'var(--accent-amber-dim)' : 'var(--border-subtle)' }}>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Targeted</div>
            <div style={{ fontSize: '1.25rem', fontWeight: 600, color: detail.alerts_targeted > 0 ? 'var(--accent-amber)' : 'var(--text-primary)' }}>
              {detail.alerts_targeted}
            </div>
          </div>
        </div>
      </div>

      {/* Associated Layer 2 Identifiers */}
      <div>
        <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
          Observed Layer 2 Associations
        </h4>
        {detail.layer2_identifiers.length === 0 ? (
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>None observed</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            {detail.layer2_identifiers.map((l2) => (
              <div
                key={l2}
                style={{
                  padding: '0.4rem 0.6rem',
                  backgroundColor: 'var(--bg-card)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  fontFamily: 'var(--font-family-mono)',
                  fontSize: '0.8rem',
                }}
              >
                {l2}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Communicating Peers */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
          <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
            Communicating Peers ({peerTotal})
          </h4>
          <select
            value={peerDirection}
            onChange={(e) => {
              setPeerDirection(e.target.value as 'all' | 'outbound' | 'inbound');
              setPeerOffset(0);
            }}
            style={{ fontSize: '0.75rem', padding: '0.2rem 0.4rem' }}
          >
            <option value="all">All Directions</option>
            <option value="outbound">Outbound</option>
            <option value="inbound">Inbound</option>
          </select>
        </div>

        {peersLoading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <Skeleton height="32px" />
            <Skeleton height="32px" />
          </div>
        ) : peers.length === 0 ? (
          <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>No peers observed</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            {peers.map((peer, idx) => (
              <div
                key={`${peer.peer_address}-${peer.direction}-${idx}`}
                style={{
                  padding: '0.5rem 0.6rem',
                  backgroundColor: 'var(--bg-card)',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '0.5rem',
                }}
              >
                <div>
                  <div style={{ fontFamily: 'var(--font-family-mono)', fontSize: '0.8rem', fontWeight: 500 }}>
                    {peer.peer_address}
                  </div>
                  <div style={{ display: 'flex', gap: '0.25rem', marginTop: '0.2rem' }}>
                    <Tag
                      label={peer.direction}
                      variant={peer.direction === 'outbound' ? 'cyan' : 'amber'}
                    />
                    {peer.protocols.map((p) => (
                      <Tag key={p} label={p} variant="slate" />
                    ))}
                  </div>
                </div>
                {onSelectCenter && (
                  <button
                    className="btn-secondary"
                    onClick={() => onSelectCenter(peer.peer_address)}
                    style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                    title="Center graph on peer"
                  >
                    Center
                  </button>
                )}
              </div>
            ))}

            {peerTotal > 10 && (
              <Pagination
                offset={peerOffset}
                limit={10}
                total={peerTotal}
                onPageChange={setPeerOffset}
                itemLabel="peers"
              />
            )}
          </div>
        )}
      </div>
    </div>
  );
};
