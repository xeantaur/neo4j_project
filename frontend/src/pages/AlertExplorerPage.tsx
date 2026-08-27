import React, { useEffect, useState, useCallback } from 'react';
import { listAlertFacts, getAlertFact } from '../api/alerts';
import type { AlertFactResponse } from '../api/types';
import { PriorityBadge, Tag } from '../components/common/Badge';
import { Pagination } from '../components/common/Pagination';
import { Modal } from '../components/common/Modal';
import { Skeleton } from '../components/common/Skeleton';
import type { ActiveView } from '../components/layout/Header';
import { Copy, Check, Network, Route } from 'lucide-react';

interface AlertExplorerPageProps {
  onNavigate?: (view: ActiveView, context?: { centerIp?: string; sourceIp?: string; targetIp?: string }) => void;
}

export const AlertExplorerPage: React.FC<AlertExplorerPageProps> = ({ onNavigate }) => {
  // Filters state
  const [sourceIp, setSourceIp] = useState<string>('');
  const [targetIp, setTargetIp] = useState<string>('');
  const [priority, setPriority] = useState<string>('');
  const [sid, setSid] = useState<string>('');
  const [protocol, setProtocol] = useState<string>('');

  // Table state
  const [alerts, setAlerts] = useState<AlertFactResponse[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [offset, setOffset] = useState<number>(0);
  const [limit] = useState<number>(50);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Inspector modal state
  const [selectedFactKey, setSelectedFactKey] = useState<string | null>(null);
  const [selectedFact, setSelectedFact] = useState<AlertFactResponse | null>(null);
  const [factLoading, setFactLoading] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);

  const fetchAlerts = useCallback(() => {
    setLoading(true);
    setError(null);

    const prioNum = priority ? Number(priority) : undefined;
    const sidNum = sid ? Number(sid) : undefined;

    listAlertFacts({
      source_ip: sourceIp.trim() || undefined,
      target_ip: targetIp.trim() || undefined,
      priority: prioNum,
      sid: sidNum,
      protocol: protocol.trim() || undefined,
      limit,
      offset,
    })
      .then((res) => {
        setAlerts(res.items);
        setTotal(res.total);
        setLoading(false);
      })
      .catch((err: Error) => {
        setError(err.message);
        setAlerts([]);
        setTotal(0);
        setLoading(false);
      });
  }, [sourceIp, targetIp, priority, sid, protocol, limit, offset]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleFilterSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setOffset(0);
    fetchAlerts();
  };

  const handleClearFilters = () => {
    setSourceIp('');
    setTargetIp('');
    setPriority('');
    setSid('');
    setProtocol('');
    setOffset(0);
  };

  const handleInspectFact = (factKey: string) => {
    setSelectedFactKey(factKey);
    setFactLoading(true);
    setCopiedKey(false);

    getAlertFact(factKey)
      .then((res) => {
        setSelectedFact(res);
        setFactLoading(false);
      })
      .catch(() => {
        setSelectedFact(null);
        setFactLoading(false);
      });
  };

  const handleCopyFactKey = (key: string) => {
    navigator.clipboard.writeText(key).then(() => {
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    });
  };

  return (
    <div style={{ maxWidth: '1440px', width: '100%', margin: '0 auto', padding: '2rem 2.5rem', display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
      {/* Title */}
      <div>
        <h2 style={{ fontSize: '1.45rem', fontWeight: 600, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Security Alert Fact Explorer
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '0.25rem' }}>
          Filter and inspect unique normalized security alert facts.
        </p>
      </div>

      {/* Semantic Notice */}
      <div className="info-banner">
        <span>ℹ</span>
        <div>
          <strong>AlertFact Semantic Note:</strong> Alert facts represent unique normalized security alert facts, not timestamped event occurrences. Identical occurrences with identical fields collapse into a single record.
        </div>
      </div>

      {/* Filter Toolbar */}
      <form onSubmit={handleFilterSubmit} className="card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.85rem', alignItems: 'flex-end' }}>
          <div>
            <label htmlFor="filter-source" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Source IP
            </label>
            <input
              id="filter-source"
              type="text"
              value={sourceIp}
              onChange={(e) => setSourceIp(e.target.value)}
              placeholder="e.g. 192.168.1.100"
              style={{ width: '100%', fontFamily: 'var(--font-family-mono)', fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
            />
          </div>

          <div>
            <label htmlFor="filter-target" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Target IP
            </label>
            <input
              id="filter-target"
              type="text"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              placeholder="e.g. 192.168.1.1"
              style={{ width: '100%', fontFamily: 'var(--font-family-mono)', fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
            />
          </div>

          <div>
            <label htmlFor="filter-priority" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Priority
            </label>
            <select
              id="filter-priority"
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
              style={{ width: '100%', fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
            >
              <option value="">All Priorities</option>
              <option value="1">Priority 1</option>
              <option value="2">Priority 2</option>
              <option value="3">Priority 3</option>
              <option value="4">Priority 4</option>
            </select>
          </div>

          <div>
            <label htmlFor="filter-sid" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Signature ID (SID)
            </label>
            <input
              id="filter-sid"
              type="number"
              value={sid}
              onChange={(e) => setSid(e.target.value)}
              placeholder="e.g. 2001219"
              style={{ width: '100%', fontFamily: 'var(--font-family-mono)', fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
            />
          </div>

          <div>
            <label htmlFor="filter-proto" style={{ display: 'block', fontSize: '0.75rem', fontWeight: 500, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Protocol
            </label>
            <input
              id="filter-proto"
              type="text"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
              placeholder="e.g. TCP, UDP"
              style={{ width: '100%', fontSize: '0.8rem', padding: '0.35rem 0.65rem' }}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button type="submit" className="btn-primary" style={{ flex: 1, fontSize: '0.8rem', padding: '0.38rem 0.75rem' }}>
              Filter
            </button>
            <button type="button" className="btn-secondary" onClick={handleClearFilters} style={{ fontSize: '0.8rem', padding: '0.38rem 0.75rem' }}>
              Clear
            </button>
          </div>
        </div>
      </form>

      {error && (
        <div className="warning-banner">
          {error}
        </div>
      )}

      {/* Alert Facts Table */}
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th style={{ width: '110px' }}>Priority</th>
              <th style={{ width: '110px' }}>SID</th>
              <th>Alert Message</th>
              <th>Source IP</th>
              <th>Target IP</th>
              <th>Protocol</th>
              <th>Ports (Src ➔ Dst)</th>
              <th style={{ width: '130px' }}>Fact Key</th>
              <th style={{ width: '90px' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i}>
                  <td><Skeleton height="20px" width="70px" /></td>
                  <td><Skeleton height="20px" width="80px" /></td>
                  <td><Skeleton height="20px" width="90%" /></td>
                  <td><Skeleton height="20px" width="100px" /></td>
                  <td><Skeleton height="20px" width="100px" /></td>
                  <td><Skeleton height="20px" width="50px" /></td>
                  <td><Skeleton height="20px" width="80px" /></td>
                  <td><Skeleton height="20px" width="80px" /></td>
                  <td><Skeleton height="20px" width="60px" /></td>
                </tr>
              ))
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                  No alert facts found matching current filters.
                </td>
              </tr>
            ) : (
              alerts.map((fact) => (
                <tr key={fact.fact_key}>
                  <td>
                    <PriorityBadge priority={fact.priority} />
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.8rem' }}>
                    {fact.sid !== null ? fact.sid : '—'}
                  </td>
                  <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>
                    {fact.message || '—'}
                  </td>
                  <td>
                    <span className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      {fact.source_ip}
                    </span>
                  </td>
                  <td>
                    <span className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                      {fact.target_ip}
                    </span>
                  </td>
                  <td>
                    {fact.protocol ? <Tag label={fact.protocol} variant="slate" /> : '—'}
                  </td>
                  <td className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    {fact.src_port !== null ? fact.src_port : '—'} ➔ {fact.dst_port !== null ? fact.dst_port : '—'}
                  </td>
                  <td>
                    <span
                      className="font-mono"
                      style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
                      title={fact.fact_key}
                    >
                      {fact.fact_key.slice(0, 8)}...{fact.fact_key.slice(-4)}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn-secondary"
                      onClick={() => handleInspectFact(fact.fact_key)}
                      style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}
                    >
                      Inspect
                    </button>
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
          itemLabel="alert facts"
        />
      )}

      {/* Alert Fact Detail Modal */}
      <Modal
        isOpen={selectedFactKey !== null}
        onClose={() => setSelectedFactKey(null)}
        title="Alert Fact Details"
        maxWidth="650px"
      >
        {factLoading ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <Skeleton height="30px" />
            <Skeleton height="60px" />
            <Skeleton height="100px" />
          </div>
        ) : selectedFact ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Fact Key Banner */}
            <div className="card" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-app)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.3rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  Deterministic SHA-256 Fact Key
                </span>
                <button
                  onClick={() => handleCopyFactKey(selectedFact.fact_key)}
                  style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.75rem', color: 'var(--accent-cyan)' }}
                >
                  {copiedKey ? <Check size={14} /> : <Copy size={14} />}
                  <span>{copiedKey ? 'Copied!' : 'Copy Key'}</span>
                </button>
              </div>
              <div style={{ fontFamily: 'var(--font-family-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>
                {selectedFact.fact_key}
              </div>
            </div>

            {/* Message & Priority */}
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
                <PriorityBadge priority={selectedFact.priority} />
                <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                  Signature ID: <strong className="font-mono" style={{ color: 'var(--text-primary)' }}>{selectedFact.sid !== null ? selectedFact.sid : 'None'}</strong>
                </span>
              </div>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600 }}>
                {selectedFact.message || 'No description provided'}
              </h3>
            </div>

            {/* Metadata Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.75rem' }}>
              <div className="card" style={{ padding: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Generator ID (GID)</div>
                <div className="font-mono" style={{ fontSize: '1rem', fontWeight: 600 }}>{selectedFact.gid !== null ? selectedFact.gid : '—'}</div>
              </div>
              <div className="card" style={{ padding: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Revision (REV)</div>
                <div className="font-mono" style={{ fontSize: '1rem', fontWeight: 600 }}>{selectedFact.rev !== null ? selectedFact.rev : '—'}</div>
              </div>
              <div className="card" style={{ padding: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Protocol</div>
                <div className="font-mono" style={{ fontSize: '1rem', fontWeight: 600 }}>{selectedFact.protocol || '—'}</div>
              </div>
            </div>

            {/* Connection Endpoints */}
            <div className="card" style={{ padding: '1rem' }}>
              <h4 style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.75rem' }}>
                Source & Target Endpoints
              </h4>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Source IP : Port</div>
                  <div className="font-mono" style={{ fontSize: '1rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {selectedFact.source_ip} : {selectedFact.src_port !== null ? selectedFact.src_port : '*'}
                  </div>
                </div>

                <div style={{ fontSize: '1.25rem', color: 'var(--text-muted)' }}>→</div>

                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Target IP : Port</div>
                  <div className="font-mono" style={{ fontSize: '1rem', color: 'var(--text-primary)', fontWeight: 600 }}>
                    {selectedFact.target_ip} : {selectedFact.dst_port !== null ? selectedFact.dst_port : '*'}
                  </div>
                </div>
              </div>
            </div>

            {/* Investigation Pivot Actions */}
            {onNavigate && (
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button
                  className="btn-primary"
                  onClick={() => {
                    setSelectedFactKey(null);
                    onNavigate('network', { centerIp: selectedFact.source_ip });
                  }}
                  style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                >
                  <Network size={14} />
                  <span>Investigate Source in Graph</span>
                </button>

                <button
                  className="btn-secondary"
                  onClick={() => {
                    setSelectedFactKey(null);
                    onNavigate('path', { sourceIp: selectedFact.source_ip, targetIp: selectedFact.target_ip });
                  }}
                  style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                >
                  <Route size={14} />
                  <span>Find Communication Path</span>
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="warning-banner">Could not load alert fact details.</div>
        )}
      </Modal>
    </div>
  );
};
