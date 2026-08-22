import React, { useEffect, useState, useCallback, useRef } from 'react';
import { getNeighborhood } from '../api/graph';
import { listIPs } from '../api/network';
import type { GraphNeighborhoodResponse, IPAddressResponse } from '../api/types';
import { CytoscapeCanvas } from '../components/graph/CytoscapeCanvas';
import type { LayoutName, CytoscapeCanvasHandle } from '../components/graph/CytoscapeCanvas';
import { GraphControls } from '../components/graph/GraphControls';
import { GraphLegend } from '../components/graph/GraphLegend';
import { SlideDrawer } from '../components/layout/SlideDrawer';
import { IPDetailPanel } from '../components/network/IPDetailPanel';
import { Layer2DetailPanel } from '../components/network/Layer2DetailPanel';
import { Skeleton } from '../components/common/Skeleton';
import type { ActiveView } from '../components/layout/Header';

interface NetworkExplorerPageProps {
  initialCenterIp?: string | null;
  onNavigate?: (view: ActiveView, context?: { sourceIp?: string; targetIp?: string }) => void;
}

export const NetworkExplorerPage: React.FC<NetworkExplorerPageProps> = ({
  initialCenterIp,
  onNavigate,
}) => {
  const canvasRef = useRef<CytoscapeCanvasHandle>(null);
  const [centerInput, setCenterInput] = useState<string>(initialCenterIp || '192.168.1.100');
  const [depth, setDepth] = useState<1 | 2>(1);
  const [maxNodes, setMaxNodes] = useState<number>(50);
  const [layoutName, setLayoutName] = useState<LayoutName>('cose');

  // Graph state
  const [graphData, setGraphData] = useState<GraphNeighborhoodResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Selected node state
  const [selectedNode, setSelectedNode] = useState<{
    id: string;
    type: 'IPAddress' | 'Layer2Identifier';
    value: string;
  } | null>(null);

  // Observed IP quick-pick list with pagination support
  const [ipList, setIpList] = useState<IPAddressResponse[]>([]);
  const [ipOffset, setIpOffset] = useState<number>(0);
  const [ipTotal, setIpTotal] = useState<number>(0);
  const IP_PAGE_SIZE = 50;

  // Fetch observed IPs when offset changes
  useEffect(() => {
    let isCancelled = false;
    listIPs(IP_PAGE_SIZE, ipOffset)
      .then((res) => {
        if (!isCancelled) {
          setIpList(res.items);
          setIpTotal(res.total);
        }
      })
      .catch(() => {
        // Fallback gracefully
      });
    return () => {
      isCancelled = true;
    };
  }, [ipOffset]);

  // Execute graph query
  const handleFetchGraph = useCallback((addressToQuery: string) => {
    if (!addressToQuery.trim()) return;

    setLoading(true);
    setError(null);
    setSelectedNode(null);

    getNeighborhood(addressToQuery.trim(), depth, maxNodes)
      .then((data) => {
        setGraphData(data);
        setCenterInput(data.center);
        setLoading(false);
      })
      .catch((err: Error) => {
        setError(err.message);
        setGraphData(null);
        setLoading(false);
      });
  }, [depth, maxNodes]);

  // Query on mount or when initialCenterIp changes
  useEffect(() => {
    const targetIp = initialCenterIp || centerInput;
    if (targetIp) {
      setCenterInput(targetIp);
      handleFetchGraph(targetIp);
    }
  }, [initialCenterIp]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleFetchGraph(centerInput);
  };

  const handleReCenter = (newAddress: string) => {
    setCenterInput(newAddress);
    handleFetchGraph(newAddress);
  };

  const totalIpPages = Math.max(1, Math.ceil(ipTotal / IP_PAGE_SIZE));
  const currentIpPage = Math.floor(ipOffset / IP_PAGE_SIZE) + 1;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', position: 'relative', overflow: 'hidden' }}>
      {/* Top Controls Toolbar */}
      <div
        style={{
          padding: '0.75rem 1.25rem',
          backgroundColor: 'var(--bg-card)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.75rem',
          zIndex: 10,
        }}
      >
        <form onSubmit={handleFormSubmit} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          {/* Manual Input */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <label htmlFor="center-ip-input" style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Center IP:
            </label>
            <input
              id="center-ip-input"
              type="text"
              value={centerInput}
              onChange={(e) => setCenterInput(e.target.value)}
              placeholder="e.g. 192.168.1.100"
              style={{ width: '150px', fontFamily: 'var(--font-family-mono)', fontSize: '0.85rem' }}
            />
          </div>

          {/* Quick Select from Observed IPs */}
          {ipList.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <label htmlFor="ip-select" style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                or Browse:
              </label>
              <select
                id="ip-select"
                value={centerInput}
                onChange={(e) => {
                  setCenterInput(e.target.value);
                  handleFetchGraph(e.target.value);
                }}
                style={{ fontSize: '0.8rem', maxWidth: '160px' }}
              >
                <option value="" disabled>Select observed IP</option>
                {ipList.map((ip) => (
                  <option key={ip.address} value={ip.address}>
                    {ip.address}
                  </option>
                ))}
              </select>

              {/* IP Pagination Controls when total > 50 */}
              {ipTotal > IP_PAGE_SIZE && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={ipOffset <= 0}
                    onClick={() => setIpOffset((prev) => Math.max(0, prev - IP_PAGE_SIZE))}
                    style={{ padding: '0.15rem 0.35rem', fontSize: '0.7rem' }}
                    title="Previous IP page"
                  >
                    ◀
                  </button>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    {currentIpPage}/{totalIpPages}
                  </span>
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={ipOffset + IP_PAGE_SIZE >= ipTotal}
                    onClick={() => setIpOffset((prev) => prev + IP_PAGE_SIZE)}
                    style={{ padding: '0.15rem 0.35rem', fontSize: '0.7rem' }}
                    title="Next IP page"
                  >
                    ▶
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Depth Toggle */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Depth:</label>
            <div style={{ display: 'flex', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', overflow: 'hidden' }}>
              <button
                type="button"
                onClick={() => setDepth(1)}
                style={{
                  padding: '0.3rem 0.6rem',
                  fontSize: '0.75rem',
                  backgroundColor: depth === 1 ? 'var(--accent-cyan-dim)' : 'transparent',
                  color: depth === 1 ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  fontWeight: depth === 1 ? 600 : 400,
                }}
              >
                1 Hop
              </button>
              <button
                type="button"
                onClick={() => setDepth(2)}
                style={{
                  padding: '0.3rem 0.6rem',
                  fontSize: '0.75rem',
                  backgroundColor: depth === 2 ? 'var(--accent-cyan-dim)' : 'transparent',
                  color: depth === 2 ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  fontWeight: depth === 2 ? 600 : 400,
                  borderLeft: '1px solid var(--border-subtle)',
                }}
              >
                2 Hops
              </button>
            </div>
          </div>

          {/* Max Nodes */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <label htmlFor="max-nodes" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              Max Nodes:
            </label>
            <select
              id="max-nodes"
              value={maxNodes}
              onChange={(e) => setMaxNodes(Number(e.target.value))}
              style={{ fontSize: '0.8rem' }}
            >
              <option value="25">25</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>

          <button type="submit" className="btn-primary" disabled={loading} style={{ fontSize: '0.8rem' }}>
            {loading ? 'Investigating...' : 'Investigate'}
          </button>
        </form>

        {/* Graph Controls Toolbar */}
        <GraphControls
          layoutName={layoutName}
          onLayoutChange={setLayoutName}
          onZoomIn={() => canvasRef.current?.zoomIn()}
          onZoomOut={() => canvasRef.current?.zoomOut()}
          onFit={() => canvasRef.current?.fit()}
          onReset={() => {
            canvasRef.current?.reset();
            if (graphData) {
              handleFetchGraph(graphData.center);
            }
          }}
        />
      </div>

      {/* Main Canvas Workspace */}
      <div style={{ flex: 1, position: 'relative', minHeight: '400px' }}>
        {loading ? (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              backgroundColor: 'var(--bg-canvas)',
              zIndex: 20,
              gap: '1rem',
            }}
          >
            <div style={{ width: '200px' }}>
              <Skeleton height="8px" />
            </div>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Querying graph neighborhood for {centerInput}...
            </span>
          </div>
        ) : error ? (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '2rem',
              textAlign: 'center',
            }}
          >
            <div className="warning-banner" style={{ maxWidth: '500px' }}>
              <strong>Neighborhood Query Error:</strong>
              <div style={{ marginTop: '0.25rem' }}>{error}</div>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>
              Verify that the address is a valid IPv4/IPv6 address observed in the dataset.
            </p>
          </div>
        ) : graphData && graphData.nodes.length > 0 ? (
          <CytoscapeCanvas
            ref={canvasRef}
            data={graphData}
            layoutName={layoutName}
            onNodeSelect={setSelectedNode}
            selectedNodeId={selectedNode?.id}
          />
        ) : (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-muted)',
            }}
          >
            No graph data to display. Enter an IP address above to begin investigation.
          </div>
        )}

        {/* Floating Legend */}
        <div style={{ position: 'absolute', bottom: '1rem', left: '1rem', zIndex: 10 }}>
          <GraphLegend />
        </div>

        {/* Slide Drawer for Selected Node Details */}
        <SlideDrawer
          isOpen={selectedNode !== null}
          onClose={() => setSelectedNode(null)}
          title={selectedNode?.type === 'IPAddress' ? 'IP Investigation' : 'Layer 2 Inspection'}
          subtitle={selectedNode ? selectedNode.id : undefined}
        >
          {selectedNode?.type === 'IPAddress' && (
            <IPDetailPanel
              address={selectedNode.value}
              onSelectCenter={(addr) => {
                setSelectedNode(null);
                handleReCenter(addr);
              }}
              onSetPathSource={(addr) => {
                if (onNavigate) {
                  onNavigate('path', { sourceIp: addr });
                }
              }}
              onSetPathTarget={(addr) => {
                if (onNavigate) {
                  onNavigate('path', { targetIp: addr });
                }
              }}
            />
          )}
          {selectedNode?.type === 'Layer2Identifier' && (
            <Layer2DetailPanel identifier={selectedNode.value} />
          )}
        </SlideDrawer>
      </div>
    </div>
  );
};
