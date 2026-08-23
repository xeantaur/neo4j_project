import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { NetworkExplorerPage } from '../pages/NetworkExplorerPage';
import type { CytoscapeEdgeData } from '../components/graph/transformGraphData';

// Mock CytoscapeCanvas to avoid canvas rendering dependencies in jsdom
vi.mock('../components/graph/CytoscapeCanvas', async () => {
  const React = await import('react');

  interface MockNode {
    id: string;
    type: 'IPAddress' | 'Layer2Identifier';
    value: string;
  }

  interface MockEdge {
    source: string;
    target: string;
    type: 'COMMUNICATED_TO' | 'OBSERVED_WITH';
    protocol: string | null;
    flow_key?: string | null;
    src_port?: number | null;
    dst_port?: number | null;
    observed_packet_count?: number | null;
    observed_bytes?: number | null;
    first_seen?: number | null;
    last_seen?: number | null;
    observed_window_seconds?: number | null;
  }

  interface MockProps {
    data: { nodes: MockNode[]; edges: MockEdge[] };
    onNodeSelect: (node: MockNode | null) => void;
    onEdgeSelect?: (edge: CytoscapeEdgeData | null) => void;
  }

  const MockCytoscape = React.forwardRef<unknown, MockProps>((props, ref) => {
    React.useImperativeHandle(ref, () => ({
      zoomIn: vi.fn(),
      zoomOut: vi.fn(),
      fit: vi.fn(),
      reset: vi.fn(),
    }));

    return (
      <div data-testid="mock-cytoscape-canvas">
        <span data-testid="canvas-node-count">{props.data.nodes.length} nodes</span>
        {props.data.nodes.map((n) => (
          <button
            key={n.id}
            data-testid={`mock-node-${n.id}`}
            onClick={() => props.onNodeSelect({ id: n.id, type: n.type, value: n.value })}
          >
            Select {n.type} {n.value}
          </button>
        ))}
        {props.data.edges.map((e, idx) => (
          <button
            key={`edge-${idx}`}
            data-testid={`mock-edge-${idx}`}
            onClick={() =>
              props.onEdgeSelect?.({
                id: `edge:${e.source}|${e.target}|${e.type}|${e.flow_key || e.protocol || 'none'}`,
                source: e.source,
                target: e.target,
                type: e.type,
                protocol: e.protocol,
                flow_key: e.flow_key ?? 'a'.repeat(64),
                src_port: e.src_port ?? 54321,
                dst_port: e.dst_port ?? 443,
                observed_packet_count: e.observed_packet_count ?? 120,
                observed_bytes: e.observed_bytes ?? 65536,
                first_seen: e.first_seen ?? 1718000000.0,
                last_seen: e.last_seen ?? 1718000500.0,
                observed_window_seconds: e.observed_window_seconds ?? 500.0,
                label: `${e.protocol || 'TCP'} · :${e.dst_port ?? 443}`,
              })
            }
          >
            Select Edge {e.type} {e.protocol}
          </button>
        ))}
        <button
          data-testid="mock-bg-click"
          onClick={() => {
            props.onNodeSelect(null);
            props.onEdgeSelect?.(null);
          }}
        >
          Deselect
        </button>
      </div>
    );
  });
  MockCytoscape.displayName = 'MockCytoscape';

  return { CytoscapeCanvas: MockCytoscape };
});

describe('NetworkExplorerPage Behavioral Tests', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  const mockNeighborhood = {
    center: '192.168.1.100',
    depth: 1,
    nodes: [
      { id: 'ip:192.168.1.100', type: 'IPAddress' as const, value: '192.168.1.100' },
      { id: 'ip:192.168.1.1', type: 'IPAddress' as const, value: '192.168.1.1' },
      { id: 'l2:00:50:56:c0:00:08', type: 'Layer2Identifier' as const, value: '00:50:56:c0:00:08' },
    ],
    edges: [
      {
        source: 'ip:192.168.1.100',
        target: 'ip:192.168.1.1',
        type: 'COMMUNICATED_TO' as const,
        protocol: 'TCP',
        flow_key: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
        src_port: 54321,
        dst_port: 443,
        observed_packet_count: 120,
        observed_bytes: 65536,
        first_seen: 1718000000.0,
        last_seen: 1718000500.0,
        observed_window_seconds: 500.0,
      },
      { source: 'ip:192.168.1.100', target: 'l2:00:50:56:c0:00:08', type: 'OBSERVED_WITH' as const, protocol: null },
    ],
  };

  const mockIpList = {
    items: [
      { address: '192.168.1.100' },
      { address: '192.168.1.1' },
      { address: '10.0.0.5' },
    ],
    total: 150, // More than 50 to test pagination
    limit: 50,
    offset: 0,
  };

  const mockIpDetail = {
    address: '192.168.1.1',
    layer2_identifiers: ['00:50:56:c0:00:08'],
    outbound_flows: 10,
    inbound_flows: 4,
    alerts_originated: 1,
    alerts_targeted: 0,
    traffic_metrics_mode: 'enriched',
    distinct_outbound_peers: 5,
    distinct_inbound_peers: 3,
    distinct_destination_ports: 2,
    observed_packets_sent: 500,
    observed_packets_received: 200,
    observed_bytes_sent: 45000,
    observed_bytes_received: 12000,
    first_observed: 1718000000.0,
    last_observed: 1718000500.0,
  };

  const mockPeers = {
    items: [{ peer_address: '192.168.1.100', direction: 'inbound', protocols: ['TCP'] }],
    total: 1,
    limit: 10,
    offset: 0,
  };

  it('A. IP Node Selection: opens IP detail drawer, queries IP detail, and supports re-centering', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/graph/neighborhood/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockNeighborhood) });
      }
      if (url.includes('/api/v1/network/ips?')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpList) });
      }
      if (url.includes('/peers')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPeers) });
      }
      if (url.includes('/api/v1/network/ips/192.168.1.1')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpDetail) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    }) as unknown as typeof fetch;

    render(<NetworkExplorerPage initialCenterIp="192.168.1.100" />);

    // Wait for graph to load
    await waitFor(() => {
      expect(screen.getByTestId('canvas-node-count')).toHaveTextContent('3 nodes');
    });

    // Select peer IP node
    const peerNodeBtn = screen.getByTestId('mock-node-ip:192.168.1.1');
    fireEvent.click(peerNodeBtn);

    // Verify IP investigation drawer opened
    await waitFor(() => {
      expect(screen.getByText('IP Investigation')).toBeInTheDocument();
      expect(screen.getByText('Investigate as Center')).toBeInTheDocument();
      expect(screen.getByText('Path From Here')).toBeInTheDocument();
      expect(screen.getByText('Path To Here')).toBeInTheDocument();
    });

    // Click "Investigate as Center"
    const centerBtn = screen.getByText('Investigate as Center');
    fireEvent.click(centerBtn);

    // Verify neighborhood query was triggered for the new center IP
    await waitFor(() => {
      const fetchCalls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const neighborhoodCall = fetchCalls.find((c) => String(c[0]).includes('/neighborhood/192.168.1.1'));
      expect(neighborhoodCall).toBeDefined();
    });
  });

  it('B. Layer 2 Node Selection: opens Layer 2 drawer, makes NO IP detail request, and has NO center or path actions', async () => {
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/graph/neighborhood/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockNeighborhood) });
      }
      if (url.includes('/api/v1/network/ips?')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpList) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    });
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    render(<NetworkExplorerPage initialCenterIp="192.168.1.100" />);

    await waitFor(() => {
      expect(screen.getByTestId('canvas-node-count')).toHaveTextContent('3 nodes');
    });

    // Select Layer 2 node
    const l2NodeBtn = screen.getByTestId('mock-node-l2:00:50:56:c0:00:08');
    fireEvent.click(l2NodeBtn);

    // Verify Layer 2 Inspection drawer opened
    await waitFor(() => {
      expect(screen.getByText('Layer 2 Inspection')).toBeInTheDocument();
      expect(screen.getByText('00:50:56:c0:00:08')).toBeInTheDocument();
    });

    // Verify NO IP detail request was made for Layer 2 identifier
    const ipDetailCalls = fetchMock.mock.calls.filter((c) =>
      String(c[0]).includes('/api/v1/network/ips/00:50:56:c0:00:08')
    );
    expect(ipDetailCalls.length).toBe(0);

    // Verify Layer 2 node CANNOT become center and CANNOT be sent to Path Finder
    expect(screen.queryByText('Investigate as Center')).not.toBeInTheDocument();
    expect(screen.queryByText('Path From Here')).not.toBeInTheDocument();
    expect(screen.queryByText('Path To Here')).not.toBeInTheDocument();
  });

  it('C. Observed IP Entry: handles manual IPv4, IPv6 input, and pagination of observed IP browser', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/graph/neighborhood/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockNeighborhood) });
      }
      if (url.includes('/api/v1/network/ips?')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpList) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    }) as unknown as typeof fetch;

    render(<NetworkExplorerPage initialCenterIp="192.168.1.100" />);

    // Test IP browser pagination controls (total 150 items -> 3 pages)
    await waitFor(() => {
      expect(screen.getByText('1/3')).toBeInTheDocument();
    });

    // Click next page in IP browser
    const nextIpPageBtn = screen.getByTitle('Next IP page');
    fireEvent.click(nextIpPageBtn);

    await waitFor(() => {
      const fetchCalls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const paginatedCall = fetchCalls.find((c) => String(c[0]).includes('offset=50'));
      expect(paginatedCall).toBeDefined();
    });

    // Test direct manual IPv6 input
    const input = screen.getByLabelText(/center ip:/i);
    fireEvent.change(input, { target: { value: '2001:db8::1' } });
    const form = input.closest('form');
    fireEvent.submit(form!);

    await waitFor(() => {
      const fetchCalls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls;
      const ipv6Call = fetchCalls.find((c) => String(c[0]).includes(encodeURIComponent('2001:db8::1')));
      expect(ipv6Call).toBeDefined();
    });
  });

  it('D. Graph States: handles 404 center not found and 503 database unavailable states', async () => {
    // 1. Test 404 center IP not observed
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/graph/neighborhood/')) {
        return Promise.resolve({
          ok: false,
          status: 404,
          statusText: 'Not Found',
          json: () => Promise.resolve({ detail: "IP address '192.0.2.1' not found in graph" }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpList) });
    }) as unknown as typeof fetch;

    const { rerender } = render(<NetworkExplorerPage initialCenterIp="192.0.2.1" />);

    await waitFor(() => {
      expect(screen.getByText("IP address '192.0.2.1' not found in graph")).toBeInTheDocument();
      expect(screen.getByText(/Verify that the address is a valid IPv4\/IPv6 address/i)).toBeInTheDocument();
    });

    // 2. Test 503 Neo4j unavailable
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/graph/neighborhood/')) {
        return Promise.resolve({
          ok: false,
          status: 503,
          statusText: 'Service Unavailable',
          json: () => Promise.resolve({ detail: 'Database unavailable' }),
        });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpList) });
    }) as unknown as typeof fetch;

    rerender(<NetworkExplorerPage initialCenterIp="10.0.0.1" />);

    await waitFor(() => {
      expect(screen.getByText('Database unavailable')).toBeInTheDocument();
    });
  });

  it('E. Layout Configuration: defaults to COSE (Force Directed) and allows switching layouts', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/graph/neighborhood/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockNeighborhood) });
      }
      if (url.includes('/api/v1/network/ips?')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpList) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    }) as unknown as typeof fetch;

    render(<NetworkExplorerPage initialCenterIp="192.168.1.100" />);

    await waitFor(() => {
      expect(screen.getByTestId('canvas-node-count')).toHaveTextContent('3 nodes');
    });

    const layoutSelect = screen.getByTitle('Select graph layout') as HTMLSelectElement;
    expect(layoutSelect.value).toBe('cose');

    // Verify option labels and order
    const options = Array.from(layoutSelect.options).map((o) => ({ value: o.value, text: o.text }));
    expect(options).toEqual([
      { value: 'cose', text: 'COSE (Force Directed)' },
      { value: 'breadthfirst', text: 'Breadthfirst (Hierarchical)' },
      { value: 'concentric', text: 'Concentric' },
    ]);

    // Switch to breadthfirst
    fireEvent.change(layoutSelect, { target: { value: 'breadthfirst' } });
    expect(layoutSelect.value).toBe('breadthfirst');
  });

  it('F. Communication Edge Selection: opens drawer with CommunicationEdgePanel displaying ports, timestamps, volume, and flow key', async () => {
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/graph/neighborhood/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockNeighborhood) });
      }
      if (url.includes('/api/v1/network/ips?')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockIpList) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    }) as unknown as typeof fetch;

    render(<NetworkExplorerPage initialCenterIp="192.168.1.100" />);

    await waitFor(() => {
      expect(screen.getByTestId('canvas-node-count')).toHaveTextContent('3 nodes');
    });

    // Click communication edge
    const commEdgeBtn = screen.getByTestId('mock-edge-0');
    fireEvent.click(commEdgeBtn);

    // Verify Communication Edge drawer opened
    await waitFor(() => {
      expect(screen.getByText('Observed Communication Aggregate')).toBeInTheDocument();
      expect(screen.getByText('Protocol & Transport Ports')).toBeInTheDocument();
      expect(screen.getByText('54321')).toBeInTheDocument();
      expect(screen.getByText('443')).toBeInTheDocument();
      expect(screen.getByText('64.00 KiB')).toBeInTheDocument();
      expect(screen.getByText('120')).toBeInTheDocument();
      expect(screen.getByText(/abcdef1234567890/i)).toBeInTheDocument();
    });
  });
});
