import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { NetworkExplorerPage } from '../pages/NetworkExplorerPage';

// Mock CytoscapeCanvas to avoid canvas rendering dependencies in jsdom
vi.mock('../components/graph/CytoscapeCanvas', async () => {
  const React = await import('react');

  interface MockNode {
    id: string;
    type: 'IPAddress' | 'Layer2Identifier';
    value: string;
  }

  interface MockProps {
    data: { nodes: MockNode[] };
    onNodeSelect: (node: MockNode | null) => void;
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
        <button data-testid="mock-bg-click" onClick={() => props.onNodeSelect(null)}>
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
      { source: 'ip:192.168.1.100', target: 'ip:192.168.1.1', type: 'COMMUNICATED_TO' as const, protocol: 'TCP' },
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
});
