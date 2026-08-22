import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { IPDetailPanel } from '../components/network/IPDetailPanel';

describe('IPDetailPanel Component', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('renders IP detail and flow counts for IPv4 and IPv6 without assuming device identity', async () => {
    const mockDetail = {
      address: '2001:db8::1',
      layer2_identifiers: ['00:50:56:c0:00:08', 'gateway.local'],
      outbound_flows: 5,
      inbound_flows: 2,
      alerts_originated: 3,
      alerts_targeted: 1,
    };

    const mockPeers = {
      items: [
        {
          peer_address: '192.168.1.1',
          direction: 'outbound',
          protocols: ['TCP', 'HTTP'],
        },
      ],
      total: 1,
      limit: 10,
      offset: 0,
    };

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/peers')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockPeers) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockDetail) });
    }) as unknown as typeof fetch;

    render(<IPDetailPanel address="2001:db8::1" />);

    await waitFor(() => {
      expect(screen.getByText('2001:db8::1')).toBeInTheDocument();
      expect(screen.getByText('5')).toBeInTheDocument(); // Outbound
      expect(screen.getByText('2')).toBeInTheDocument(); // Inbound
      expect(screen.getByText('3')).toBeInTheDocument(); // Originated
      expect(screen.getByText('1')).toBeInTheDocument(); // Targeted
      expect(screen.getByText('00:50:56:c0:00:08')).toBeInTheDocument();
      expect(screen.getByText('gateway.local')).toBeInTheDocument();
    });

    // Verify peer list header is "Communicating Peers", NOT "Top Peers" or "Top 5"
    expect(screen.getByText(/Communicating Peers/i)).toBeInTheDocument();
    expect(screen.queryByText(/Top Peers/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Top 5/i)).not.toBeInTheDocument();
  });
});
