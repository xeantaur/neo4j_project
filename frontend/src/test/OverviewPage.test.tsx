import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { OverviewPage } from '../pages/OverviewPage';

describe('OverviewPage Component', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('renders entity metric cards with correct totals and semantic labels', async () => {
    const mockSummary = {
      traffic_metrics_mode: 'enriched',
      total_communication_aggregates: 16,
      enriched_communication_aggregates: 16,
      basic_communication_aggregates: 0,
      total_observed_packets: 4500,
      total_observed_bytes: 524288,
      first_observed: 1718000000.0,
      last_observed: 1718000500.0,
      protocol_distribution: [
        { protocol: 'TCP', communication_aggregate_count: 10, observed_packet_count: 3000, observed_bytes: 400000 },
      ],
      destination_port_distribution: [
        { dst_port: 443, communication_aggregate_count: 8, observed_packet_count: 2500, observed_bytes: 350000 },
      ],
      top_fan_out: [
        { address: '192.168.1.100', distinct_destination_ips: 5 },
      ],
      top_fan_in: [
        { address: '192.168.1.1', distinct_source_ips: 8 },
      ],
    };

    const mockEndpoints = {
      items: [
        {
          address: '192.168.1.100',
          outbound_communication_aggregates: 10,
          inbound_communication_aggregates: 2,
          distinct_outbound_peers: 5,
          distinct_inbound_peers: 2,
          distinct_destination_ports: 3,
          observed_packets_sent: 3000,
          observed_packets_received: 500,
          observed_bytes_sent: 400000,
          observed_bytes_received: 50000,
          first_observed: 1718000000.0,
          last_observed: 1718000500.0,
          traffic_metrics_mode: 'enriched',
        },
      ],
      total: 1,
      limit: 10,
      offset: 0,
    };

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/network/analytics/summary')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockSummary) });
      }
      if (url.includes('/api/v1/network/analytics/endpoints')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockEndpoints) });
      }
      if (url.includes('/api/v1/network/ips')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ items: [], total: 14, limit: 1, offset: 0 }) });
      }
      if (url.includes('/api/v1/network/layer2')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ items: [], total: 12, limit: 1, offset: 0 }) });
      }
      if (url.includes('/api/v1/alerts')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ items: [], total: 11, limit: 1, offset: 0 }) });
      }
      if (url.includes('/api/v1/network/communications')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ items: [], total: 16, limit: 1, offset: 0 }) });
      }
      if (url.includes('/api/v1/correlations/traffic-alerts')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ items: [], total: 6, limit: 1, offset: 0 }) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ total: 0 }) });
    }) as unknown as typeof fetch;

    const onNavigateMock = vi.fn();
    render(<OverviewPage onNavigate={onNavigateMock} />);

    await waitFor(() => {
      expect(screen.getByText('14')).toBeInTheDocument();
      expect(screen.getByText('12')).toBeInTheDocument();
      expect(screen.getByText('11')).toBeInTheDocument();
      expect(screen.getAllByText('16').length).toBeGreaterThan(0);
      expect(screen.getByText('6')).toBeInTheDocument();
    });

    // Check titles
    expect(screen.getByText('Observed IP Addresses')).toBeInTheDocument();
    expect(screen.getByText('Layer 2 Identifiers')).toBeInTheDocument();
    expect(screen.getByText('Security Alert Facts')).toBeInTheDocument();
    expect(screen.getByText('L3 Communications')).toBeInTheDocument();
    expect(screen.getByText('Traffic / Alert Correlations')).toBeInTheDocument();

    // Check Traffic Analytics section
    expect(screen.getByText('Traffic Analytics & Volume Metrics')).toBeInTheDocument();
    expect(screen.getByText('512.00 KiB')).toBeInTheDocument();
    expect(screen.getByText('4,500')).toBeInTheDocument();
    expect(screen.getByText('Port 443')).toBeInTheDocument();
    expect(screen.getByText('Endpoint Rankings')).toBeInTheDocument();

    // Confirm that "Correlated Pairs" is NOT used
    expect(screen.queryByText(/Correlated Pairs/i)).not.toBeInTheDocument();
  });
});
