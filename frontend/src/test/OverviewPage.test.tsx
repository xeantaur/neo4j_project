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
    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
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
      expect(screen.getByText('16')).toBeInTheDocument();
      expect(screen.getByText('6')).toBeInTheDocument();
    });

    // Check titles
    expect(screen.getByText('Observed IP Addresses')).toBeInTheDocument();
    expect(screen.getByText('Layer 2 Identifiers')).toBeInTheDocument();
    expect(screen.getByText('Security Alert Facts')).toBeInTheDocument();
    expect(screen.getByText('L3 Communications')).toBeInTheDocument();
    expect(screen.getByText('Traffic / Alert Correlations')).toBeInTheDocument();

    // Confirm that "Correlated Pairs" is NOT used
    expect(screen.queryByText(/Correlated Pairs/i)).not.toBeInTheDocument();
  });
});
