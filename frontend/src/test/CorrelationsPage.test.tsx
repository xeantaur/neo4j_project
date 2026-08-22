import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { CorrelationsPage } from '../pages/CorrelationsPage';

describe('CorrelationsPage Component', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('renders correlation records and uses neutral correlation wording', async () => {
    const mockCorrelations = {
      items: [
        {
          source_ip: '192.168.1.100',
          target_ip: '192.168.1.1',
          traffic_protocol: 'TCP',
          fact_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          sid: 2001219,
          message: 'ET SCAN Potential SSH Scan',
          priority: 1,
          alert_protocol: 'TCP',
        },
      ],
      total: 1,
      limit: 50,
      offset: 0,
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockCorrelations),
    }) as unknown as typeof fetch;

    render(<CorrelationsPage />);

    await waitFor(() => {
      expect(screen.getByText('ET SCAN Potential SSH Scan')).toBeInTheDocument();
      expect(screen.getByText('192.168.1.100')).toBeInTheDocument();
      expect(screen.getByText('192.168.1.1')).toBeInTheDocument();
    });

    // Verify footer wording is "correlation records", NOT "pairs"
    expect(screen.getByText(/correlation records/i)).toBeInTheDocument();
    expect(screen.queryByText(/correlated pairs/i)).not.toBeInTheDocument();
  });
});
