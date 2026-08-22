import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { AlertExplorerPage } from '../pages/AlertExplorerPage';

describe('AlertExplorerPage Component', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('renders alert facts table with exact numeric priority and handles null fields', async () => {
    const mockAlerts = {
      items: [
        {
          fact_key: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
          source_ip: '192.168.1.100',
          target_ip: '192.168.1.1',
          sid: 2001219,
          gid: 1,
          rev: 1,
          message: 'ET SCAN Potential SSH Scan',
          priority: 1,
          protocol: 'TCP',
          src_port: 54321,
          dst_port: 22,
        },
        {
          fact_key: 'abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789',
          source_ip: '10.0.0.5',
          target_ip: '192.168.1.100',
          sid: null,
          gid: null,
          rev: null,
          message: null,
          priority: null, // Null priority
          protocol: null,
          src_port: null,
          dst_port: null,
        },
      ],
      total: 2,
      limit: 50,
      offset: 0,
    };

    globalThis.fetch = vi.fn().mockImplementation((url: string) => {
      if (url.includes('/api/v1/alerts/')) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve(mockAlerts.items[0]) });
      }
      return Promise.resolve({ ok: true, json: () => Promise.resolve(mockAlerts) });
    }) as unknown as typeof fetch;

    render(<AlertExplorerPage />);

    await waitFor(() => {
      expect(screen.getByText('ET SCAN Potential SSH Scan')).toBeInTheDocument();
      expect(screen.getAllByText('Priority 1').length).toBeGreaterThan(0);
      expect(screen.getByText('Unknown')).toBeInTheDocument(); // Priority null -> Unknown
    });

    // Verify invented severity labels are NOT present
    expect(screen.queryByText('Critical')).not.toBeInTheDocument();
    expect(screen.queryByText('High')).not.toBeInTheDocument();

    // Test Inspect modal
    const inspectButtons = screen.getAllByText('Inspect');
    fireEvent.click(inspectButtons[0]);

    await waitFor(() => {
      expect(screen.getByText('Alert Fact Details')).toBeInTheDocument();
      expect(screen.getByText('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')).toBeInTheDocument();
    });
  });
});
