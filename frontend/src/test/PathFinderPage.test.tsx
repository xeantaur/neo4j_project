import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { PathFinderPage } from '../pages/PathFinderPage';

describe('PathFinderPage Component', () => {
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('renders communication path successfully with hop steps and protocols', async () => {
    const mockPath = {
      source: '192.168.1.100',
      target: '10.0.0.5',
      hops: ['192.168.1.100', '192.168.1.1', '10.0.0.5'],
      protocols: ['TCP', 'HTTP'],
      length: 2,
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(mockPath),
    }) as unknown as typeof fetch;

    render(<PathFinderPage initialSourceIp="192.168.1.100" initialTargetIp="10.0.0.5" />);

    const findButton = screen.getByRole('button', { name: /find path/i });
    fireEvent.click(findButton);

    await waitFor(() => {
      expect(screen.getByText('2 Hops from 192.168.1.100 to 10.0.0.5')).toBeInTheDocument();
      expect(screen.getByText('Step 1:')).toBeInTheDocument();
      expect(screen.getByText('Step 2:')).toBeInTheDocument();
      expect(screen.getByText('Protocol: TCP')).toBeInTheDocument();
      expect(screen.getByText('Protocol: HTTP')).toBeInTheDocument();
    });
  });

  it('handles 404 no communication path error gracefully', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: () =>
        Promise.resolve({
          detail: "No communication path found between '192.168.1.100' and '10.0.0.99' within 5 hops",
        }),
    }) as unknown as typeof fetch;

    render(<PathFinderPage initialSourceIp="192.168.1.100" initialTargetIp="10.0.0.99" />);

    const findButton = screen.getByRole('button', { name: /find path/i });
    fireEvent.click(findButton);

    await waitFor(() => {
      expect(
        screen.getByText(/No communication path found between '192.168.1.100' and '10.0.0.99' within 5 hops/i)
      ).toBeInTheDocument();
    });
  });
});
