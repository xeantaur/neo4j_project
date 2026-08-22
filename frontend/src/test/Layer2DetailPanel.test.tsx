import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Layer2DetailPanel } from '../components/network/Layer2DetailPanel';

describe('Layer2DetailPanel Component', () => {
  it('renders Layer 2 identifier without querying IP endpoints or assuming device identity', () => {
    const fetchMock = vi.fn();
    globalThis.fetch = fetchMock as unknown as typeof fetch;

    render(<Layer2DetailPanel identifier="00:50:56:c0:00:08" />);

    expect(screen.getByText('00:50:56:c0:00:08')).toBeInTheDocument();
    expect(screen.getAllByText(/Observed Layer 2 Identifier/i).length).toBeGreaterThan(0);

    // Verify zero API calls are made for Layer2 detail panel
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
