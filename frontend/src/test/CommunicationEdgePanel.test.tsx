import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { CommunicationEdgePanel } from '../components/network/CommunicationEdgePanel';
import type { CytoscapeEdgeData } from '../components/graph/transformGraphData';

describe('CommunicationEdgePanel Component', () => {
  const mockEnrichedEdge: CytoscapeEdgeData = {
    id: 'edge:ip%3A192.168.1.100|ip%3A192.168.1.1|COMMUNICATED_TO|flow_key_123',
    source: 'ip:192.168.1.100',
    target: 'ip:192.168.1.1',
    type: 'COMMUNICATED_TO',
    protocol: 'TCP',
    flow_key: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
    src_port: 54321,
    dst_port: 443,
    observed_packet_count: 250,
    observed_bytes: 131072,
    first_seen: 1718000000.0,
    last_seen: 1718000500.0,
    observed_window_seconds: 500.0,
    label: 'TCP · :443',
  };

  const mockBasicEdge: CytoscapeEdgeData = {
    id: 'edge:ip%3A10.0.0.1|ip%3A10.0.0.2|COMMUNICATED_TO|UDP',
    source: 'ip:10.0.0.1',
    target: 'ip:10.0.0.2',
    type: 'COMMUNICATED_TO',
    protocol: 'UDP',
    flow_key: null,
    src_port: null,
    dst_port: null,
    observed_packet_count: null,
    observed_bytes: null,
    first_seen: null,
    last_seen: null,
    observed_window_seconds: null,
    label: 'UDP',
  };

  it('renders enriched communication edge metrics and handles action callbacks', () => {
    const onSelectCenterMock = vi.fn();
    const onSetPathEndpointsMock = vi.fn();

    render(
      <CommunicationEdgePanel
        edge={mockEnrichedEdge}
        onSelectCenter={onSelectCenterMock}
        onSetPathEndpoints={onSetPathEndpointsMock}
      />
    );

    // Endpoint values without 'ip:' prefix
    expect(screen.getByText('192.168.1.100')).toBeInTheDocument();
    expect(screen.getByText('192.168.1.1')).toBeInTheDocument();

    // Protocol and ports
    expect(screen.getByText('TCP')).toBeInTheDocument();
    expect(screen.getByText('54321')).toBeInTheDocument();
    expect(screen.getByText('443')).toBeInTheDocument();

    // Volume metrics
    expect(screen.getByText('250')).toBeInTheDocument();
    expect(screen.getByText('128.00 KiB')).toBeInTheDocument();
    expect(screen.getByText('500.00s')).toBeInTheDocument();

    // Flow key
    expect(
      screen.getByText('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')
    ).toBeInTheDocument();

    // Action button clicks
    fireEvent.click(screen.getByText('Center on Source'));
    expect(onSelectCenterMock).toHaveBeenCalledWith('192.168.1.100');

    fireEvent.click(screen.getByText('Center on Target'));
    expect(onSelectCenterMock).toHaveBeenCalledWith('192.168.1.1');

    fireEvent.click(screen.getByText('Find Shortest Path'));
    expect(onSetPathEndpointsMock).toHaveBeenCalledWith('192.168.1.100', '192.168.1.1');
  });

  it('renders legacy basic communication edge with fallback notice', () => {
    render(<CommunicationEdgePanel edge={mockBasicEdge} />);

    expect(screen.getByText('10.0.0.1')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.2')).toBeInTheDocument();
    expect(screen.getByText('UDP')).toBeInTheDocument();
    expect(
      screen.getByText(/Detailed packet, frame-byte, and timing metrics are unavailable/i)
    ).toBeInTheDocument();
    expect(screen.getByText('None (Legacy basic aggregate)')).toBeInTheDocument();
  });
});
