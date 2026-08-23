import { describe, it, expect } from 'vitest';
import {
  generateFrontendEdgeId,
  transformGraphToElements,
  formatBreadthfirstRootSelector,
} from '../components/graph/transformGraphData';
import type { GraphNeighborhoodResponse } from '../api/types';

describe('Graph Data Transformation', () => {
  it('generates deterministic frontend edge IDs', () => {
    const id1 = generateFrontendEdgeId('ip:192.168.1.1', 'ip:192.168.1.2', 'COMMUNICATED_TO', 'TCP');
    const id2 = generateFrontendEdgeId('ip:192.168.1.1', 'ip:192.168.1.2', 'COMMUNICATED_TO', 'TCP');
    const id3 = generateFrontendEdgeId('ip:192.168.1.1', 'ip:192.168.1.2', 'COMMUNICATED_TO', 'UDP');

    expect(id1).toBe(id2);
    expect(id1).not.toBe(id3);
    expect(id1).toContain('edge:');
  });

  it('formats breadthfirst root selector using safe attribute matching for IPv4 and IPv6 without fragile escaping', () => {
    // IPv4 with dots and colons
    const ipv4Selector = formatBreadthfirstRootSelector('ip:192.168.1.10');
    expect(ipv4Selector).toBe('[id = "ip:192.168.1.10"]');

    // IPv6 with multiple colons
    const ipv6Selector = formatBreadthfirstRootSelector('ip:2001:db8::1');
    expect(ipv6Selector).toBe('[id = "ip:2001:db8::1"]');

    // Layer 2 identifier with MAC colons
    const l2Selector = formatBreadthfirstRootSelector('l2:02:00:00:00:00:01');
    expect(l2Selector).toBe('[id = "l2:02:00:00:00:00:01"]');
  });

  it('transforms neighborhood response into Cytoscape elements with center node marked', () => {
    const mockData: GraphNeighborhoodResponse = {
      center: '192.168.1.100',
      depth: 1,
      nodes: [
        { id: 'ip:192.168.1.100', type: 'IPAddress', value: '192.168.1.100' },
        { id: 'ip:192.168.1.1', type: 'IPAddress', value: '192.168.1.1' },
        { id: 'l2:00:50:56:c0:00:08', type: 'Layer2Identifier', value: '00:50:56:c0:00:08' },
      ],
      edges: [
        {
          source: 'ip:192.168.1.100',
          target: 'ip:192.168.1.1',
          type: 'COMMUNICATED_TO',
          protocol: 'TCP',
          flow_key: null,
          src_port: null,
          dst_port: null,
          observed_packet_count: null,
          observed_bytes: null,
          first_seen: null,
          last_seen: null,
          observed_window_seconds: null,
        },
        {
          source: 'ip:192.168.1.100',
          target: 'l2:00:50:56:c0:00:08',
          type: 'OBSERVED_WITH',
          protocol: null,
          flow_key: null,
          src_port: null,
          dst_port: null,
          observed_packet_count: null,
          observed_bytes: null,
          first_seen: null,
          last_seen: null,
          observed_window_seconds: null,
        },
      ],
    };

    const elements = transformGraphToElements(mockData);

    // 3 nodes + 2 edges = 5 elements
    expect(elements.length).toBe(5);

    // Find center node
    const centerNode = elements.find((e) => e.data.id === 'ip:192.168.1.100');
    expect(centerNode).toBeDefined();
    if ('isCenter' in centerNode!.data) {
      expect(centerNode!.data.isCenter).toBe(true);
      expect(centerNode!.data.type).toBe('IPAddress');
    }

    // Find peer node
    const peerNode = elements.find((e) => e.data.id === 'ip:192.168.1.1');
    expect(peerNode).toBeDefined();
    if ('isCenter' in peerNode!.data) {
      expect(peerNode!.data.isCenter).toBe(false);
    }

    // Find L2 node
    const l2Node = elements.find((e) => e.data.id === 'l2:00:50:56:c0:00:08');
    expect(l2Node).toBeDefined();
    if ('type' in l2Node!.data) {
      expect(l2Node!.data.type).toBe('Layer2Identifier');
    }

    // Check edge labels
    const tcpEdge = elements.find((e) => 'protocol' in e.data && e.data.protocol === 'TCP');
    expect(tcpEdge).toBeDefined();
    if ('label' in tcpEdge!.data) {
      expect(tcpEdge!.data.label).toBe('TCP');
    }
  });

  it('generates unique edge IDs using flow_key and preserves parallel flows with different ports', () => {
    const mockData: GraphNeighborhoodResponse = {
      center: '10.0.0.1',
      depth: 1,
      nodes: [
        { id: 'ip:10.0.0.1', type: 'IPAddress', value: '10.0.0.1' },
        { id: 'ip:10.0.0.2', type: 'IPAddress', value: '10.0.0.2' },
      ],
      edges: [
        {
          source: 'ip:10.0.0.1',
          target: 'ip:10.0.0.2',
          type: 'COMMUNICATED_TO',
          protocol: 'TCP',
          flow_key: 'flow_key_1111111111111111111111111111111111111111111111111111111111111111',
          src_port: 50000,
          dst_port: 80,
          observed_packet_count: 10,
          observed_bytes: 1024,
          first_seen: 100.0,
          last_seen: 110.0,
          observed_window_seconds: 10.0,
        },
        {
          source: 'ip:10.0.0.1',
          target: 'ip:10.0.0.2',
          type: 'COMMUNICATED_TO',
          protocol: 'TCP',
          flow_key: 'flow_key_2222222222222222222222222222222222222222222222222222222222222222',
          src_port: 50001,
          dst_port: 443,
          observed_packet_count: 25,
          observed_bytes: 4096,
          first_seen: 105.0,
          last_seen: 115.0,
          observed_window_seconds: 10.0,
        },
      ],
    };

    const elements = transformGraphToElements(mockData);
    // 2 nodes + 2 distinct parallel edges = 4 elements
    expect(elements.length).toBe(4);

    const edge1 = elements.find(
      (e) => 'flow_key' in e.data && e.data.flow_key?.startsWith('flow_key_1')
    );
    const edge2 = elements.find(
      (e) => 'flow_key' in e.data && e.data.flow_key?.startsWith('flow_key_2')
    );

    expect(edge1).toBeDefined();
    expect(edge2).toBeDefined();
    expect(edge1?.data.id).not.toBe(edge2?.data.id);

    if (edge1 && 'dst_port' in edge1.data) {
      expect(edge1.data.label).toBe('TCP · :80');
      expect(edge1.data.dst_port).toBe(80);
      expect(edge1.data.observed_bytes).toBe(1024);
    }
    if (edge2 && 'dst_port' in edge2.data) {
      expect(edge2.data.label).toBe('TCP · :443');
      expect(edge2.data.dst_port).toBe(443);
      expect(edge2.data.observed_bytes).toBe(4096);
    }
  });

  it('deduplicates identical edge definitions', () => {
    const mockData: GraphNeighborhoodResponse = {
      center: '10.0.0.1',
      depth: 1,
      nodes: [
        { id: 'ip:10.0.0.1', type: 'IPAddress', value: '10.0.0.1' },
        { id: 'ip:10.0.0.2', type: 'IPAddress', value: '10.0.0.2' },
      ],
      edges: [
        {
          source: 'ip:10.0.0.1',
          target: 'ip:10.0.0.2',
          type: 'COMMUNICATED_TO',
          protocol: 'TCP',
          flow_key: null,
          src_port: null,
          dst_port: null,
          observed_packet_count: null,
          observed_bytes: null,
          first_seen: null,
          last_seen: null,
          observed_window_seconds: null,
        },
        {
          source: 'ip:10.0.0.1',
          target: 'ip:10.0.0.2',
          type: 'COMMUNICATED_TO',
          protocol: 'TCP',
          flow_key: null,
          src_port: null,
          dst_port: null,
          observed_packet_count: null,
          observed_bytes: null,
          first_seen: null,
          last_seen: null,
          observed_window_seconds: null,
        }, // duplicate
      ],
    };

    const elements = transformGraphToElements(mockData);
    // 2 nodes + 1 unique edge = 3 elements
    expect(elements.length).toBe(3);
  });
});
