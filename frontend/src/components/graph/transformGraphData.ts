import type { GraphNeighborhoodResponse } from '../../api/types';

export interface CytoscapeNodeData {
  id: string;
  label: string;
  type: 'IPAddress' | 'Layer2Identifier';
  value: string;
  isCenter: boolean;
}

export interface CytoscapeEdgeData {
  id: string;
  source: string;
  target: string;
  type: 'COMMUNICATED_TO' | 'OBSERVED_WITH';
  protocol: string | null;
  flow_key: string | null;
  src_port: number | null;
  dst_port: number | null;
  observed_packet_count: number | null;
  observed_bytes: number | null;
  first_seen: number | null;
  last_seen: number | null;
  observed_window_seconds: number | null;
  label: string;
}

export interface CytoscapeElement {
  data: CytoscapeNodeData | CytoscapeEdgeData;
}

/**
 * Generate a deterministic frontend-only Cytoscape edge ID.
 * When flow_key is available (for enriched COMMUNICATED_TO), it is used to guarantee
 * unique edge identities for parallel flows with identical endpoints and protocols.
 */
export function generateFrontendEdgeId(
  source: string,
  target: string,
  type: string,
  protocol: string | null,
  flowKey?: string | null
): string {
  if (flowKey) {
    return `edge:${encodeURIComponent(source)}|${encodeURIComponent(target)}|${encodeURIComponent(type)}|${encodeURIComponent(flowKey)}`;
  }
  const safeProto = protocol ? encodeURIComponent(protocol) : 'none';
  return `edge:${encodeURIComponent(source)}|${encodeURIComponent(target)}|${encodeURIComponent(type)}|${safeProto}`;
}

/**
 * Transform GraphNeighborhoodResponse into Cytoscape element definitions.
 */
export function transformGraphToElements(
  data: GraphNeighborhoodResponse
): CytoscapeElement[] {
  const centerId = `ip:${data.center}`;
  const elements: CytoscapeElement[] = [];

  // Add nodes
  for (const node of data.nodes) {
    elements.push({
      data: {
        id: node.id,
        label: node.value,
        type: node.type,
        value: node.value,
        isCenter: node.id === centerId,
      },
    });
  }

  // Add edges
  const seenEdgeIds = new Set<string>();
  for (const edge of data.edges) {
    const edgeId = generateFrontendEdgeId(
      edge.source,
      edge.target,
      edge.type,
      edge.protocol,
      edge.flow_key
    );

    if (!seenEdgeIds.has(edgeId)) {
      seenEdgeIds.add(edgeId);

      let label = '';
      if (edge.type === 'COMMUNICATED_TO') {
        if (edge.dst_port != null && edge.protocol) {
          label = `${edge.protocol} · :${edge.dst_port}`;
        } else if (edge.dst_port != null) {
          label = `:${edge.dst_port}`;
        } else {
          label = edge.protocol || '';
        }
      }

      elements.push({
        data: {
          id: edgeId,
          source: edge.source,
          target: edge.target,
          type: edge.type,
          protocol: edge.protocol,
          flow_key: edge.flow_key ?? null,
          src_port: edge.src_port ?? null,
          dst_port: edge.dst_port ?? null,
          observed_packet_count: edge.observed_packet_count ?? null,
          observed_bytes: edge.observed_bytes ?? null,
          first_seen: edge.first_seen ?? null,
          last_seen: edge.last_seen ?? null,
          observed_window_seconds: edge.observed_window_seconds ?? null,
          label,
        },
      });
    }
  }

  return elements;
}

/**
 * Format a Cytoscape root selector for breadthfirst layout.
 * Uses exact attribute matching ([id = "..."]) to avoid CSS selector
 * parsing issues with dots (.) and colons (:) in IPv4/IPv6 addresses.
 */
export function formatBreadthfirstRootSelector(centerId: string): string {
  return `[id = "${centerId}"]`;
}
