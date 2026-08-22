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
  label: string;
}

export interface CytoscapeElement {
  data: CytoscapeNodeData | CytoscapeEdgeData;
}

/**
 * Generate a deterministic frontend-only Cytoscape edge ID.
 * Backend edges do not carry application IDs; this ensures stable Cytoscape element identity.
 */
export function generateFrontendEdgeId(
  source: string,
  target: string,
  type: string,
  protocol: string | null
): string {
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
    const edgeId = generateFrontendEdgeId(edge.source, edge.target, edge.type, edge.protocol);
    if (!seenEdgeIds.has(edgeId)) {
      seenEdgeIds.add(edgeId);
      elements.push({
        data: {
          id: edgeId,
          source: edge.source,
          target: edge.target,
          type: edge.type,
          protocol: edge.protocol,
          label: edge.protocol || '',
        },
      });
    }
  }

  return elements;
}
