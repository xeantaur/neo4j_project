import { useEffect, useRef, useImperativeHandle, forwardRef } from 'react';
import cytoscape from 'cytoscape';
import type { Core, EventObject } from 'cytoscape';
import type { GraphNeighborhoodResponse } from '../../api/types';
import {
  transformGraphToElements,
  formatBreadthfirstRootSelector,
} from './transformGraphData';
import type { CytoscapeEdgeData } from './transformGraphData';
import { cytoscapeStylesheet } from './cytoscapeStyle';

export type LayoutName = 'breadthfirst' | 'cose' | 'concentric';

export interface CytoscapeCanvasHandle {
  zoomIn: () => void;
  zoomOut: () => void;
  fit: () => void;
  reset: () => void;
}

interface CytoscapeCanvasProps {
  data: GraphNeighborhoodResponse;
  layoutName: LayoutName;
  onNodeSelect: (nodeData: { id: string; type: 'IPAddress' | 'Layer2Identifier'; value: string } | null) => void;
  onEdgeSelect?: (edgeData: CytoscapeEdgeData | null) => void;
  selectedNodeId?: string | null;
  selectedEdgeId?: string | null;
}

export const CytoscapeCanvas = forwardRef<CytoscapeCanvasHandle, CytoscapeCanvasProps>(
  ({ data, layoutName, onNodeSelect, onEdgeSelect, selectedNodeId, selectedEdgeId }, ref) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const cyRef = useRef<Core | null>(null);

    // Expose toolbar control methods to parent
    useImperativeHandle(ref, () => ({
      zoomIn: () => {
        const cy = cyRef.current;
        if (cy) {
          cy.zoom(cy.zoom() * 1.25);
        }
      },
      zoomOut: () => {
        const cy = cyRef.current;
        if (cy) {
          cy.zoom(cy.zoom() * 0.8);
        }
      },
      fit: () => {
        const cy = cyRef.current;
        if (cy) {
          cy.fit(undefined, 30);
        }
      },
      reset: () => {
        const cy = cyRef.current;
        if (cy) {
          cy.elements().removeClass('dimmed highlighted');
          cy.fit(undefined, 30);
        }
      },
    }));

    // Initialize and update Cytoscape instance
    useEffect(() => {
      if (!containerRef.current) return;

      const elements = transformGraphToElements(data);
      const centerId = `ip:${data.center}`;

      // Layout configuration
      let layoutOptions: cytoscape.LayoutOptions;
      if (layoutName === 'cose') {
        layoutOptions = {
          name: 'cose',
          animate: false,
          nodeRepulsion: () => 9000,
          idealEdgeLength: () => 90,
          gravity: 0.25,
        };
      } else if (layoutName === 'concentric') {
        layoutOptions = {
          name: 'concentric',
          concentric: (node: cytoscape.NodeSingular) =>
            node.id() === centerId ? 3 : node.data('type') === 'IPAddress' ? 2 : 1,
          levelWidth: () => 1,
          minNodeSpacing: 40,
          animate: false,
        };
      } else {
        // Default: breadthfirst (center-rooted)
        layoutOptions = {
          name: 'breadthfirst',
          directed: true,
          roots: [formatBreadthfirstRootSelector(centerId)],
          spacingFactor: 1.2,
          animate: false,
        };
      }

      const cy = cytoscape({
        container: containerRef.current,
        elements,
        style: cytoscapeStylesheet,
        layout: layoutOptions,
        minZoom: 0.2,
        maxZoom: 3.0,
        wheelSensitivity: 0.2,
      });

      cyRef.current = cy;

      // Node selection handler
      cy.on('tap', 'node', (evt: EventObject) => {
        const node = evt.target;
        const nodeData = {
          id: node.data('id'),
          type: node.data('type'),
          value: node.data('value'),
        };
        onNodeSelect(nodeData);
        if (onEdgeSelect) {
          onEdgeSelect(null);
        }

        // Neighborhood focus highlighting
        cy.elements().removeClass('dimmed highlighted');
        const neighborhood = node.neighborhood().add(node);
        cy.elements().difference(neighborhood).addClass('dimmed');
        neighborhood.addClass('highlighted');
      });

      // Edge selection handler (COMMUNICATED_TO only)
      cy.on('tap', 'edge', (evt: EventObject) => {
        const edge = evt.target;
        const edgeData = edge.data() as CytoscapeEdgeData;

        if (edgeData.type === 'COMMUNICATED_TO' && onEdgeSelect) {
          onEdgeSelect(edgeData);
          onNodeSelect(null);

          // Focus edge highlighting
          cy.elements().removeClass('dimmed highlighted');
          const connected = edge.connectedNodes().add(edge);
          cy.elements().difference(connected).addClass('dimmed');
          edge.addClass('highlighted');
        }
      });

      // Background tap resets selection
      cy.on('tap', (evt: EventObject) => {
        if (evt.target === cy) {
          onNodeSelect(null);
          if (onEdgeSelect) {
            onEdgeSelect(null);
          }
          cy.elements().removeClass('dimmed highlighted');
        }
      });

      return () => {
        cy.destroy();
        cyRef.current = null;
      };
    }, [data, layoutName, onNodeSelect, onEdgeSelect]);

    // Sync external selectedNodeId / selectedEdgeId if updated
    useEffect(() => {
      const cy = cyRef.current;
      if (!cy) return;

      if (selectedNodeId) {
        const selected = cy.getElementById(selectedNodeId);
        if (selected.length > 0) {
          cy.elements().removeClass('dimmed highlighted');
          const neighborhood = selected.neighborhood().add(selected);
          cy.elements().difference(neighborhood).addClass('dimmed');
          neighborhood.addClass('highlighted');
        }
      } else if (selectedEdgeId) {
        const selected = cy.getElementById(selectedEdgeId);
        if (selected.length > 0) {
          cy.elements().removeClass('dimmed highlighted');
          const connected = selected.connectedNodes().add(selected);
          cy.elements().difference(connected).addClass('dimmed');
          selected.addClass('highlighted');
        }
      } else {
        cy.elements().removeClass('dimmed highlighted');
      }
    }, [selectedNodeId, selectedEdgeId]);

    return (
      <div
        ref={containerRef}
        style={{
          position: 'absolute',
          inset: 0,
          backgroundColor: 'var(--bg-canvas)',
          borderRadius: 'var(--radius-md)',
          overflow: 'hidden',
        }}
      />
    );
  }
);

CytoscapeCanvas.displayName = 'CytoscapeCanvas';
