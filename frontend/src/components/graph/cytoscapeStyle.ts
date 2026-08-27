import type { StylesheetStyle } from 'cytoscape';

export const cytoscapeStylesheet: StylesheetStyle[] = [
  // Base node style
  {
    selector: 'node',
    style: {
      'font-family': 'ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Monaco, Consolas, monospace',
      'font-size': '10px',
      'text-valign': 'center',
      'text-halign': 'center',
      'color': '#1f2937',
      'text-outline-width': 0,
      'transition-property': 'background-color, border-color, border-width, opacity',
      'transition-duration': 150,
    },
  },

  // IPAddress node
  {
    selector: 'node[type = "IPAddress"]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#ffffff',
      'border-color': '#94a3b8',
      'border-width': 1.5,
      'width': 'label',
      'height': 28,
      'padding': '6px',
      'content': 'data(label)',
      'color': '#1f2937',
    },
  },

  // Center IPAddress node
  {
    selector: 'node[?isCenter]',
    style: {
      'background-color': '#eff6ff',
      'border-color': '#2563eb',
      'border-width': 2,
      'font-weight': 'bold',
      'color': '#1e40af',
    },
  },

  // Layer2Identifier node
  {
    selector: 'node[type = "Layer2Identifier"]',
    style: {
      'shape': 'ellipse',
      'background-color': '#f3f4f6',
      'border-color': '#94a3b8',
      'border-width': 1.5,
      'width': 'label',
      'height': 24,
      'padding': '5px',
      'content': 'data(label)',
      'color': '#4b5563',
    },
  },

  // Base edge style
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'curve-style': 'bezier',
      'font-family': 'ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Monaco, Consolas, monospace',
      'font-size': '8.5px',
      'color': '#4b5563',
      'text-background-color': '#ffffff',
      'text-background-opacity': 0.95,
      'text-background-padding': '2px',
      'text-background-shape': 'roundrectangle',
      'text-border-color': '#e5e7eb',
      'text-border-width': 1,
      'text-border-opacity': 0.9,
      'text-rotation': 'autorotate',
      'transition-property': 'line-color, target-arrow-color, opacity, width',
      'transition-duration': 150,
    },
  },

  // COMMUNICATED_TO edge
  {
    selector: 'edge[type = "COMMUNICATED_TO"]',
    style: {
      'line-color': '#64748b',
      'target-arrow-color': '#64748b',
      'target-arrow-shape': 'triangle',
      'line-style': 'solid',
      'content': 'data(label)',
    },
  },

  // OBSERVED_WITH edge
  {
    selector: 'edge[type = "OBSERVED_WITH"]',
    style: {
      'line-color': '#cbd5e1',
      'line-style': 'dashed',
      'line-dash-pattern': [4, 3],
      'target-arrow-shape': 'none',
      'content': '', // keep association edges uncluttered
    },
  },

  // Highlight / Selected states
  {
    selector: 'node:selected',
    style: {
      'border-color': '#2563eb',
      'border-width': 2.5,
      'underlay-color': '#2563eb',
      'underlay-padding': '3px',
      'underlay-opacity': 0.12,
    },
  },
  {
    selector: 'edge:selected',
    style: {
      'line-color': '#2563eb',
      'target-arrow-color': '#2563eb',
      'width': 2,
    },
  },

  // Dimming rule for neighbor isolation
  {
    selector: '.dimmed',
    style: {
      'opacity': 0.2,
    },
  },
  {
    selector: '.highlighted',
    style: {
      'opacity': 1.0,
    },
  },
];
