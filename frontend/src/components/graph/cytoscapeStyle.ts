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
      'color': '#0f172a',
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
      'border-color': '#0284c7',
      'border-width': 1.5,
      'width': 'label',
      'height': 30,
      'padding': '6px',
      'content': 'data(label)',
      'color': '#0f172a',
    },
  },

  // Center IPAddress node
  {
    selector: 'node[?isCenter]',
    style: {
      'background-color': '#ffffff',
      'border-color': '#d97706',
      'border-width': 2.5,
      'underlay-color': '#d97706',
      'underlay-padding': '4px',
      'underlay-opacity': 0.16,
      'font-weight': 'bold',
      'color': '#0f172a',
    },
  },

  // Layer2Identifier node
  {
    selector: 'node[type = "Layer2Identifier"]',
    style: {
      'shape': 'ellipse',
      'background-color': '#f1f5f9',
      'border-color': '#64748b',
      'border-width': 1.5,
      'width': 'label',
      'height': 26,
      'padding': '5px',
      'content': 'data(label)',
      'color': '#334155',
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
      'color': '#334155',
      'text-background-color': '#ffffff',
      'text-background-opacity': 0.95,
      'text-background-padding': '2px',
      'text-background-shape': 'roundrectangle',
      'text-border-color': '#cbd5e1',
      'text-border-width': 1,
      'text-border-opacity': 0.85,
      'text-rotation': 'autorotate',
      'transition-property': 'line-color, target-arrow-color, opacity, width',
      'transition-duration': 150,
    },
  },

  // COMMUNICATED_TO edge
  {
    selector: 'edge[type = "COMMUNICATED_TO"]',
    style: {
      'line-color': '#2563eb',
      'target-arrow-color': '#2563eb',
      'target-arrow-shape': 'triangle',
      'line-style': 'solid',
      'content': 'data(label)',
    },
  },

  // OBSERVED_WITH edge
  {
    selector: 'edge[type = "OBSERVED_WITH"]',
    style: {
      'line-color': '#94a3b8',
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
      'underlay-padding': '4px',
      'underlay-opacity': 0.16,
    },
  },
  {
    selector: 'edge:selected',
    style: {
      'line-color': '#2563eb',
      'target-arrow-color': '#2563eb',
      'width': 2.5,
    },
  },

  // Dimming rule for neighbor isolation
  {
    selector: '.dimmed',
    style: {
      'opacity': 0.18,
    },
  },
  {
    selector: '.highlighted',
    style: {
      'opacity': 1.0,
    },
  },
];
