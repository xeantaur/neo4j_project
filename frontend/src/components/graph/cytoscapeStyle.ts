import type { StylesheetStyle } from 'cytoscape';

export const cytoscapeStylesheet: StylesheetStyle[] = [
  // Base node style
  {
    selector: 'node',
    style: {
      'font-family': 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
      'font-size': '11px',
      'text-valign': 'center',
      'text-halign': 'center',
      'color': '#f8fafc',
      'text-outline-width': 2,
      'text-outline-color': '#090d14',
      'transition-property': 'background-color, border-color, border-width, opacity',
      'transition-duration': 150,
    },
  },

  // IPAddress node
  {
    selector: 'node[type = "IPAddress"]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#111827',
      'border-color': '#38bdf8',
      'border-width': 2,
      'width': 'label',
      'height': 34,
      'padding': '8px',
      'content': 'data(label)',
    },
  },

  // Center IPAddress node
  {
    selector: 'node[?isCenter]',
    style: {
      'border-color': '#f59e0b',
      'border-width': 3,
      'underlay-color': '#f59e0b',
      'underlay-padding': '4px',
      'underlay-opacity': 0.2,
      'font-weight': 'bold',
    },
  },

  // Layer2Identifier node
  {
    selector: 'node[type = "Layer2Identifier"]',
    style: {
      'shape': 'ellipse',
      'background-color': '#1e293b',
      'border-color': '#94a3b8',
      'border-width': 1.5,
      'width': 'label',
      'height': 30,
      'padding': '6px',
      'content': 'data(label)',
      'color': '#cbd5e1',
    },
  },

  // Base edge style
  {
    selector: 'edge',
    style: {
      'width': 2,
      'curve-style': 'bezier',
      'font-size': '9px',
      'color': '#94a3b8',
      'text-background-color': '#111827',
      'text-background-opacity': 0.9,
      'text-background-padding': '2px',
      'text-background-shape': 'roundrectangle',
      'text-rotation': 'autorotate',
      'transition-property': 'line-color, target-arrow-color, opacity, width',
      'transition-duration': 150,
    },
  },

  // COMMUNICATED_TO edge
  {
    selector: 'edge[type = "COMMUNICATED_TO"]',
    style: {
      'line-color': '#0284c7',
      'target-arrow-color': '#0284c7',
      'target-arrow-shape': 'triangle',
      'line-style': 'solid',
      'content': 'data(label)',
    },
  },

  // OBSERVED_WITH edge
  {
    selector: 'edge[type = "OBSERVED_WITH"]',
    style: {
      'line-color': '#475569',
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
      'border-color': '#ec4899',
      'border-width': 3,
      'underlay-color': '#ec4899',
      'underlay-padding': '4px',
      'underlay-opacity': 0.25,
    },
  },
  {
    selector: 'edge:selected',
    style: {
      'line-color': '#ec4899',
      'target-arrow-color': '#ec4899',
      'width': 3,
    },
  },

  // Dimming rule for neighbor isolation
  {
    selector: '.dimmed',
    style: {
      'opacity': 0.15,
    },
  },
  {
    selector: '.highlighted',
    style: {
      'opacity': 1.0,
    },
  },
];
