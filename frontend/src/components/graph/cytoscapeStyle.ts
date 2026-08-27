import type { StylesheetStyle } from 'cytoscape';

export const cytoscapeStylesheet: StylesheetStyle[] = [
  // Base node style
  {
    selector: 'node',
    style: {
      'font-family': 'ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Monaco, Consolas, monospace',
      'font-size': '10.5px',
      'text-valign': 'center',
      'text-halign': 'center',
      'color': '#f4f7fb',
      'text-outline-width': 2,
      'text-outline-color': '#080b12',
      'transition-property': 'background-color, border-color, border-width, opacity',
      'transition-duration': 150,
    },
  },

  // IPAddress node
  {
    selector: 'node[type = "IPAddress"]',
    style: {
      'shape': 'round-rectangle',
      'background-color': '#111722',
      'border-color': '#38bdf8',
      'border-width': 1.5,
      'width': 'label',
      'height': 32,
      'padding': '7px',
      'content': 'data(label)',
    },
  },

  // Center IPAddress node
  {
    selector: 'node[?isCenter]',
    style: {
      'background-color': '#151c28',
      'border-color': '#f59e0b',
      'border-width': 2.5,
      'underlay-color': '#f59e0b',
      'underlay-padding': '4px',
      'underlay-opacity': 0.18,
      'font-weight': 'bold',
    },
  },

  // Layer2Identifier node
  {
    selector: 'node[type = "Layer2Identifier"]',
    style: {
      'shape': 'ellipse',
      'background-color': '#151c28',
      'border-color': '#64748b',
      'border-width': 1.5,
      'width': 'label',
      'height': 28,
      'padding': '6px',
      'content': 'data(label)',
      'color': '#cbd5e1',
    },
  },

  // Base edge style
  {
    selector: 'edge',
    style: {
      'width': 1.75,
      'curve-style': 'bezier',
      'font-family': 'ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Monaco, Consolas, monospace',
      'font-size': '8.5px',
      'color': '#94a3b8',
      'text-background-color': '#080b12',
      'text-background-opacity': 0.95,
      'text-background-padding': '2.5px',
      'text-background-shape': 'roundrectangle',
      'text-border-color': 'rgba(255, 255, 255, 0.12)',
      'text-border-width': 1,
      'text-border-opacity': 0.7,
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
      'border-color': '#6366f1',
      'border-width': 2.5,
      'underlay-color': '#6366f1',
      'underlay-padding': '4px',
      'underlay-opacity': 0.22,
    },
  },
  {
    selector: 'edge:selected',
    style: {
      'line-color': '#6366f1',
      'target-arrow-color': '#6366f1',
      'width': 2.5,
    },
  },

  // Dimming rule for neighbor isolation
  {
    selector: '.dimmed',
    style: {
      'opacity': 0.12,
    },
  },
  {
    selector: '.highlighted',
    style: {
      'opacity': 1.0,
    },
  },
];
