import React from 'react';
import { ZoomIn, ZoomOut, Maximize2, RotateCcw } from 'lucide-react';
import type { LayoutName } from './CytoscapeCanvas';

interface GraphControlsProps {
  layoutName: LayoutName;
  onLayoutChange: (layout: LayoutName) => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFit: () => void;
  onReset: () => void;
}

export const GraphControls: React.FC<GraphControlsProps> = ({
  layoutName,
  onLayoutChange,
  onZoomIn,
  onZoomOut,
  onFit,
  onReset,
}) => {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.4rem',
        backgroundColor: 'var(--bg-card)',
        padding: '0.35rem 0.55rem',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-card)',
        boxShadow: 'var(--shadow-sm)',
      }}
    >
      <select
        value={layoutName}
        onChange={(e) => onLayoutChange(e.target.value as LayoutName)}
        style={{ fontSize: '0.78rem', padding: '0.25rem 0.5rem', fontWeight: 500 }}
        title="Select graph layout"
      >
        <option value="cose">COSE (Force Directed)</option>
        <option value="breadthfirst">Breadthfirst (Hierarchical)</option>
        <option value="concentric">Concentric</option>
      </select>

      <div style={{ width: '1px', height: '16px', backgroundColor: 'var(--border-subtle)', margin: '0 0.2rem' }} />

      <button
        onClick={onZoomIn}
        aria-label="Zoom in"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', borderRadius: 'var(--radius-sm)' }}
        title="Zoom In"
      >
        <ZoomIn size={14} />
      </button>

      <button
        onClick={onZoomOut}
        aria-label="Zoom out"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', borderRadius: 'var(--radius-sm)' }}
        title="Zoom Out"
      >
        <ZoomOut size={14} />
      </button>

      <button
        onClick={onFit}
        aria-label="Fit to screen"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', borderRadius: 'var(--radius-sm)' }}
        title="Fit to Screen"
      >
        <Maximize2 size={14} />
      </button>

      <button
        onClick={onReset}
        aria-label="Reset view"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', borderRadius: 'var(--radius-sm)' }}
        title="Reset View"
      >
        <RotateCcw size={14} />
      </button>
    </div>
  );
};
