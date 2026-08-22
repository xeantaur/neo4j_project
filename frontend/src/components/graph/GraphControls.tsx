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
        gap: '0.5rem',
        backgroundColor: 'var(--bg-card)',
        padding: '0.4rem 0.6rem',
        borderRadius: 'var(--radius-sm)',
        border: '1px solid var(--border-subtle)',
        boxShadow: 'var(--shadow-sm)',
      }}
    >
      <select
        value={layoutName}
        onChange={(e) => onLayoutChange(e.target.value as LayoutName)}
        style={{ fontSize: '0.8rem', padding: '0.25rem 0.5rem' }}
        title="Select graph layout"
      >
        <option value="breadthfirst">Breadthfirst (Hierarchical)</option>
        <option value="cose">CoSE (Clustered)</option>
        <option value="concentric">Concentric (Type Rings)</option>
      </select>

      <div style={{ width: '1px', height: '16px', backgroundColor: 'var(--border-subtle)' }} />

      <button
        onClick={onZoomIn}
        aria-label="Zoom in"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)' }}
        title="Zoom In"
      >
        <ZoomIn size={15} />
      </button>

      <button
        onClick={onZoomOut}
        aria-label="Zoom out"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)' }}
        title="Zoom Out"
      >
        <ZoomOut size={15} />
      </button>

      <button
        onClick={onFit}
        aria-label="Fit to screen"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)' }}
        title="Fit to Screen"
      >
        <Maximize2 size={15} />
      </button>

      <button
        onClick={onReset}
        aria-label="Reset view"
        style={{ padding: '0.3rem', color: 'var(--text-secondary)' }}
        title="Reset View"
      >
        <RotateCcw size={15} />
      </button>
    </div>
  );
};
