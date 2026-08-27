import React from 'react';

interface SkeletonProps {
  height?: string | number;
  width?: string | number;
  borderRadius?: string;
  style?: React.CSSProperties;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  height = '1rem',
  width = '100%',
  borderRadius = 'var(--radius-sm)',
  style,
}) => {
  return (
    <div
      style={{
        height,
        width,
        borderRadius,
        backgroundColor: '#e2e8f0',
        animation: 'pulse 1.5s ease-in-out infinite',
        ...style,
      }}
    />
  );
};
