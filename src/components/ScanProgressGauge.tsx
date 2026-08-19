import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

interface ScanProgressGaugeProps {
  progress: number; // 0 - 100
  processedFiles: number;
  totalFiles: number;
  status: string;
  size?: number;
}

export const ScanProgressGauge: React.FC<ScanProgressGaugeProps> = ({
  progress,
  processedFiles,
  totalFiles,
  status,
  size = 200,
}) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const prevAngleRef = useRef<number>(0);

  // Determine color scheme based on status
  const getColors = () => {
    switch (status) {
      case 'PAUSED':
        return {
          primary: '#f59e0b', // amber-500
          secondary: '#fbbf24', // amber-400
          track: '#1e293b', // slate-800
          glow: 'rgba(245, 158, 11, 0.4)',
          text: '#fcd34d', // amber-300
        };
      case 'FAILED':
        return {
          primary: '#ef4444', // red-500
          secondary: '#f87171', // red-400
          track: '#1e293b',
          glow: 'rgba(239, 68, 68, 0.4)',
          text: '#fca5a5',
        };
      case 'COMPLETED':
        return {
          primary: '#10b981', // emerald-500
          secondary: '#34d399', // emerald-400
          track: '#1e293b',
          glow: 'rgba(16, 185, 129, 0.4)',
          text: '#6ee7b7',
        };
      case 'SCANNING':
      default:
        return {
          primary: '#10b981', // emerald-500
          secondary: '#06b6d4', // cyan-500
          track: '#1e293b',
          glow: 'rgba(16, 185, 129, 0.5)',
          text: '#34d399',
        };
    }
  };

  useEffect(() => {
    if (!svgRef.current) return;

    const colors = getColors();
    const width = size;
    const height = size;
    const margin = 14;
    const radius = Math.min(width, height) / 2 - margin;
    const innerRadius = radius - 14;
    const outerRadius = radius;

    // Angle mapping: 0 to 2*PI
    const clampedProgress = Math.max(0, Math.min(100, progress));
    const targetAngle = (clampedProgress / 100) * 2 * Math.PI;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const defs = svg.append('defs');

    // Create linear gradient for progress arc
    const gradientId = `gauge-gradient-${status}`;
    const gradient = defs
      .append('linearGradient')
      .attr('id', gradientId)
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '100%')
      .attr('y2', '100%');

    gradient
      .append('stop')
      .attr('offset', '0%')
      .attr('stop-color', colors.primary);

    gradient
      .append('stop')
      .attr('offset', '100%')
      .attr('stop-color', colors.secondary);

    // Glow filter
    const filter = defs.append('filter')
      .attr('id', 'gauge-glow')
      .attr('x', '-30%')
      .attr('y', '-30%')
      .attr('width', '160%')
      .attr('height', '160%');

    filter.append('feGaussianBlur')
      .attr('stdDeviation', '4')
      .attr('result', 'blur');

    filter.append('feComposite')
      .attr('in', 'SourceGraphic')
      .attr('in2', 'blur')
      .attr('operator', 'over');

    const g = svg
      .append('g')
      .attr('transform', `translate(${width / 2}, ${height / 2})`);

    // Tick marks around gauge perimeter
    const tickCount = 40;
    const tickRadiusOuter = radius + 6;
    const tickRadiusInner = radius + 2;

    for (let i = 0; i < tickCount; i++) {
      const angle = (i / tickCount) * 2 * Math.PI - Math.PI / 2;
      const isMajor = i % 10 === 0;
      const rInner = isMajor ? tickRadiusInner - 3 : tickRadiusInner;
      const x1 = Math.cos(angle) * rInner;
      const y1 = Math.sin(angle) * rInner;
      const x2 = Math.cos(angle) * tickRadiusOuter;
      const y2 = Math.sin(angle) * tickRadiusOuter;

      const isPassed = (i / tickCount) <= (clampedProgress / 100);

      g.append('line')
        .attr('x1', x1)
        .attr('y1', y1)
        .attr('x2', x2)
        .attr('y2', y2)
        .attr('stroke', isPassed ? colors.primary : '#334155')
        .attr('stroke-width', isMajor ? 1.5 : 1)
        .attr('stroke-opacity', isPassed ? (isMajor ? 0.9 : 0.6) : 0.3);
    }

    // Background track arc
    const trackArc = d3.arc<any>()
      .innerRadius(innerRadius)
      .outerRadius(outerRadius)
      .startAngle(0)
      .endAngle(2 * Math.PI)
      .cornerRadius(7);

    g.append('path')
      .attr('d', trackArc as any)
      .attr('fill', colors.track)
      .attr('opacity', 0.85);

    // Subtle inner border ring
    g.append('circle')
      .attr('r', innerRadius - 4)
      .attr('fill', 'none')
      .attr('stroke', '#1e293b')
      .attr('stroke-width', 1)
      .attr('stroke-dasharray', '3,3')
      .attr('opacity', 0.5);

    // Arc generator for progress
    const arcGenerator = d3.arc<any>()
      .innerRadius(innerRadius)
      .outerRadius(outerRadius)
      .startAngle(0)
      .cornerRadius(7);

    if (clampedProgress > 0) {
      // Glow underlay for active progress
      const glowPath = g.append('path')
        .datum({ endAngle: targetAngle })
        .attr('d', arcGenerator as any)
        .attr('fill', `url(#${gradientId})`)
        .attr('filter', 'url(#gauge-glow)')
        .attr('opacity', status === 'SCANNING' ? 0.6 : 0.3);

      // Foreground Progress Arc with transition
      const progressPath = g.append('path')
        .datum({ endAngle: prevAngleRef.current })
        .attr('d', arcGenerator as any)
        .attr('fill', `url(#${gradientId})`);

      progressPath.transition()
        .duration(450)
        .ease(d3.easeCubicOut)
        .attrTween('d', (d: any) => {
          const interpolate = d3.interpolate(d.endAngle, targetAngle);
          return (t: number) => {
            d.endAngle = interpolate(t);
            glowPath.datum(d).attr('d', arcGenerator as any);
            return arcGenerator(d) || '';
          };
        });
    }

    prevAngleRef.current = targetAngle;
  }, [progress, status, size]);

  return (
    <div className="relative flex flex-col items-center justify-center p-2">
      {/* SVG Canvas for D3 Progress Ring */}
      <svg
        ref={svgRef}
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="overflow-visible"
        aria-label={`Real-time scanning progress: ${progress}%`}
      />

      {/* Centered Overlay Metrics */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center select-none">
        <span className="text-[10px] uppercase font-mono font-bold tracking-wider text-slate-400">
          Progress
        </span>
        <div className="flex items-baseline justify-center gap-0.5 my-0.5">
          <span className="text-3xl font-extrabold font-mono tracking-tight text-slate-100">
            {progress}
          </span>
          <span className="text-sm font-bold font-mono text-emerald-400">
            %
          </span>
        </div>
        <div className="text-[10px] font-mono text-slate-400 bg-slate-950/80 border border-slate-800 px-2 py-0.5 rounded-full mt-0.5">
          {processedFiles} / {totalFiles} files
        </div>
      </div>
    </div>
  );
};
