import React from 'react'
import { clsx } from 'clsx'

/**
 * Chart data point interface
 */
export interface ChartDataPoint {
  name: string
  value: number
  color?: string
}

/**
 * Base chart props
 */
export interface BaseChartProps {
  data: ChartDataPoint[]
  width?: number
  height?: number
  className?: string
}

/**
 * Line chart props
 */
export interface LineChartProps extends BaseChartProps {
  strokeColor?: string
  strokeWidth?: number
  showDots?: boolean
}

/**
 * Bar chart props
 */
export interface BarChartProps extends BaseChartProps {
  barColor?: string
  showValues?: boolean
}

/**
 * Pie chart props
 */
export interface PieChartProps extends BaseChartProps {
  showLabels?: boolean
  showPercentages?: boolean
}

/**
 * Simple Line Chart component using SVG
 */
export const LineChart: React.FC<LineChartProps> = ({
  data,
  width = 400,
  height = 200,
  strokeColor = '#3b82f6',
  strokeWidth = 2,
  showDots = true,
  className,
}) => {
  if (!data || data.length === 0) {
    return (
      <div
        className={clsx('flex items-center justify-center', className)}
        style={{ width, height }}
      >
        <p className="text-muted-foreground">No data available</p>
      </div>
    )
  }

  const maxValue = Math.max(...data.map(d => d.value))
  const minValue = Math.min(...data.map(d => d.value))
  const valueRange = maxValue - minValue || 1

  const padding = 20
  const chartWidth = width - 2 * padding
  const chartHeight = height - 2 * padding

  // Generate path for line
  const pathData = data
    .map((point, index) => {
      const x = padding + (index / (data.length - 1)) * chartWidth
      const y = padding + ((maxValue - point.value) / valueRange) * chartHeight
      return `${index === 0 ? 'M' : 'L'} ${x} ${y}`
    })
    .join(' ')

  return (
    <div className={clsx('relative', className)}>
      <svg width={width} height={height} className="overflow-visible">
        {/* Grid lines */}
        <defs>
          <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path
              d="M 40 0 L 0 0 0 40"
              fill="none"
              stroke="#e5e7eb"
              strokeWidth="1"
              opacity="0.3"
            />
          </pattern>
        </defs>
        <rect width={width} height={height} fill="url(#grid)" />

        {/* Line path */}
        <path
          d={pathData}
          fill="none"
          stroke={strokeColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeLinejoin="round"
        />

        {/* Data points */}
        {showDots &&
          data.map((point, index) => {
            const x = padding + (index / (data.length - 1)) * chartWidth
            const y = padding + ((maxValue - point.value) / valueRange) * chartHeight
            return (
              <circle
                key={index}
                cx={x}
                cy={y}
                r="4"
                fill={strokeColor}
                className="hover:r-6 transition-all"
              >
                <title>{`${point.name}: ${point.value}`}</title>
              </circle>
            )
          })}
      </svg>
    </div>
  )
}

/**
 * Simple Bar Chart component using SVG
 */
export const BarChart: React.FC<BarChartProps> = ({
  data,
  width = 400,
  height = 200,
  barColor = '#3b82f6',
  showValues = true,
  className,
}) => {
  if (!data || data.length === 0) {
    return (
      <div
        className={clsx('flex items-center justify-center', className)}
        style={{ width, height }}
      >
        <p className="text-muted-foreground">No data available</p>
      </div>
    )
  }

  const maxValue = Math.max(...data.map(d => d.value))
  const padding = 20
  const chartWidth = width - 2 * padding
  const chartHeight = height - 2 * padding
  const barWidth = (chartWidth / data.length) * 0.8
  const barSpacing = (chartWidth / data.length) * 0.2

  return (
    <div className={clsx('relative', className)}>
      <svg width={width} height={height}>
        {data.map((point, index) => {
          const barHeight = (point.value / maxValue) * chartHeight
          const x = padding + index * (barWidth + barSpacing) + barSpacing / 2
          const y = height - padding - barHeight

          return (
            <g key={index}>
              {/* Bar */}
              <rect
                x={x}
                y={y}
                width={barWidth}
                height={barHeight}
                fill={point.color || barColor}
                className="hover:opacity-80 transition-opacity"
              >
                <title>{`${point.name}: ${point.value}`}</title>
              </rect>

              {/* Value label */}
              {showValues && (
                <text
                  x={x + barWidth / 2}
                  y={y - 5}
                  textAnchor="middle"
                  className="text-xs fill-current text-foreground"
                >
                  {point.value}
                </text>
              )}

              {/* Name label */}
              <text
                x={x + barWidth / 2}
                y={height - 5}
                textAnchor="middle"
                className="text-xs fill-current text-muted-foreground"
              >
                {point.name.length > 8 ? `${point.name.slice(0, 8)}...` : point.name}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}

/**
 * Simple Pie Chart component using SVG
 */
export const PieChart: React.FC<PieChartProps> = ({
  data,
  width = 200,
  height = 200,
  showLabels = true,
  showPercentages = true,
  className,
}) => {
  if (!data || data.length === 0) {
    return (
      <div
        className={clsx('flex items-center justify-center', className)}
        style={{ width, height }}
      >
        <p className="text-muted-foreground">No data available</p>
      </div>
    )
  }

  const total = data.reduce((sum, point) => sum + point.value, 0)
  const radius = Math.min(width, height) / 2 - 20
  const centerX = width / 2
  const centerY = height / 2

  let currentAngle = 0
  const colors = [
    '#3b82f6',
    '#ef4444',
    '#10b981',
    '#f59e0b',
    '#8b5cf6',
    '#06b6d4',
    '#84cc16',
    '#f97316',
    '#ec4899',
    '#6366f1',
  ]

  const slices = data.map((point, index) => {
    const percentage = (point.value / total) * 100
    const sliceAngle = (point.value / total) * 2 * Math.PI
    const startAngle = currentAngle
    const endAngle = currentAngle + sliceAngle

    const x1 = centerX + radius * Math.cos(startAngle)
    const y1 = centerY + radius * Math.sin(startAngle)
    const x2 = centerX + radius * Math.cos(endAngle)
    const y2 = centerY + radius * Math.sin(endAngle)

    const largeArcFlag = sliceAngle > Math.PI ? 1 : 0

    const pathData = [
      `M ${centerX} ${centerY}`,
      `L ${x1} ${y1}`,
      `A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2}`,
      'Z',
    ].join(' ')

    currentAngle += sliceAngle

    return {
      ...point,
      pathData,
      percentage,
      color: point.color || colors[index % colors.length],
    }
  })

  return (
    <div className={clsx('relative', className)}>
      <svg width={width} height={height}>
        {slices.map((slice, index) => (
          <path
            key={index}
            d={slice.pathData}
            fill={slice.color}
            className="hover:opacity-80 transition-opacity"
          >
            <title>{`${slice.name}: ${slice.value} (${slice.percentage.toFixed(1)}%)`}</title>
          </path>
        ))}
      </svg>

      {/* Legend */}
      {showLabels && (
        <div className="mt-4 flex flex-wrap gap-2">
          {slices.map((slice, index) => (
            <div key={index} className="flex items-center gap-1 text-xs">
              <div className="w-3 h-3 rounded-sm" style={{ backgroundColor: slice.color }} />
              <span>
                {slice.name}
                {showPercentages && ` (${slice.percentage.toFixed(1)}%)`}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
