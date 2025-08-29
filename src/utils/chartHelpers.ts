/**
 * Chart Utilities and Helpers
 * Reusable chart configurations with accessibility features
 */

import { BusinessRecord } from '@/types/business'
import { LeadScore } from '@/lib/aiLeadScoring'

export interface ChartData {
  name: string
  value: number
  color?: string
  label?: string
}

export interface ChartConfig {
  colors: string[]
  accessibility: {
    ariaLabel: string
    description: string
    textAlternative: string
  }
  responsive: boolean
  animation: boolean
}

export interface GeographicData {
  state: string
  count: number
  averageScore: number
  coordinates: { lat: number; lng: number }
}

export interface TrendData {
  date: string
  value: number
  category?: string
}

/**
 * Default color palettes for charts
 */
export const COLOR_PALETTES = {
  primary: [
    '#3B82F6', // Blue
    '#10B981', // Green
    '#F59E0B', // Yellow
    '#EF4444', // Red
    '#8B5CF6', // Purple
    '#06B6D4', // Cyan
    '#84CC16', // Lime
    '#F97316', // Orange
  ],
  accessibility: [
    '#1f77b4', // Blue
    '#ff7f0e', // Orange
    '#2ca02c', // Green
    '#d62728', // Red
    '#9467bd', // Purple
    '#8c564b', // Brown
    '#e377c2', // Pink
    '#7f7f7f', // Gray
  ],
  heatmap: ['#fee5d9', '#fcbba1', '#fc9272', '#fb6a4a', '#ef3b2c', '#cb181d', '#99000d'],
}

/**
 * Generate industry distribution data for pie charts
 */
export function generateIndustryDistribution(
  businesses: BusinessRecord[],
  scores?: Map<string, LeadScore>
): ChartData[] {
  const industryMap = new Map<string, { count: number; totalScore: number }>()

  businesses.forEach(business => {
    const industry = business.industry || 'Unknown'
    const current = industryMap.get(industry) || { count: 0, totalScore: 0 }
    const score = scores?.get(business.id)?.score || 0

    industryMap.set(industry, {
      count: current.count + 1,
      totalScore: current.totalScore + score,
    })
  })

  return Array.from(industryMap.entries())
    .map(([industry, data], index) => ({
      name: industry,
      value: data.count,
      color: COLOR_PALETTES.primary[index % COLOR_PALETTES.primary.length],
      label: `${industry}: ${data.count} businesses (Avg Score: ${Math.round(data.totalScore / data.count)})`,
    }))
    .sort((a, b) => b.value - a.value)
}

/**
 * Generate lead score distribution data for histograms
 */
export function generateScoreDistribution(scores: Map<string, LeadScore>): ChartData[] {
  const buckets = [
    { range: '0-20', min: 0, max: 20, count: 0 },
    { range: '21-40', min: 21, max: 40, count: 0 },
    { range: '41-60', min: 41, max: 60, count: 0 },
    { range: '61-80', min: 61, max: 80, count: 0 },
    { range: '81-100', min: 81, max: 100, count: 0 },
  ]

  scores.forEach(score => {
    const bucket = buckets.find(b => score.score >= b.min && score.score <= b.max)
    if (bucket) bucket.count++
  })

  return buckets.map((bucket, index) => ({
    name: bucket.range,
    value: bucket.count,
    color: COLOR_PALETTES.accessibility[index],
    label: `Score ${bucket.range}: ${bucket.count} leads`,
  }))
}

/**
 * Generate geographic distribution data
 */
export function generateGeographicDistribution(
  businesses: BusinessRecord[],
  scores?: Map<string, LeadScore>
): GeographicData[] {
  const stateMap = new Map<
    string,
    { count: number; totalScore: number; coords: { lat: number; lng: number } }
  >()

  // State coordinates for mapping (simplified)
  const stateCoordinates: Record<string, { lat: number; lng: number }> = {
    CA: { lat: 36.7783, lng: -119.4179 },
    NY: { lat: 43.2994, lng: -74.2179 },
    TX: { lat: 31.9686, lng: -99.9018 },
    FL: { lat: 27.7663, lng: -81.6868 },
    WA: { lat: 47.7511, lng: -120.7401 },
    IL: { lat: 40.6331, lng: -89.3985 },
    PA: { lat: 41.2033, lng: -77.1945 },
    OH: { lat: 40.4173, lng: -82.9071 },
  }

  businesses.forEach(business => {
    const state = business.address?.state
    if (!state) return

    const current = stateMap.get(state) || {
      count: 0,
      totalScore: 0,
      coords: stateCoordinates[state] || { lat: 0, lng: 0 },
    }
    const score = scores?.get(business.id)?.score || 0

    stateMap.set(state, {
      count: current.count + 1,
      totalScore: current.totalScore + score,
      coords: current.coords,
    })
  })

  return Array.from(stateMap.entries()).map(([state, data]) => ({
    state,
    count: data.count,
    averageScore: data.count > 0 ? Math.round(data.totalScore / data.count) : 0,
    coordinates: data.coords,
  }))
}

/**
 * Generate trend data for time series charts
 */
export function generateTrendData(
  businesses: BusinessRecord[],
  period: 'daily' | 'weekly' | 'monthly' = 'daily'
): TrendData[] {
  const trendMap = new Map<string, number>()

  businesses.forEach(business => {
    const date = new Date(business.scrapedAt)
    let key: string

    switch (period) {
      case 'daily':
        key = date.toISOString().split('T')[0]
        break
      case 'weekly':
        const weekStart = new Date(date)
        weekStart.setDate(date.getDate() - date.getDay())
        key = weekStart.toISOString().split('T')[0]
        break
      case 'monthly':
        key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`
        break
    }

    trendMap.set(key, (trendMap.get(key) || 0) + 1)
  })

  return Array.from(trendMap.entries())
    .map(([date, value]) => ({ date, value }))
    .sort((a, b) => a.date.localeCompare(b.date))
}

/**
 * Generate conversion prediction data
 */
export function generateConversionPrediction(scores: Map<string, LeadScore>): ChartData[] {
  const scoreRanges = [
    { range: '80-100', multiplier: 0.85, label: 'High Quality' },
    { range: '60-79', multiplier: 0.65, label: 'Good Quality' },
    { range: '40-59', multiplier: 0.45, label: 'Medium Quality' },
    { range: '20-39', multiplier: 0.25, label: 'Low Quality' },
    { range: '0-19', multiplier: 0.1, label: 'Very Low Quality' },
  ]

  const distribution = generateScoreDistribution(scores)

  return scoreRanges.map((range, index) => {
    const bucket = distribution.find(d => d.name.includes(range.range.split('-')[0]))
    const leadCount = bucket?.value || 0
    const predictedConversions = Math.round(leadCount * range.multiplier)

    return {
      name: range.label,
      value: predictedConversions,
      color: COLOR_PALETTES.primary[index],
      label: `${range.label}: ${predictedConversions} predicted conversions from ${leadCount} leads`,
    }
  })
}

/**
 * Create accessible chart configuration
 */
export function createChartConfig(
  title: string,
  description: string,
  type: 'pie' | 'bar' | 'line' | 'area' | 'scatter' = 'bar'
): ChartConfig {
  return {
    colors: COLOR_PALETTES.accessibility,
    accessibility: {
      ariaLabel: `${type} chart showing ${title}`,
      description: description,
      textAlternative: `Chart data: ${description}`,
    },
    responsive: true,
    animation: true,
  }
}

/**
 * Generate text summary for screen readers
 */
export function generateChartSummary(data: ChartData[], title: string): string {
  const total = data.reduce((sum, item) => sum + item.value, 0)
  const topItems = data.slice(0, 3)

  let summary = `${title}: Total of ${total} items. `

  if (topItems.length > 0) {
    summary += 'Top categories: '
    summary += topItems
      .map(item => `${item.name} with ${item.value} (${Math.round((item.value / total) * 100)}%)`)
      .join(', ')
  }

  return summary
}

/**
 * Format numbers for display
 */
export function formatNumber(
  value: number,
  type: 'count' | 'percentage' | 'score' = 'count'
): string {
  switch (type) {
    case 'percentage':
      return `${Math.round(value * 100)}%`
    case 'score':
      return `${Math.round(value)}/100`
    case 'count':
    default:
      return value.toLocaleString()
  }
}

/**
 * Generate color based on score value
 */
export function getScoreColor(score: number): string {
  if (score >= 80) return '#10B981' // Green
  if (score >= 60) return '#F59E0B' // Yellow
  if (score >= 40) return '#F97316' // Orange
  return '#EF4444' // Red
}

/**
 * Calculate ROI predictions based on lead scores
 */
export function calculateROIPredictions(
  scores: Map<string, LeadScore>,
  averageOrderValue: number = 1000,
  conversionRates: Record<string, number> = {
    high: 0.15,
    medium: 0.08,
    low: 0.03,
  }
): { category: string; leads: number; predictedRevenue: number; roi: number }[] {
  const categories = {
    high: { min: 70, max: 100, rate: conversionRates.high },
    medium: { min: 40, max: 69, rate: conversionRates.medium },
    low: { min: 0, max: 39, rate: conversionRates.low },
  }

  return Object.entries(categories).map(([category, config]) => {
    const leads = Array.from(scores.values()).filter(
      score => score.score >= config.min && score.score <= config.max
    ).length

    const predictedConversions = leads * config.rate
    const predictedRevenue = predictedConversions * averageOrderValue
    const roi = predictedRevenue / (leads * 10) // Assuming $10 cost per lead

    return {
      category: category.charAt(0).toUpperCase() + category.slice(1),
      leads,
      predictedRevenue: Math.round(predictedRevenue),
      roi: Math.round(roi * 100) / 100,
    }
  })
}

/**
 * Export chart data to CSV format
 */
export function exportChartDataToCSV(data: ChartData[], filename: string): void {
  const csvContent = [
    ['Category', 'Value', 'Percentage'].join(','),
    ...data.map(item => {
      const total = data.reduce((sum, d) => sum + d.value, 0)
      const percentage = Math.round((item.value / total) * 100)
      return [item.name, item.value, `${percentage}%`].join(',')
    }),
  ].join('\n')

  const blob = new Blob([csvContent], { type: 'text/csv' })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${filename}.csv`
  link.click()
  window.URL.revokeObjectURL(url)
}

/**
 * Responsive chart dimensions
 */
export function getResponsiveChartDimensions(containerWidth: number): {
  width: number
  height: number
} {
  const aspectRatio = 16 / 9
  const maxWidth = Math.min(containerWidth - 40, 800) // 20px padding on each side
  const height = Math.min(maxWidth / aspectRatio, 400)

  return {
    width: maxWidth,
    height: Math.max(height, 200), // Minimum height
  }
}

/**
 * High contrast color palette for accessibility
 */
export const HIGH_CONTRAST_COLORS = [
  '#000000', // Black
  '#FFFFFF', // White
  '#FF0000', // Red
  '#00FF00', // Green
  '#0000FF', // Blue
  '#FFFF00', // Yellow
  '#FF00FF', // Magenta
  '#00FFFF', // Cyan
]

/**
 * Apply high contrast mode to chart data
 */
export function applyHighContrastMode(data: ChartData[]): ChartData[] {
  return data.map((item, index) => ({
    ...item,
    color: HIGH_CONTRAST_COLORS[index % HIGH_CONTRAST_COLORS.length],
  }))
}
