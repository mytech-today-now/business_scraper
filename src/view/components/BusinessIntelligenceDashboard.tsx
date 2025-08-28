/**
 * Business Intelligence Dashboard Component
 * Comprehensive dashboard with AI insights, charts, and predictive analytics
 */

'use client'

import React, { useState, useEffect } from 'react'
import { 
  PieChart, 
  Pie, 
  BarChart, 
  Bar, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer,
  Cell
} from 'recharts'
import { 
  TrendingUp, 
  TrendingDown, 
  Target, 
  DollarSign, 
  Users, 
  MapPin,
  Download,
  RefreshCw,
  Eye,
  EyeOff
} from 'lucide-react'
import { BusinessRecord } from '@/types/business'
import { LeadScore } from '@/lib/aiLeadScoring'
import { useBusinessInsights } from '@/hooks/useBusinessInsights'
import { usePredictiveAnalytics } from '@/hooks/usePredictiveAnalytics'
import { 
  createChartConfig, 
  generateChartSummary, 
  getScoreColor, 
  formatNumber,
  applyHighContrastMode
} from '@/utils/chartHelpers'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'

export interface BusinessIntelligenceDashboardProps {
  businesses: BusinessRecord[]
  scores: Map<string, LeadScore>
  className?: string
}

/**
 * Business Intelligence Dashboard Component
 */
export const BusinessIntelligenceDashboard: React.FC<BusinessIntelligenceDashboardProps> = ({
  businesses,
  scores,
  className = ''
}) => {
  const [highContrastMode, setHighContrastMode] = useState(false)
  const [selectedView, setSelectedView] = useState<'overview' | 'trends' | 'predictions'>('overview')

  // Use custom hooks for insights and predictions
  const {
    insights,
    isLoading: insightsLoading,
    error: insightsError,
    refreshInsights,
    exportInsights
  } = useBusinessInsights(businesses, scores, {
    autoRefresh: true,
    includeROI: true
  })

  const {
    trendPredictions,
    roiForecasts,
    marketInsights,
    isLoading: predictionsLoading,
    error: predictionsError,
    runPredictions,
    exportPredictions
  } = usePredictiveAnalytics(businesses, scores, {
    enableTrendAnalysis: true,
    enableROIForecasting: true,
    enableMarketInsights: true
  })

  const isLoading = insightsLoading || predictionsLoading
  const hasError = insightsError || predictionsError

  // Apply high contrast mode to chart data
  const processChartData = (data: any[]) => {
    return highContrastMode ? applyHighContrastMode(data) : data
  }

  // Custom tooltip component for accessibility
  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div 
          className="bg-white p-3 border border-gray-300 rounded shadow-lg"
          role="tooltip"
          aria-label={`Chart data for ${label}`}
        >
          <p className="font-medium">{label}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} style={{ color: entry.color }}>
              {entry.name}: {entry.value}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  if (isLoading) {
    return (
      <div className={`p-6 ${className}`}>
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="w-8 h-8 animate-spin text-blue-600" />
          <span className="ml-2 text-lg">Generating insights...</span>
        </div>
      </div>
    )
  }

  if (hasError || !insights) {
    return (
      <div className={`p-6 ${className}`}>
        <Card className="border-red-200 bg-red-50">
          <CardContent className="p-6">
            <h3 className="text-lg font-semibold text-red-800 mb-2">
              Unable to Generate Insights
            </h3>
            <p className="text-red-600 mb-4">
              {insightsError || predictionsError || 'No data available for analysis'}
            </p>
            <Button 
              onClick={refreshInsights}
              className="bg-red-600 hover:bg-red-700"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className={`p-6 space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">
            Business Intelligence Dashboard
          </h1>
          <p className="text-gray-600 mt-1">
            AI-powered insights and predictive analytics
          </p>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            onClick={() => setHighContrastMode(!highContrastMode)}
            aria-label={`${highContrastMode ? 'Disable' : 'Enable'} high contrast mode`}
          >
            {highContrastMode ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
            {highContrastMode ? 'Normal' : 'High Contrast'}
          </Button>
          
          <Button
            variant="outline"
            onClick={refreshInsights}
            aria-label="Refresh insights"
          >
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          
          <Button
            variant="outline"
            onClick={() => exportInsights('csv')}
            aria-label="Export insights as CSV"
          >
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
        </div>
      </div>

      {/* View Selector */}
      <div className="flex space-x-1 bg-gray-100 p-1 rounded-lg">
        {[
          { key: 'overview', label: 'Overview' },
          { key: 'trends', label: 'Trends' },
          { key: 'predictions', label: 'Predictions' }
        ].map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setSelectedView(key as any)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              selectedView === key
                ? 'bg-white text-blue-600 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
            aria-pressed={selectedView === key}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Total Businesses</p>
                <p className="text-2xl font-bold text-gray-900">
                  {formatNumber(insights.summary.totalBusinesses)}
                </p>
              </div>
              <Users className="w-8 h-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Average Score</p>
                <p className="text-2xl font-bold" style={{ color: getScoreColor(insights.summary.averageScore) }}>
                  {insights.summary.averageScore}/100
                </p>
              </div>
              <Target className="w-8 h-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">High Quality Leads</p>
                <p className="text-2xl font-bold text-green-600">
                  {formatNumber(insights.summary.highQualityLeads)}
                </p>
              </div>
              <TrendingUp className="w-8 h-8 text-green-600" />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">Est. Revenue</p>
                <p className="text-2xl font-bold text-purple-600">
                  ${formatNumber(insights.summary.estimatedRevenue)}
                </p>
              </div>
              <DollarSign className="w-8 h-8 text-purple-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Overview Tab */}
      {selectedView === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Industry Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>Industry Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div 
                role="img" 
                aria-label={generateChartSummary(insights.industryDistribution, 'Industry distribution')}
              >
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={processChartData(insights.industryDistribution)}
                      cx="50%"
                      cy="50%"
                      labelLine={false}
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      outerRadius={80}
                      fill="#8884d8"
                      dataKey="value"
                    >
                      {insights.industryDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-4 text-sm text-gray-600">
                {generateChartSummary(insights.industryDistribution, 'Industry distribution')}
              </div>
            </CardContent>
          </Card>

          {/* Lead Score Distribution */}
          <Card>
            <CardHeader>
              <CardTitle>Lead Score Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div 
                role="img" 
                aria-label={generateChartSummary(insights.scoreDistribution, 'Lead score distribution')}
              >
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={processChartData(insights.scoreDistribution)}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="value" fill="#3B82F6" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-4 text-sm text-gray-600">
                {generateChartSummary(insights.scoreDistribution, 'Lead score distribution')}
              </div>
            </CardContent>
          </Card>

          {/* Geographic Distribution */}
          <Card className="lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center">
                <MapPin className="w-5 h-5 mr-2" />
                Geographic Distribution
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {insights.geographicDistribution.slice(0, 6).map((location) => (
                  <div key={location.state} className="p-4 bg-gray-50 rounded-lg">
                    <div className="flex justify-between items-center">
                      <span className="font-medium">{location.state}</span>
                      <span className="text-sm text-gray-600">{location.count} businesses</span>
                    </div>
                    <div className="mt-2">
                      <span className="text-sm text-gray-600">Avg Score: </span>
                      <span 
                        className="font-medium"
                        style={{ color: getScoreColor(location.averageScore) }}
                      >
                        {location.averageScore}/100
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Trends Tab */}
      {selectedView === 'trends' && (
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Business Discovery Trends</CardTitle>
            </CardHeader>
            <CardContent>
              <div role="img" aria-label="Business discovery trends over time">
                <ResponsiveContainer width="100%" height={400}>
                  <LineChart data={insights.trendData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" />
                    <YAxis />
                    <Tooltip content={<CustomTooltip />} />
                    <Legend />
                    <Line 
                      type="monotone" 
                      dataKey="value" 
                      stroke="#3B82F6" 
                      strokeWidth={2}
                      name="Businesses Discovered"
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Market Insights */}
          {marketInsights.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Market Insights</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {marketInsights.slice(0, 5).map((insight, index) => (
                    <div key={index} className="p-4 border border-gray-200 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="font-medium">{insight.industry}</h4>
                        <div className="flex items-center">
                          {insight.trend === 'growing' ? (
                            <TrendingUp className="w-4 h-4 text-green-600 mr-1" />
                          ) : insight.trend === 'declining' ? (
                            <TrendingDown className="w-4 h-4 text-red-600 mr-1" />
                          ) : null}
                          <span className={`text-sm ${
                            insight.trend === 'growing' ? 'text-green-600' : 
                            insight.trend === 'declining' ? 'text-red-600' : 
                            'text-gray-600'
                          }`}>
                            {insight.trend} ({insight.growthRate > 0 ? '+' : ''}{insight.growthRate.toFixed(1)}%)
                          </span>
                        </div>
                      </div>
                      <div className="text-sm text-gray-600">
                        Competition: <span className="font-medium">{insight.competitionLevel}</span>
                      </div>
                      {insight.recommendations.length > 0 && (
                        <div className="mt-2">
                          <p className="text-sm text-blue-600">{insight.recommendations[0]}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Predictions Tab */}
      {selectedView === 'predictions' && (
        <div className="space-y-6">
          {/* ROI Forecasts */}
          <Card>
            <CardHeader>
              <CardTitle>ROI Forecasts</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {roiForecasts.map((forecast, index) => (
                  <div key={index} className="p-4 bg-gradient-to-br from-blue-50 to-purple-50 rounded-lg">
                    <h4 className="font-medium text-gray-900 mb-2">{forecast.timeframe}</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600">Revenue:</span>
                        <span className="font-medium text-green-600">
                          ${formatNumber(forecast.expectedRevenue)}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Costs:</span>
                        <span className="font-medium text-red-600">
                          ${formatNumber(forecast.expectedCosts)}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">ROI:</span>
                        <span className="font-medium text-purple-600">
                          {formatNumber(forecast.projectedROI, 'percentage')}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Confidence:</span>
                        <span className="font-medium">
                          {formatNumber(forecast.confidence, 'percentage')}
                        </span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Conversion Predictions */}
          <Card>
            <CardHeader>
              <CardTitle>Conversion Predictions</CardTitle>
            </CardHeader>
            <CardContent>
              <div role="img" aria-label="Predicted conversions by lead quality">
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={processChartData(insights.conversionPredictions)}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip content={<CustomTooltip />} />
                    <Bar dataKey="value" fill="#10B981" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Trend Predictions */}
          {trendPredictions.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Trend Predictions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {trendPredictions.map((prediction, index) => (
                    <div key={index} className="p-4 border border-gray-200 rounded-lg">
                      <h4 className="font-medium mb-2">{prediction.period}</h4>
                      <div className="text-2xl font-bold text-blue-600 mb-2">
                        {formatNumber(prediction.predictedLeads)} leads
                      </div>
                      <div className="text-sm text-gray-600 mb-2">
                        Confidence: {formatNumber(prediction.confidence, 'percentage')}
                      </div>
                      {prediction.seasonalFactors.length > 0 && (
                        <div className="text-sm text-gray-600">
                          Factors: {prediction.seasonalFactors.join(', ')}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {/* Recommendations */}
      {insights.summary.recommendations.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>AI Recommendations</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {insights.summary.recommendations.map((recommendation, index) => (
                <div key={index} className="flex items-start p-3 bg-blue-50 rounded-lg">
                  <div className="w-2 h-2 bg-blue-600 rounded-full mt-2 mr-3 flex-shrink-0" />
                  <p className="text-sm text-blue-800">{recommendation}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
