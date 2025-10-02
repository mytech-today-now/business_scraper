/**
 * Data Visualization Component
 * Secure data visualization with input validation and sanitization
 */

'use client'

import React, { useMemo } from 'react'
import { X, BarChart3, PieChart } from 'lucide-react'
import { SecurityBoundary, SecurityUtils } from '../security/SecurityBoundary'
import { Button } from '../ui/Button'
import { Card, CardHeader, CardTitle, CardContent } from '../ui/Card'
import { BusinessRecord } from '@/types/business'
import { logger } from '@/utils/logger'

export interface DataVisualizationProps {
  businesses: BusinessRecord[]
  onClose: () => void
}

export interface VisualizationData {
  type: 'bar' | 'pie' | 'line' | 'scatter' | 'map'
  title: string
  data: any[]
  config: any
}

/**
 * Data Visualization component with security validation
 */
export function DataVisualization({
  businesses,
  onClose,
}: DataVisualizationProps): JSX.Element {

  /**
   * Generate secure industry distribution data
   */
  const industryDistribution = useMemo(() => {
    try {
      // Validate and sanitize business data
      const validatedBusinesses = businesses.map(business => {
        const validation = SecurityUtils.validateBusinessData(business)
        if (!validation.isValid) {
          logger.debug('DataVisualization', 'Sanitizing business data for visualization', {
            businessId: business.id,
            errors: validation.errors
          })
        }
        return SecurityUtils.sanitizeBusinessData(business)
      })

      const industryData = validatedBusinesses.reduce(
        (acc, business) => {
          const industry = business.industry || 'Unknown'
          acc[industry] = (acc[industry] || 0) + 1
          return acc
        },
        {} as Record<string, number>
      )

      return Object.entries(industryData)
        .map(([industry, count]) => ({
          name: industry,
          value: count,
          percentage: ((count / validatedBusinesses.length) * 100).toFixed(1)
        }))
        .sort((a, b) => b.value - a.value)
    } catch (error) {
      logger.error('DataVisualization', 'Failed to generate industry distribution', error)
      return []
    }
  }, [businesses])

  /**
   * Generate secure geographic distribution data
   */
  const geographicDistribution = useMemo(() => {
    try {
      // Validate and sanitize business data
      const validatedBusinesses = businesses.map(business => {
        const validation = SecurityUtils.validateBusinessData(business)
        if (!validation.isValid) {
          logger.debug('DataVisualization', 'Sanitizing business data for geographic visualization', {
            businessId: business.id,
            errors: validation.errors
          })
        }
        return SecurityUtils.sanitizeBusinessData(business)
      })

      const stateData = validatedBusinesses.reduce(
        (acc, business) => {
          const state = business.address?.state || 'Unknown'
          acc[state] = (acc[state] || 0) + 1
          return acc
        },
        {} as Record<string, number>
      )

      return Object.entries(stateData)
        .map(([state, count]) => ({
          name: state,
          value: count,
          percentage: ((count / validatedBusinesses.length) * 100).toFixed(1)
        }))
        .sort((a, b) => b.value - a.value)
        .slice(0, 10) // Show top 10 states
    } catch (error) {
      logger.error('DataVisualization', 'Failed to generate geographic distribution', error)
      return []
    }
  }, [businesses])

  /**
   * Generate contact information completeness data
   */
  const contactCompleteness = useMemo(() => {
    try {
      const validatedBusinesses = businesses.map(business => 
        SecurityUtils.sanitizeBusinessData(business)
      )

      const completeness = {
        'Email Only': 0,
        'Phone Only': 0,
        'Both Email & Phone': 0,
        'No Contact Info': 0,
      }

      validatedBusinesses.forEach(business => {
        const hasEmail = business.email && business.email.length > 0 && business.email[0]
        const hasPhone = business.phone && business.phone.trim() !== ''

        if (hasEmail && hasPhone) {
          completeness['Both Email & Phone']++
        } else if (hasEmail) {
          completeness['Email Only']++
        } else if (hasPhone) {
          completeness['Phone Only']++
        } else {
          completeness['No Contact Info']++
        }
      })

      return Object.entries(completeness)
        .map(([category, count]) => ({
          name: category,
          value: count,
          percentage: ((count / validatedBusinesses.length) * 100).toFixed(1)
        }))
        .filter(item => item.value > 0)
    } catch (error) {
      logger.error('DataVisualization', 'Failed to generate contact completeness data', error)
      return []
    }
  }, [businesses])

  /**
   * Secure close handler
   */
  const handleClose = () => {
    try {
      logger.debug('DataVisualization', 'Visualization closed')
      onClose()
    } catch (error) {
      logger.error('DataVisualization', 'Failed to close visualization', error)
    }
  }

  return (
    <SecurityBoundary componentName="DataVisualization">
      <Card className="p-6">
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
          <CardTitle className="flex items-center space-x-2">
            <BarChart3 className="h-5 w-5" />
            <span>Data Visualization</span>
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={handleClose}
            icon={X}
            aria-label="Close visualization"
          />
        </CardHeader>
        
        <CardContent>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Industry Distribution */}
            <SecurityBoundary componentName="IndustryChart">
              <div className="space-y-4">
                <div className="flex items-center space-x-2">
                  <PieChart className="h-4 w-4" />
                  <h3 className="font-semibold">Industry Distribution</h3>
                </div>
                
                <div className="space-y-2">
                  {industryDistribution.map((item, index) => (
                    <div key={item.name} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <span className="text-sm font-medium">{item.name}</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-gray-600">{item.value}</span>
                        <span className="text-xs text-gray-500">({item.percentage}%)</span>
                      </div>
                    </div>
                  ))}
                  {industryDistribution.length === 0 && (
                    <p className="text-sm text-gray-500 text-center py-4">
                      No industry data available
                    </p>
                  )}
                </div>
              </div>
            </SecurityBoundary>

            {/* Geographic Distribution */}
            <SecurityBoundary componentName="GeographicChart">
              <div className="space-y-4">
                <div className="flex items-center space-x-2">
                  <BarChart3 className="h-4 w-4" />
                  <h3 className="font-semibold">Geographic Distribution (Top 10)</h3>
                </div>
                
                <div className="space-y-2">
                  {geographicDistribution.map((item, index) => (
                    <div key={item.name} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <span className="text-sm font-medium">{item.name}</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-gray-600">{item.value}</span>
                        <span className="text-xs text-gray-500">({item.percentage}%)</span>
                      </div>
                    </div>
                  ))}
                  {geographicDistribution.length === 0 && (
                    <p className="text-sm text-gray-500 text-center py-4">
                      No geographic data available
                    </p>
                  )}
                </div>
              </div>
            </SecurityBoundary>

            {/* Contact Information Completeness */}
            <SecurityBoundary componentName="ContactCompletenessChart">
              <div className="space-y-4">
                <div className="flex items-center space-x-2">
                  <PieChart className="h-4 w-4" />
                  <h3 className="font-semibold">Contact Information Completeness</h3>
                </div>
                
                <div className="space-y-2">
                  {contactCompleteness.map((item, index) => (
                    <div key={item.name} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <span className="text-sm font-medium">{item.name}</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-sm text-gray-600">{item.value}</span>
                        <span className="text-xs text-gray-500">({item.percentage}%)</span>
                      </div>
                    </div>
                  ))}
                  {contactCompleteness.length === 0 && (
                    <p className="text-sm text-gray-500 text-center py-4">
                      No contact data available
                    </p>
                  )}
                </div>
              </div>
            </SecurityBoundary>

            {/* Summary Statistics */}
            <SecurityBoundary componentName="SummaryStats">
              <div className="space-y-4">
                <h3 className="font-semibold">Summary Statistics</h3>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 bg-blue-50 rounded-lg text-center">
                    <div className="text-2xl font-bold text-blue-600">{businesses.length}</div>
                    <div className="text-sm text-blue-800">Total Businesses</div>
                  </div>
                  
                  <div className="p-3 bg-green-50 rounded-lg text-center">
                    <div className="text-2xl font-bold text-green-600">{industryDistribution.length}</div>
                    <div className="text-sm text-green-800">Industries</div>
                  </div>
                  
                  <div className="p-3 bg-purple-50 rounded-lg text-center">
                    <div className="text-2xl font-bold text-purple-600">{geographicDistribution.length}</div>
                    <div className="text-sm text-purple-800">States/Regions</div>
                  </div>
                  
                  <div className="p-3 bg-orange-50 rounded-lg text-center">
                    <div className="text-2xl font-bold text-orange-600">
                      {contactCompleteness.find(item => item.name === 'Both Email & Phone')?.value || 0}
                    </div>
                    <div className="text-sm text-orange-800">Complete Contacts</div>
                  </div>
                </div>
              </div>
            </SecurityBoundary>
          </div>

          {/* Data Quality Notice */}
          <div className="mt-6 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
            <p className="text-sm text-yellow-800">
              <strong>Data Quality:</strong> All data has been validated and sanitized for security. 
              Charts show sanitized business information to prevent XSS and injection attacks.
            </p>
          </div>
        </CardContent>
      </Card>
    </SecurityBoundary>
  )
}
