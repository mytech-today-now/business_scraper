/**
 * Data Retention Hook
 * Encapsulates data lifecycle enforcement logic for compliance
 */

import { useState, useEffect, useCallback } from 'react'
import { logger } from '@/utils/logger'

// Retention policy interface
interface RetentionPolicy {
  id: string
  name: string
  description: string
  dataType: string
  retentionPeriodDays: number
  legalBasis: string
  autoDelete: boolean
  archiveBeforeDelete: boolean
  notificationDays: number[]
  isActive: boolean
  createdAt: Date
  updatedAt: Date
}

// Retention status interface
interface RetentionStatus {
  dataType: string
  totalRecords: number
  expiredRecords: number
  nextPurgeDate?: Date
  lastPurgeDate?: Date
  policy: RetentionPolicy
}

// Purge record interface
interface PurgeRecord {
  id: string
  policyId: string
  dataType: string
  recordsAffected: number
  purgeDate: Date
  reason: string
  status: 'pending' | 'completed' | 'failed'
  details: Record<string, any>
}

// Retention context
interface RetentionContext {
  policies: RetentionPolicy[]
  statuses: RetentionStatus[]
  purgeHistory: PurgeRecord[]
  loading: boolean
  error: string | null

  // Policy management
  createPolicy: (
    policy: Omit<RetentionPolicy, 'id' | 'createdAt' | 'updatedAt'>
  ) => Promise<boolean>
  updatePolicy: (id: string, updates: Partial<RetentionPolicy>) => Promise<boolean>
  deletePolicy: (id: string) => Promise<boolean>

  // Retention operations
  checkRetentionStatus: (dataType?: string) => Promise<void>
  executePurge: (policyId: string) => Promise<boolean>
  scheduleRetention: (policyId: string, cronExpression: string) => Promise<boolean>

  // Data lifecycle
  markForRetention: (dataType: string, recordId: string, retentionDate: Date) => Promise<boolean>
  extendRetention: (dataType: string, recordId: string, extensionDays: number) => Promise<boolean>

  // Compliance reporting
  generateRetentionReport: (startDate: Date, endDate: Date) => Promise<any>
  getUpcomingPurges: (days: number) => Promise<RetentionStatus[]>

  // Utilities
  refreshData: () => Promise<void>
  calculateRetentionDate: (createdDate: Date, retentionDays: number) => Date
  isRetentionExpired: (createdDate: Date, retentionDays: number) => boolean
}

/**
 * Data retention management hook
 */
export function useRetention(): RetentionContext {
  const [policies, setPolicies] = useState<RetentionPolicy[]>([])
  const [statuses, setStatuses] = useState<RetentionStatus[]>([])
  const [purgeHistory, setPurgeHistory] = useState<PurgeRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Load retention data
  const loadRetentionData = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)

      // Load policies
      const policiesResponse = await fetch('/api/compliance/retention/policies')
      if (!policiesResponse.ok) {
        throw new Error('Failed to load retention policies')
      }
      const policiesData = await policiesResponse.json()
      setPolicies(policiesData.policies || [])

      // Load statuses
      const statusesResponse = await fetch('/api/compliance/retention/status')
      if (!statusesResponse.ok) {
        throw new Error('Failed to load retention statuses')
      }
      const statusesData = await statusesResponse.json()
      setStatuses(statusesData.statuses || [])

      // Load purge history
      const historyResponse = await fetch('/api/compliance/retention/history?limit=50')
      if (!historyResponse.ok) {
        throw new Error('Failed to load purge history')
      }
      const historyData = await historyResponse.json()
      setPurgeHistory(historyData.records || [])
    } catch (error) {
      logger.error('Retention Hook', 'Failed to load retention data', error)
      setError('Failed to load retention data')
    } finally {
      setLoading(false)
    }
  }, [])

  // Load data on mount
  useEffect(() => {
    loadRetentionData()
  }, [loadRetentionData])

  // Create retention policy
  const createPolicy = useCallback(
    async (policy: Omit<RetentionPolicy, 'id' | 'createdAt' | 'updatedAt'>): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/retention/policies', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(policy),
        })

        if (response.ok) {
          await loadRetentionData() // Refresh data
          return true
        } else {
          throw new Error('Failed to create retention policy')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to create policy', error)
        setError('Failed to create retention policy')
        return false
      }
    },
    [loadRetentionData]
  )

  // Update retention policy
  const updatePolicy = useCallback(
    async (id: string, updates: Partial<RetentionPolicy>): Promise<boolean> => {
      try {
        const response = await fetch(`/api/compliance/retention/policies/${id}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(updates),
        })

        if (response.ok) {
          await loadRetentionData() // Refresh data
          return true
        } else {
          throw new Error('Failed to update retention policy')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to update policy', error)
        setError('Failed to update retention policy')
        return false
      }
    },
    [loadRetentionData]
  )

  // Delete retention policy
  const deletePolicy = useCallback(
    async (id: string): Promise<boolean> => {
      try {
        const response = await fetch(`/api/compliance/retention/policies/${id}`, {
          method: 'DELETE',
        })

        if (response.ok) {
          await loadRetentionData() // Refresh data
          return true
        } else {
          throw new Error('Failed to delete retention policy')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to delete policy', error)
        setError('Failed to delete retention policy')
        return false
      }
    },
    [loadRetentionData]
  )

  // Check retention status
  const checkRetentionStatus = useCallback(
    async (dataType?: string): Promise<void> => {
      try {
        const params = dataType ? `?dataType=${encodeURIComponent(dataType)}` : ''
        const response = await fetch(`/api/compliance/retention/check${params}`)

        if (response.ok) {
          await loadRetentionData() // Refresh data
        } else {
          throw new Error('Failed to check retention status')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to check retention status', error)
        setError('Failed to check retention status')
      }
    },
    [loadRetentionData]
  )

  // Execute purge
  const executePurge = useCallback(
    async (policyId: string): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/retention/purge', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ policyId }),
        })

        if (response.ok) {
          await loadRetentionData() // Refresh data
          return true
        } else {
          throw new Error('Failed to execute purge')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to execute purge', error)
        setError('Failed to execute purge')
        return false
      }
    },
    [loadRetentionData]
  )

  // Schedule retention
  const scheduleRetention = useCallback(
    async (policyId: string, cronExpression: string): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/retention/schedule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ policyId, cronExpression }),
        })

        if (response.ok) {
          await loadRetentionData() // Refresh data
          return true
        } else {
          throw new Error('Failed to schedule retention')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to schedule retention', error)
        setError('Failed to schedule retention')
        return false
      }
    },
    [loadRetentionData]
  )

  // Mark for retention
  const markForRetention = useCallback(
    async (dataType: string, recordId: string, retentionDate: Date): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/retention/mark', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dataType,
            recordId,
            retentionDate: retentionDate.toISOString(),
          }),
        })

        if (response.ok) {
          return true
        } else {
          throw new Error('Failed to mark for retention')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to mark for retention', error)
        setError('Failed to mark for retention')
        return false
      }
    },
    []
  )

  // Extend retention
  const extendRetention = useCallback(
    async (dataType: string, recordId: string, extensionDays: number): Promise<boolean> => {
      try {
        const response = await fetch('/api/compliance/retention/extend', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            dataType,
            recordId,
            extensionDays,
          }),
        })

        if (response.ok) {
          return true
        } else {
          throw new Error('Failed to extend retention')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to extend retention', error)
        setError('Failed to extend retention')
        return false
      }
    },
    []
  )

  // Generate retention report
  const generateRetentionReport = useCallback(
    async (startDate: Date, endDate: Date): Promise<any> => {
      try {
        const response = await fetch('/api/compliance/retention/report', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            startDate: startDate.toISOString(),
            endDate: endDate.toISOString(),
          }),
        })

        if (response.ok) {
          return await response.json()
        } else {
          throw new Error('Failed to generate retention report')
        }
      } catch (error) {
        logger.error('Retention Hook', 'Failed to generate retention report', error)
        setError('Failed to generate retention report')
        return null
      }
    },
    []
  )

  // Get upcoming purges
  const getUpcomingPurges = useCallback(async (days: number): Promise<RetentionStatus[]> => {
    try {
      const response = await fetch(`/api/compliance/retention/upcoming?days=${days}`)

      if (response.ok) {
        const data = await response.json()
        return data.statuses || []
      } else {
        throw new Error('Failed to get upcoming purges')
      }
    } catch (error) {
      logger.error('Retention Hook', 'Failed to get upcoming purges', error)
      setError('Failed to get upcoming purges')
      return []
    }
  }, [])

  // Refresh data
  const refreshData = useCallback(async (): Promise<void> => {
    await loadRetentionData()
  }, [loadRetentionData])

  // Calculate retention date
  const calculateRetentionDate = useCallback((createdDate: Date, retentionDays: number): Date => {
    const retentionDate = new Date(createdDate)
    retentionDate.setDate(retentionDate.getDate() + retentionDays)
    return retentionDate
  }, [])

  // Check if retention is expired
  const isRetentionExpired = useCallback(
    (createdDate: Date, retentionDays: number): boolean => {
      const retentionDate = calculateRetentionDate(createdDate, retentionDays)
      return new Date() > retentionDate
    },
    [calculateRetentionDate]
  )

  return {
    policies,
    statuses,
    purgeHistory,
    loading,
    error,
    createPolicy,
    updatePolicy,
    deletePolicy,
    checkRetentionStatus,
    executePurge,
    scheduleRetention,
    markForRetention,
    extendRetention,
    generateRetentionReport,
    getUpcomingPurges,
    refreshData,
    calculateRetentionDate,
    isRetentionExpired,
  }
}

/**
 * Hook for checking specific data retention
 */
export function useDataRetention(dataType: string) {
  const { policies, statuses, isRetentionExpired } = useRetention()

  const policy = policies.find(p => p.dataType === dataType)
  const status = statuses.find(s => s.dataType === dataType)

  const checkRecordRetention = useCallback(
    (
      createdDate: Date
    ): {
      isExpired: boolean
      retentionDate: Date
      daysRemaining: number
    } => {
      if (!policy) {
        return {
          isExpired: false,
          retentionDate: new Date(),
          daysRemaining: 0,
        }
      }

      const retentionDate = new Date(createdDate)
      retentionDate.setDate(retentionDate.getDate() + policy.retentionPeriodDays)

      const now = new Date()
      const daysRemaining = Math.ceil(
        (retentionDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
      )

      return {
        isExpired: isRetentionExpired(createdDate, policy.retentionPeriodDays),
        retentionDate,
        daysRemaining: Math.max(0, daysRemaining),
      }
    },
    [policy, isRetentionExpired]
  )

  return {
    policy,
    status,
    checkRecordRetention,
    hasPolicy: !!policy,
    autoDelete: policy?.autoDelete || false,
    retentionDays: policy?.retentionPeriodDays || 0,
  }
}

/**
 * Utility functions for retention management
 */
export const RetentionUtils = {
  /**
   * Format retention period for display
   */
  formatRetentionPeriod: (days: number): string => {
    if (days < 30) {
      return `${days} day${days !== 1 ? 's' : ''}`
    } else if (days < 365) {
      const months = Math.round(days / 30)
      return `${months} month${months !== 1 ? 's' : ''}`
    } else {
      const years = Math.round(days / 365)
      return `${years} year${years !== 1 ? 's' : ''}`
    }
  },

  /**
   * Get retention urgency level
   */
  getRetentionUrgency: (daysRemaining: number): 'low' | 'medium' | 'high' | 'critical' => {
    if (daysRemaining <= 0) return 'critical'
    if (daysRemaining <= 7) return 'high'
    if (daysRemaining <= 30) return 'medium'
    return 'low'
  },

  /**
   * Get urgency color
   */
  getUrgencyColor: (urgency: string): string => {
    const colors = {
      low: 'text-green-600',
      medium: 'text-yellow-600',
      high: 'text-orange-600',
      critical: 'text-red-600',
    }
    return colors[urgency as keyof typeof colors] || 'text-gray-600'
  },

  /**
   * Validate retention policy
   */
  validateRetentionPolicy: (policy: Partial<RetentionPolicy>): string[] => {
    const errors: string[] = []

    if (!policy.name?.trim()) {
      errors.push('Policy name is required')
    }

    if (!policy.dataType?.trim()) {
      errors.push('Data type is required')
    }

    if (!policy.retentionPeriodDays || policy.retentionPeriodDays < 1) {
      errors.push('Retention period must be at least 1 day')
    }

    if (!policy.legalBasis?.trim()) {
      errors.push('Legal basis is required')
    }

    return errors
  },
}
