'use client'

/**
 * HubSpot CRM Dashboard Component
 * React dashboard for HubSpot integration with real-time sync
 */

import React, { useState, useEffect, useCallback } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Badge } from './ui/Badge'
import { 
  Settings, 
  Sync, 
  Users, 
  Building2, 
  TrendingUp, 
  AlertCircle,
  CheckCircle,
  Clock,
  ExternalLink
} from 'lucide-react'
import { logger } from '@/utils/logger'

interface HubSpotStats {
  totalContacts: number
  totalCompanies: number
  totalDeals: number
  syncedToday: number
  lastSyncTime: string
  syncStatus: 'success' | 'error' | 'pending' | 'never'
  connectionStatus: 'connected' | 'disconnected' | 'error'
}

interface HubSpotProvider {
  id: string
  name: string
  portalId: string
  isActive: boolean
  lastSyncTime?: string
  syncStatus?: string
}

interface SyncRecord {
  id: string
  businessName: string
  email: string
  syncStatus: 'synced' | 'failed' | 'pending'
  syncTime: string
  hubspotContactId?: string
  hubspotCompanyId?: string
  errorMessage?: string
}

export function HubSpotDashboard() {
  const [stats, setStats] = useState<HubSpotStats>({
    totalContacts: 0,
    totalCompanies: 0,
    totalDeals: 0,
    syncedToday: 0,
    lastSyncTime: 'Never',
    syncStatus: 'never',
    connectionStatus: 'disconnected'
  })
  
  const [providers, setProviders] = useState<HubSpotProvider[]>([])
  const [recentSyncs, setRecentSyncs] = useState<SyncRecord[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [isSyncing, setIsSyncing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Load dashboard data
  const loadDashboardData = useCallback(async () => {
    try {
      setIsLoading(true)
      setError(null)

      // Load CRM providers
      const providersResponse = await fetch('/api/crm')
      if (providersResponse.ok) {
        const providersData = await providersResponse.json()
        const hubspotProviders = providersData.data.providers.filter(
          (p: any) => p.type === 'hubspot'
        )
        setProviders(hubspotProviders)
      }

      // Load sync history
      const syncResponse = await fetch('/api/crm/sync?providerId=hubspot&limit=10')
      if (syncResponse.ok) {
        const syncData = await syncResponse.json()
        setRecentSyncs(syncData.data.syncHistory || [])
      }

      // Load HubSpot-specific stats (mock data for now)
      setStats({
        totalContacts: 1250,
        totalCompanies: 340,
        totalDeals: 89,
        syncedToday: 23,
        lastSyncTime: new Date().toLocaleString(),
        syncStatus: 'success',
        connectionStatus: 'connected'
      })

    } catch (error) {
      logger.error('HubSpotDashboard', 'Failed to load dashboard data', error)
      setError('Failed to load dashboard data')
    } finally {
      setIsLoading(false)
    }
  }, [])

  // Initialize OAuth flow
  const initiateOAuth = useCallback(async () => {
    try {
      setError(null)
      
      // Redirect to OAuth initiation endpoint
      window.location.href = '/api/crm/hubspot/oauth'
    } catch (error) {
      logger.error('HubSpotDashboard', 'Failed to initiate OAuth', error)
      setError('Failed to initiate HubSpot connection')
    }
  }, [])

  // Trigger manual sync
  const triggerSync = useCallback(async () => {
    try {
      setIsSyncing(true)
      setError(null)

      const response = await fetch('/api/crm/sync', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          providerIds: providers.map(p => p.id),
          syncMode: 'push'
        })
      })

      if (response.ok) {
        const result = await response.json()
        logger.info('HubSpotDashboard', 'Sync triggered successfully', result)
        
        // Reload data after sync
        setTimeout(() => {
          loadDashboardData()
        }, 2000)
      } else {
        throw new Error('Sync request failed')
      }
    } catch (error) {
      logger.error('HubSpotDashboard', 'Failed to trigger sync', error)
      setError('Failed to trigger sync')
    } finally {
      setIsSyncing(false)
    }
  }, [providers, loadDashboardData])

  // Disconnect provider
  const disconnectProvider = useCallback(async (providerId: string) => {
    try {
      setError(null)

      const response = await fetch(`/api/crm?id=${providerId}`, {
        method: 'DELETE'
      })

      if (response.ok) {
        logger.info('HubSpotDashboard', 'Provider disconnected successfully')
        loadDashboardData()
      } else {
        throw new Error('Failed to disconnect provider')
      }
    } catch (error) {
      logger.error('HubSpotDashboard', 'Failed to disconnect provider', error)
      setError('Failed to disconnect provider')
    }
  }, [loadDashboardData])

  // Load data on component mount
  useEffect(() => {
    loadDashboardData()
  }, [loadDashboardData])

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(loadDashboardData, 30000)
    return () => clearInterval(interval)
  }, [loadDashboardData])

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success':
      case 'synced':
      case 'connected':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'error':
      case 'failed':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      case 'pending':
        return <Clock className="h-4 w-4 text-yellow-500" />
      default:
        return <AlertCircle className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusVariant = (status: string) => {
    switch (status) {
      case 'success':
      case 'synced':
      case 'connected':
        return 'success'
      case 'error':
      case 'failed':
        return 'destructive'
      case 'pending':
        return 'warning'
      default:
        return 'secondary'
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">HubSpot Integration</h2>
          <p className="text-muted-foreground">
            Manage your HubSpot CRM integration and sync business data
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={loadDashboardData}
            disabled={isLoading}
          >
            <Sync className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          {providers.length === 0 ? (
            <Button onClick={initiateOAuth}>
              <ExternalLink className="h-4 w-4 mr-2" />
              Connect HubSpot
            </Button>
          ) : (
            <Button
              onClick={triggerSync}
              disabled={isSyncing}
            >
              <Sync className={`h-4 w-4 mr-2 ${isSyncing ? 'animate-spin' : ''}`} />
              Sync Now
            </Button>
          )}
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="pt-6">
            <div className="flex items-center gap-2 text-red-700">
              <AlertCircle className="h-4 w-4" />
              <span>{error}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Connection Status */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            Connection Status
          </CardTitle>
        </CardHeader>
        <CardContent>
          {providers.length === 0 ? (
            <div className="text-center py-8">
              <Building2 className="h-12 w-12 mx-auto text-gray-400 mb-4" />
              <h3 className="text-lg font-medium mb-2">No HubSpot Connection</h3>
              <p className="text-muted-foreground mb-4">
                Connect your HubSpot account to start syncing business data
              </p>
              <Button onClick={initiateOAuth}>
                <ExternalLink className="h-4 w-4 mr-2" />
                Connect HubSpot Account
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {providers.map((provider) => (
                <div key={provider.id} className="flex items-center justify-between p-4 border rounded-lg">
                  <div className="flex items-center gap-3">
                    {getStatusIcon(stats.connectionStatus)}
                    <div>
                      <h4 className="font-medium">{provider.name}</h4>
                      <p className="text-sm text-muted-foreground">
                        Portal ID: {provider.portalId}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant={getStatusVariant(stats.connectionStatus)}>
                      {stats.connectionStatus}
                    </Badge>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => disconnectProvider(provider.id)}
                    >
                      Disconnect
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Statistics */}
      {providers.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Users className="h-8 w-8 text-blue-500" />
                <div>
                  <p className="text-2xl font-bold">{stats.totalContacts.toLocaleString()}</p>
                  <p className="text-sm text-muted-foreground">Total Contacts</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Building2 className="h-8 w-8 text-green-500" />
                <div>
                  <p className="text-2xl font-bold">{stats.totalCompanies.toLocaleString()}</p>
                  <p className="text-sm text-muted-foreground">Total Companies</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-8 w-8 text-purple-500" />
                <div>
                  <p className="text-2xl font-bold">{stats.totalDeals.toLocaleString()}</p>
                  <p className="text-sm text-muted-foreground">Total Deals</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="pt-6">
              <div className="flex items-center gap-2">
                <Sync className="h-8 w-8 text-orange-500" />
                <div>
                  <p className="text-2xl font-bold">{stats.syncedToday}</p>
                  <p className="text-sm text-muted-foreground">Synced Today</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Recent Sync Activity */}
      {providers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Recent Sync Activity</CardTitle>
          </CardHeader>
          <CardContent>
            {recentSyncs.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground">
                No recent sync activity
              </div>
            ) : (
              <div className="space-y-3">
                {recentSyncs.map((sync) => (
                  <div key={sync.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex items-center gap-3">
                      {getStatusIcon(sync.syncStatus)}
                      <div>
                        <h4 className="font-medium">{sync.businessName}</h4>
                        <p className="text-sm text-muted-foreground">{sync.email}</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <Badge variant={getStatusVariant(sync.syncStatus)}>
                        {sync.syncStatus}
                      </Badge>
                      <p className="text-xs text-muted-foreground mt-1">
                        {new Date(sync.syncTime).toLocaleString()}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Sync Status */}
      {providers.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Sync Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {getStatusIcon(stats.syncStatus)}
                <span>Last sync: {stats.lastSyncTime}</span>
              </div>
              <Badge variant={getStatusVariant(stats.syncStatus)}>
                {stats.syncStatus}
              </Badge>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
