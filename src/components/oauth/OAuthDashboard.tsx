/**
 * OAuth 2.0 Management Dashboard
 * Provides UI for managing OAuth clients, tokens, and monitoring
 */

'use client'

import React, { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  Shield,
  Key,
  Users,
  Activity,
  Plus,
  Eye,
  EyeOff,
  Copy,
  Trash2,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Clock,
} from 'lucide-react'
import { ClientRegistrationForm } from './ClientRegistrationForm'

interface OAuthClient {
  id: string
  name: string
  type: 'public' | 'confidential'
  secret?: string
  redirectUris: string[]
  allowedScopes: string[]
  isActive: boolean
  createdAt: string
  metadata?: Record<string, any>
}

interface TokenStats {
  totalAccessTokens: number
  activeAccessTokens: number
  totalRefreshTokens: number
  activeRefreshTokens: number
  blacklistedTokens: number
}

interface ClientStats {
  totalClients: number
  activeClients: number
  publicClients: number
  confidentialClients: number
}

export default function OAuthDashboard(): JSX.Element {
  const [clients, setClients] = useState<OAuthClient[]>([])
  const [tokenStats, setTokenStats] = useState<TokenStats | null>(null)
  const [clientStats, setClientStats] = useState<ClientStats | null>(null)
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({})
  const [loading, setLoading] = useState(true)
  const [showRegistrationForm, setShowRegistrationForm] = useState(false)

  useEffect(() => {
    loadDashboardData()
  }, [])

  const loadDashboardData = async (): Promise<void> => {
    try {
      setLoading(true)

      // In a real implementation, these would be API calls
      // For now, we'll use mock data
      const mockClients: OAuthClient[] = [
        {
          id: 'business-scraper-web',
          name: 'Business Scraper Web Application',
          type: 'confidential',
          secret: 'web_client_secret_12345',
          redirectUris: ['http://localhost:3000/auth/callback'],
          allowedScopes: ['openid', 'profile', 'email', 'read', 'write'],
          isActive: true,
          createdAt: new Date().toISOString(),
          metadata: { description: 'Default web application client', isDefault: true },
        },
        {
          id: 'business-scraper-mobile',
          name: 'Business Scraper Mobile/SPA',
          type: 'public',
          redirectUris: ['com.businessscraper://auth/callback'],
          allowedScopes: ['openid', 'profile', 'email', 'read'],
          isActive: true,
          createdAt: new Date().toISOString(),
          metadata: { description: 'Default mobile and SPA client', requiresPkce: true },
        },
        {
          id: 'business-scraper-api',
          name: 'Business Scraper API Client',
          type: 'confidential',
          secret: 'api_client_secret_67890',
          redirectUris: [],
          allowedScopes: ['read', 'write', 'admin'],
          isActive: true,
          createdAt: new Date().toISOString(),
          metadata: { description: 'Default API client for server-to-server communication' },
        },
      ]

      const mockTokenStats: TokenStats = {
        totalAccessTokens: 45,
        activeAccessTokens: 23,
        totalRefreshTokens: 38,
        activeRefreshTokens: 19,
        blacklistedTokens: 7,
      }

      const mockClientStats: ClientStats = {
        totalClients: 3,
        activeClients: 3,
        publicClients: 1,
        confidentialClients: 2,
      }

      setClients(mockClients)
      setTokenStats(mockTokenStats)
      setClientStats(mockClientStats)
    } catch (error) {
      console.error('Failed to load OAuth dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  const toggleSecretVisibility = (clientId: string): void => {
    setShowSecrets(prev => ({
      ...prev,
      [clientId]: !prev[clientId],
    }))
  }

  const copyToClipboard = async (text: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(text)
      // In a real implementation, show a toast notification
      console.log('Copied to clipboard')
    } catch (error) {
      console.error('Failed to copy to clipboard:', error)
    }
  }

  const revokeClient = async (clientId: string): Promise<void> => {
    try {
      // In a real implementation, make API call to revoke client
      setClients(prev =>
        prev.map(client => (client.id === clientId ? { ...client, isActive: false } : client))
      )
      console.log(`Client ${clientId} revoked`)
    } catch (error) {
      console.error('Failed to revoke client:', error)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin" />
        <span className="ml-2">Loading OAuth dashboard...</span>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">OAuth 2.0 Management</h1>
          <p className="text-muted-foreground">
            Manage OAuth clients, tokens, and monitor authentication activity
          </p>
        </div>
        <Button onClick={() => setShowRegistrationForm(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Register New Client
        </Button>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Clients</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{clientStats?.activeClients}</div>
            <p className="text-xs text-muted-foreground">
              {clientStats?.totalClients} total clients
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Tokens</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tokenStats?.activeAccessTokens}</div>
            <p className="text-xs text-muted-foreground">
              {tokenStats?.totalAccessTokens} total access tokens
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Refresh Tokens</CardTitle>
            <RefreshCw className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tokenStats?.activeRefreshTokens}</div>
            <p className="text-xs text-muted-foreground">
              {tokenStats?.totalRefreshTokens} total refresh tokens
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{tokenStats?.blacklistedTokens}</div>
            <p className="text-xs text-muted-foreground">Revoked tokens</p>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs defaultValue="clients" className="space-y-4">
        <TabsList>
          <TabsTrigger value="clients">OAuth Clients</TabsTrigger>
          <TabsTrigger value="tokens">Token Management</TabsTrigger>
          <TabsTrigger value="activity">Activity Monitor</TabsTrigger>
          <TabsTrigger value="settings">Settings</TabsTrigger>
        </TabsList>

        <TabsContent value="clients" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Registered OAuth Clients</CardTitle>
              <CardDescription>Manage OAuth 2.0 clients and their configurations</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {clients.map(client => (
                  <div key={client.id} className="border rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <h3 className="font-semibold">{client.name}</h3>
                        <Badge variant={client.type === 'confidential' ? 'default' : 'secondary'}>
                          {client.type}
                        </Badge>
                        <Badge variant={client.isActive ? 'default' : 'destructive'}>
                          {client.isActive ? 'Active' : 'Inactive'}
                        </Badge>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Button variant="outline" size="sm">
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => revokeClient(client.id)}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                      <div>
                        <label className="font-medium">Client ID:</label>
                        <div className="flex items-center space-x-2 mt-1">
                          <code className="bg-muted px-2 py-1 rounded text-xs">{client.id}</code>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(client.id)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>

                      {client.secret && (
                        <div>
                          <label className="font-medium">Client Secret:</label>
                          <div className="flex items-center space-x-2 mt-1">
                            <code className="bg-muted px-2 py-1 rounded text-xs">
                              {showSecrets[client.id] ? client.secret : '••••••••••••••••'}
                            </code>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => toggleSecretVisibility(client.id)}
                            >
                              {showSecrets[client.id] ? (
                                <EyeOff className="h-3 w-3" />
                              ) : (
                                <Eye className="h-3 w-3" />
                              )}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(client.secret!)}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="space-y-2 text-sm">
                      <div>
                        <label className="font-medium">Allowed Scopes:</label>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {client.allowedScopes.map(scope => (
                            <Badge key={scope} variant="outline" className="text-xs">
                              {scope}
                            </Badge>
                          ))}
                        </div>
                      </div>

                      {client.redirectUris.length > 0 && (
                        <div>
                          <label className="font-medium">Redirect URIs:</label>
                          <div className="space-y-1 mt-1">
                            {client.redirectUris.map((uri, index) => (
                              <code
                                key={index}
                                className="block bg-muted px-2 py-1 rounded text-xs"
                              >
                                {uri}
                              </code>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="tokens" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Token Management</CardTitle>
              <CardDescription>
                Monitor and manage OAuth 2.0 access and refresh tokens
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8">
                <Activity className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Token Management</h3>
                <p className="text-muted-foreground">
                  Token management interface will be implemented here
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="activity" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Activity Monitor</CardTitle>
              <CardDescription>
                Real-time OAuth authentication and authorization activity
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8">
                <Clock className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Activity Monitor</h3>
                <p className="text-muted-foreground">
                  Real-time activity monitoring will be implemented here
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="settings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>OAuth Settings</CardTitle>
              <CardDescription>
                Configure OAuth 2.0 server settings and security policies
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8">
                <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">OAuth Settings</h3>
                <p className="text-muted-foreground">
                  OAuth configuration settings will be implemented here
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Client Registration Form */}
      <ClientRegistrationForm
        open={showRegistrationForm}
        onClose={() => setShowRegistrationForm(false)}
        onClientRegistered={client => {
          // Add new client to the list
          setClients(prev => [
            ...prev,
            {
              id: client.clientId,
              name: client.clientName,
              type: client.clientType,
              secret: client.clientSecret,
              redirectUris: client.redirectUris,
              allowedScopes: client.scope.split(' '),
              isActive: true,
              createdAt: new Date().toISOString(),
            },
          ])
          setShowRegistrationForm(false)
        }}
      />
    </div>
  )
}
