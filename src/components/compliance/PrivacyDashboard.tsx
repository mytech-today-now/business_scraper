/**
 * Privacy Dashboard Component
 * Provides user-facing compliance dashboards for GDPR, CCPA, and data management
 */

'use client'

import React, { useState, useEffect } from 'react'
import {
  Shield,
  Download,
  Trash2,
  Edit,
  Eye,
  Settings,
  AlertTriangle,
  CheckCircle,
  Clock,
  FileText,
  Mail,
  Phone,
  MapPin,
  Calendar,
  ExternalLink
} from 'lucide-react'
import { logger } from '@/utils/logger'

// Data categories
interface DataCategory {
  id: string
  name: string
  description: string
  dataCount: number
  lastUpdated: Date
  retentionPeriod?: number
  canDelete: boolean
  canExport: boolean
  canModify: boolean
}

// Privacy rights
interface PrivacyRight {
  id: string
  name: string
  description: string
  available: boolean
  lastUsed?: Date
  status?: 'available' | 'pending' | 'completed' | 'unavailable'
}

// DSAR request
interface DSARRequest {
  id: string
  type: 'access' | 'rectification' | 'erasure' | 'portability'
  status: 'pending' | 'in_progress' | 'completed' | 'rejected'
  submittedAt: Date
  completedAt?: Date
  description: string
}

// Privacy settings
interface PrivacySettings {
  consentPreferences: Record<string, boolean>
  ccpaOptOut: boolean
  marketingOptOut: boolean
  dataRetentionPreference: 'minimum' | 'standard' | 'extended'
  notificationPreferences: {
    email: boolean
    sms: boolean
    dataUpdates: boolean
    securityAlerts: boolean
  }
}

interface PrivacyDashboardProps {
  userEmail?: string
  sessionId?: string
}

export default function PrivacyDashboard({ userEmail, sessionId }: PrivacyDashboardProps) {
  const [activeTab, setActiveTab] = useState<'overview' | 'data' | 'rights' | 'settings' | 'requests'>('overview')
  const [loading, setLoading] = useState(true)
  const [dataCategories, setDataCategories] = useState<DataCategory[]>([])
  const [privacyRights, setPrivacyRights] = useState<PrivacyRight[]>([])
  const [dsarRequests, setDSARRequests] = useState<DSARRequest[]>([])
  const [privacySettings, setPrivacySettings] = useState<PrivacySettings | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Load privacy dashboard data
  useEffect(() => {
    loadDashboardData()
  }, [userEmail, sessionId])

  const loadDashboardData = async () => {
    try {
      setLoading(true)
      setError(null)

      const params = new URLSearchParams()
      if (userEmail) params.append('email', userEmail)
      if (sessionId) params.append('sessionId', sessionId)

      const response = await fetch(`/api/compliance/privacy-dashboard?${params}`)
      
      if (!response.ok) {
        throw new Error('Failed to load privacy data')
      }

      const data = await response.json()

      setDataCategories(data.dataCategories || [])
      setPrivacyRights(data.privacyRights || [])
      setDSARRequests(data.dsarRequests || [])
      setPrivacySettings(data.privacySettings || null)

    } catch (error) {
      logger.error('Privacy Dashboard', 'Failed to load dashboard data', error)
      setError('Failed to load privacy data. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  // Submit DSAR request
  const submitDSARRequest = async (type: string, description: string) => {
    try {
      const response = await fetch('/api/compliance/dsar', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          requestType: type,
          subjectEmail: userEmail,
          description,
          verificationMethod: 'email',
          verificationData: { email: userEmail }
        })
      })

      if (response.ok) {
        await loadDashboardData() // Refresh data
        alert('Your request has been submitted successfully.')
      } else {
        throw new Error('Failed to submit request')
      }
    } catch (error) {
      logger.error('Privacy Dashboard', 'Failed to submit DSAR request', error)
      alert('Failed to submit request. Please try again.')
    }
  }

  // Update privacy settings
  const updatePrivacySettings = async (newSettings: Partial<PrivacySettings>) => {
    try {
      const response = await fetch('/api/compliance/privacy-settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userEmail,
          sessionId,
          settings: newSettings
        })
      })

      if (response.ok) {
        setPrivacySettings(prev => prev ? { ...prev, ...newSettings } : null)
        alert('Privacy settings updated successfully.')
      } else {
        throw new Error('Failed to update settings')
      }
    } catch (error) {
      logger.error('Privacy Dashboard', 'Failed to update privacy settings', error)
      alert('Failed to update settings. Please try again.')
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <span className="ml-2">Loading privacy dashboard...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-8 text-center">
        <AlertTriangle className="h-12 w-12 text-red-500 mx-auto mb-4" />
        <p className="text-red-600 mb-4">{error}</p>
        <button
          onClick={loadDashboardData}
          className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
        >
          Try Again
        </button>
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <Shield className="h-8 w-8 text-blue-600" />
          <h1 className="text-3xl font-bold">Privacy Dashboard</h1>
        </div>
        <p className="text-gray-600">
          Manage your data, privacy settings, and exercise your rights under GDPR and CCPA.
        </p>
      </div>

      {/* Navigation Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="flex space-x-8">
          {[
            { id: 'overview', label: 'Overview', icon: Eye },
            { id: 'data', label: 'My Data', icon: FileText },
            { id: 'rights', label: 'Privacy Rights', icon: Shield },
            { id: 'settings', label: 'Settings', icon: Settings },
            { id: 'requests', label: 'Requests', icon: Clock }
          ].map(tab => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <Icon className="h-4 w-4" />
                {tab.label}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Privacy Score */}
          <div className="bg-gradient-to-r from-blue-50 to-green-50 p-6 rounded-lg">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">Privacy Score</h3>
                <p className="text-gray-600">Your current privacy protection level</p>
              </div>
              <div className="text-right">
                <div className="text-3xl font-bold text-green-600">85%</div>
                <div className="text-sm text-gray-500">Good Protection</div>
              </div>
            </div>
          </div>

          {/* Quick Stats */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white p-6 rounded-lg border">
              <div className="flex items-center gap-3">
                <FileText className="h-8 w-8 text-blue-600" />
                <div>
                  <div className="text-2xl font-bold">{dataCategories.length}</div>
                  <div className="text-sm text-gray-600">Data Categories</div>
                </div>
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg border">
              <div className="flex items-center gap-3">
                <CheckCircle className="h-8 w-8 text-green-600" />
                <div>
                  <div className="text-2xl font-bold">
                    {privacyRights.filter(r => r.available).length}
                  </div>
                  <div className="text-sm text-gray-600">Available Rights</div>
                </div>
              </div>
            </div>
            
            <div className="bg-white p-6 rounded-lg border">
              <div className="flex items-center gap-3">
                <Clock className="h-8 w-8 text-orange-600" />
                <div>
                  <div className="text-2xl font-bold">
                    {dsarRequests.filter(r => r.status === 'pending').length}
                  </div>
                  <div className="text-sm text-gray-600">Pending Requests</div>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Activity */}
          <div className="bg-white p-6 rounded-lg border">
            <h3 className="text-lg font-semibold mb-4">Recent Privacy Activity</h3>
            <div className="space-y-3">
              {dsarRequests.slice(0, 3).map(request => (
                <div key={request.id} className="flex items-center justify-between py-2">
                  <div className="flex items-center gap-3">
                    <div className={`w-2 h-2 rounded-full ${
                      request.status === 'completed' ? 'bg-green-500' :
                      request.status === 'pending' ? 'bg-yellow-500' : 'bg-blue-500'
                    }`} />
                    <span className="text-sm">{request.description}</span>
                  </div>
                  <span className="text-xs text-gray-500">
                    {new Date(request.submittedAt).toLocaleDateString()}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'data' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Your Data Categories</h3>
            <button
              onClick={() => submitDSARRequest('access', 'Request access to all my data')}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              <Download className="h-4 w-4" />
              Export All Data
            </button>
          </div>

          <div className="grid gap-4">
            {dataCategories.map(category => (
              <div key={category.id} className="bg-white p-6 rounded-lg border">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h4 className="font-semibold">{category.name}</h4>
                    <p className="text-sm text-gray-600">{category.description}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-lg font-semibold">{category.dataCount}</div>
                    <div className="text-xs text-gray-500">records</div>
                  </div>
                </div>

                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-500">
                    Last updated: {new Date(category.lastUpdated).toLocaleDateString()}
                  </span>
                  <div className="flex gap-2">
                    {category.canExport && (
                      <button className="flex items-center gap-1 px-3 py-1 text-blue-600 hover:bg-blue-50 rounded">
                        <Download className="h-3 w-3" />
                        Export
                      </button>
                    )}
                    {category.canModify && (
                      <button className="flex items-center gap-1 px-3 py-1 text-green-600 hover:bg-green-50 rounded">
                        <Edit className="h-3 w-3" />
                        Modify
                      </button>
                    )}
                    {category.canDelete && (
                      <button className="flex items-center gap-1 px-3 py-1 text-red-600 hover:bg-red-50 rounded">
                        <Trash2 className="h-3 w-3" />
                        Delete
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'rights' && (
        <div className="space-y-6">
          <h3 className="text-lg font-semibold">Your Privacy Rights</h3>
          
          <div className="grid gap-4">
            {privacyRights.map(right => (
              <div key={right.id} className="bg-white p-6 rounded-lg border">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h4 className="font-semibold">{right.name}</h4>
                      <span className={`px-2 py-1 text-xs rounded-full ${
                        right.status === 'available' ? 'bg-green-100 text-green-800' :
                        right.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                        right.status === 'completed' ? 'bg-blue-100 text-blue-800' :
                        'bg-gray-100 text-gray-800'
                      }`}>
                        {right.status || 'available'}
                      </span>
                    </div>
                    <p className="text-sm text-gray-600 mb-2">{right.description}</p>
                    {right.lastUsed && (
                      <p className="text-xs text-gray-500">
                        Last used: {new Date(right.lastUsed).toLocaleDateString()}
                      </p>
                    )}
                  </div>
                  
                  {right.available && right.status === 'available' && (
                    <button
                      onClick={() => {
                        const description = prompt(`Describe your ${right.name.toLowerCase()} request:`)
                        if (description) {
                          submitDSARRequest(right.id, description)
                        }
                      }}
                      className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                    >
                      Exercise Right
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'settings' && privacySettings && (
        <div className="space-y-6">
          <h3 className="text-lg font-semibold">Privacy Settings</h3>
          
          {/* Consent Preferences */}
          <div className="bg-white p-6 rounded-lg border">
            <h4 className="font-semibold mb-4">Consent Preferences</h4>
            <div className="space-y-3">
              {Object.entries(privacySettings.consentPreferences).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between">
                  <span className="capitalize">{key.replace('_', ' ')}</span>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={value}
                      onChange={(e) => updatePrivacySettings({
                        consentPreferences: {
                          ...privacySettings.consentPreferences,
                          [key]: e.target.checked
                        }
                      })}
                      className="sr-only peer"
                    />
                    <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                  </label>
                </div>
              ))}
            </div>
          </div>

          {/* CCPA Settings */}
          <div className="bg-white p-6 rounded-lg border">
            <h4 className="font-semibold mb-4">California Privacy Rights (CCPA)</h4>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-medium">Do Not Sell My Information</span>
                  <p className="text-sm text-gray-600">Opt out of the sale of your personal information</p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={privacySettings.ccpaOptOut}
                    onChange={(e) => updatePrivacySettings({ ccpaOptOut: e.target.checked })}
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                </label>
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'requests' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Privacy Requests</h3>
            <button
              onClick={() => {
                const type = prompt('Request type (access, rectification, erasure, portability):')
                const description = prompt('Describe your request:')
                if (type && description) {
                  submitDSARRequest(type, description)
                }
              }}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              New Request
            </button>
          </div>

          <div className="space-y-4">
            {dsarRequests.map(request => (
              <div key={request.id} className="bg-white p-6 rounded-lg border">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h4 className="font-semibold capitalize">{request.type} Request</h4>
                    <p className="text-sm text-gray-600">{request.description}</p>
                  </div>
                  <span className={`px-3 py-1 text-sm rounded-full ${
                    request.status === 'completed' ? 'bg-green-100 text-green-800' :
                    request.status === 'pending' ? 'bg-yellow-100 text-yellow-800' :
                    request.status === 'in_progress' ? 'bg-blue-100 text-blue-800' :
                    'bg-red-100 text-red-800'
                  }`}>
                    {request.status.replace('_', ' ')}
                  </span>
                </div>
                
                <div className="flex items-center justify-between text-sm text-gray-500">
                  <span>Submitted: {new Date(request.submittedAt).toLocaleDateString()}</span>
                  {request.completedAt && (
                    <span>Completed: {new Date(request.completedAt).toLocaleDateString()}</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
