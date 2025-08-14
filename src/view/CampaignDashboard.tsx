/**
 * Campaign Management Dashboard
 * Comprehensive interface for creating, managing, and monitoring campaigns
 */

'use client'

import React, { useState, useEffect } from 'react'
import {
  Plus,
  Play,
  Pause,
  Copy,
  Edit,
  Trash2,
  Calendar,
  Target,
  TrendingUp,
  Users,
  MapPin,
  Search,
  MoreVertical,
  Download,
  Share2
} from 'lucide-react'
import { Card } from '@/view/components/ui/Card'
import { Button } from '@/view/components/ui/Button'
import { Input } from '@/view/components/ui/Input'
import { logger } from '@/utils/logger'

export interface Campaign {
  id: string
  name: string
  description: string
  industry: string
  location: string
  status: 'draft' | 'active' | 'paused' | 'completed' | 'failed'
  progress: {
    current: number
    total: number
    percentage: number
  }
  results: {
    businesses: number
    contacts: number
    quality: number
  }
  schedule?: {
    startDate: Date
    endDate?: Date
    recurring?: boolean
    frequency?: 'daily' | 'weekly' | 'monthly'
  }
  settings: {
    searchRadius: number
    searchDepth: number
    pagesPerSite: number
    zipCode: string
  }
  createdAt: Date
  updatedAt: Date
  createdBy: string
  tags: string[]
  template?: string
}

export interface CampaignTemplate {
  id: string
  name: string
  description: string
  industry: string
  settings: Campaign['settings']
  isDefault: boolean
}

export function CampaignDashboard() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([])
  const [templates, setTemplates] = useState<CampaignTemplate[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [selectedCampaigns, setSelectedCampaigns] = useState<Set<string>>(new Set())
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [showCreateWizard, setShowCreateWizard] = useState(false)

  // Load campaigns and templates
  useEffect(() => {
    loadCampaigns()
    loadTemplates()
  }, [])

  const loadCampaigns = async () => {
    setIsLoading(true)
    try {
      // This would fetch from your API
      const mockCampaigns: Campaign[] = [
        {
          id: '1',
          name: 'Restaurant Leads - NYC',
          description: 'Target restaurants in New York City area',
          industry: 'Restaurant',
          location: 'New York, NY',
          status: 'active',
          progress: { current: 150, total: 500, percentage: 30 },
          results: { businesses: 120, contacts: 95, quality: 0.85 },
          settings: { searchRadius: 25, searchDepth: 3, pagesPerSite: 5, zipCode: '10001' },
          createdAt: new Date('2024-01-15'),
          updatedAt: new Date('2024-01-20'),
          createdBy: 'user@example.com',
          tags: ['restaurants', 'nyc', 'high-priority'],
        },
        {
          id: '2',
          name: 'Healthcare Providers - LA',
          description: 'Medical practices and clinics in Los Angeles',
          industry: 'Healthcare',
          location: 'Los Angeles, CA',
          status: 'completed',
          progress: { current: 300, total: 300, percentage: 100 },
          results: { businesses: 285, contacts: 240, quality: 0.92 },
          settings: { searchRadius: 30, searchDepth: 4, pagesPerSite: 8, zipCode: '90210' },
          createdAt: new Date('2024-01-10'),
          updatedAt: new Date('2024-01-18'),
          createdBy: 'user@example.com',
          tags: ['healthcare', 'la', 'completed'],
        },
      ]
      setCampaigns(mockCampaigns)
    } catch (error) {
      logger.error('CampaignDashboard', 'Failed to load campaigns', error)
    } finally {
      setIsLoading(false)
    }
  }

  const loadTemplates = async () => {
    try {
      const mockTemplates: CampaignTemplate[] = [
        {
          id: '1',
          name: 'Restaurant Template',
          description: 'Optimized for restaurant and food service businesses',
          industry: 'Restaurant',
          settings: { searchRadius: 25, searchDepth: 3, pagesPerSite: 5, zipCode: '' },
          isDefault: true,
        },
        {
          id: '2',
          name: 'Healthcare Template',
          description: 'Designed for medical practices and healthcare providers',
          industry: 'Healthcare',
          settings: { searchRadius: 30, searchDepth: 4, pagesPerSite: 8, zipCode: '' },
          isDefault: true,
        },
      ]
      setTemplates(mockTemplates)
    } catch (error) {
      logger.error('CampaignDashboard', 'Failed to load templates', error)
    }
  }

  const handleCampaignAction = async (campaignId: string, action: string) => {
    try {
      switch (action) {
        case 'start':
          logger.info('CampaignDashboard', `Starting campaign ${campaignId}`)
          // API call to start campaign
          break
        case 'pause':
          logger.info('CampaignDashboard', `Pausing campaign ${campaignId}`)
          // API call to pause campaign
          break
        case 'stop':
          logger.info('CampaignDashboard', `Stopping campaign ${campaignId}`)
          // API call to stop campaign
          break
        case 'clone':
          logger.info('CampaignDashboard', `Cloning campaign ${campaignId}`)
          // API call to clone campaign
          break
        case 'delete':
          logger.info('CampaignDashboard', `Deleting campaign ${campaignId}`)
          // API call to delete campaign
          break
      }
      await loadCampaigns() // Refresh data
    } catch (error) {
      logger.error('CampaignDashboard', `Failed to ${action} campaign`, error)
    }
  }

  const filteredCampaigns = campaigns.filter(campaign => {
    const matchesStatus = filterStatus === 'all' || campaign.status === filterStatus
    const matchesSearch = campaign.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         campaign.industry.toLowerCase().includes(searchQuery.toLowerCase()) ||
                         campaign.location.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesStatus && matchesSearch
  })

  const getStatusColor = (status: Campaign['status']) => {
    switch (status) {
      case 'active': return 'text-green-600 bg-green-100'
      case 'paused': return 'text-yellow-600 bg-yellow-100'
      case 'completed': return 'text-blue-600 bg-blue-100'
      case 'failed': return 'text-red-600 bg-red-100'
      default: return 'text-gray-600 bg-gray-100'
    }
  }

  const formatDate = (date: Date) => {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    }).format(date)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Campaign Management</h1>
          <p className="text-gray-600 mt-1">Create, manage, and monitor your scraping campaigns</p>
        </div>
        <div className="flex items-center space-x-3">
          <Button
            onClick={() => setShowCreateWizard(true)}
            icon={Plus}
          >
            New Campaign
          </Button>
          <Button variant="outline" icon={Download}>
            Export
          </Button>
        </div>
      </div>

      {/* Stats Overview */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-500">Total Campaigns</p>
              <p className="text-2xl font-bold">{campaigns.length}</p>
            </div>
            <Target className="h-8 w-8 text-blue-500" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-500">Active Campaigns</p>
              <p className="text-2xl font-bold text-green-600">
                {campaigns.filter(c => c.status === 'active').length}
              </p>
            </div>
            <Play className="h-8 w-8 text-green-500" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-500">Total Businesses</p>
              <p className="text-2xl font-bold">
                {campaigns.reduce((sum, c) => sum + c.results.businesses, 0)}
              </p>
            </div>
            <Users className="h-8 w-8 text-purple-500" />
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-500">Avg Quality Score</p>
              <p className="text-2xl font-bold text-orange-600">
                {(campaigns.reduce((sum, c) => sum + c.results.quality, 0) / campaigns.length * 100).toFixed(0)}%
              </p>
            </div>
            <TrendingUp className="h-8 w-8 text-orange-500" />
          </div>
        </Card>
      </div>

      {/* Filters and Search */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search campaigns..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10 w-64"
            />
          </div>
          
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-md text-sm"
          >
            <option value="all">All Status</option>
            <option value="draft">Draft</option>
            <option value="active">Active</option>
            <option value="paused">Paused</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
        </div>

        <div className="flex items-center space-x-2">
          <Button
            variant={viewMode === 'grid' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setViewMode('grid')}
          >
            Grid
          </Button>
          <Button
            variant={viewMode === 'list' ? 'default' : 'outline'}
            size="sm"
            onClick={() => setViewMode('list')}
          >
            List
          </Button>
        </div>
      </div>

      {/* Campaigns Grid/List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-center space-y-4">
            <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent mx-auto" />
            <p className="text-gray-500">Loading campaigns...</p>
          </div>
        </div>
      ) : filteredCampaigns.length === 0 ? (
        <Card className="p-12 text-center">
          <Target className="h-12 w-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-gray-900 mb-2">No campaigns found</h3>
          <p className="text-gray-500 mb-6">
            {searchQuery || filterStatus !== 'all' 
              ? 'Try adjusting your search or filters'
              : 'Get started by creating your first campaign'
            }
          </p>
          <Button onClick={() => setShowCreateWizard(true)} icon={Plus}>
            Create Campaign
          </Button>
        </Card>
      ) : (
        <div className={viewMode === 'grid' ? 'grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6' : 'space-y-4'}>
          {filteredCampaigns.map(campaign => (
            <CampaignCard
              key={campaign.id}
              campaign={campaign}
              viewMode={viewMode}
              onAction={handleCampaignAction}
            />
          ))}
        </div>
      )}

      {/* Create Campaign Wizard Modal */}
      {showCreateWizard && (
        <CampaignWizard
          templates={templates}
          onClose={() => setShowCreateWizard(false)}
          onSuccess={() => {
            setShowCreateWizard(false)
            loadCampaigns()
          }}
        />
      )}
    </div>
  )
}

interface CampaignCardProps {
  campaign: Campaign
  viewMode: 'grid' | 'list'
  onAction: (campaignId: string, action: string) => void
}

function CampaignCard({ campaign, viewMode, onAction }: CampaignCardProps) {
  const [showActions, setShowActions] = useState(false)

  if (viewMode === 'list') {
    return (
      <Card className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex-1">
              <div className="flex items-center space-x-3">
                <h3 className="font-semibold">{campaign.name}</h3>
                <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(campaign.status)}`}>
                  {campaign.status}
                </span>
              </div>
              <p className="text-sm text-gray-500 mt-1">{campaign.description}</p>
              <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                <span className="flex items-center">
                  <MapPin className="h-3 w-3 mr-1" />
                  {campaign.location}
                </span>
                <span>{campaign.industry}</span>
                <span>{campaign.updatedAt.toLocaleDateString()}</span>
              </div>
            </div>
          </div>
          
          <div className="flex items-center space-x-4">
            <div className="text-right">
              <p className="text-sm font-medium">{campaign.results.businesses} businesses</p>
              <p className="text-xs text-gray-500">{(campaign.results.quality * 100).toFixed(0)}% quality</p>
            </div>
            
            <div className="w-24">
              <div className="flex justify-between text-xs text-gray-500 mb-1">
                <span>{campaign.progress.percentage}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full"
                  style={{ width: `${campaign.progress.percentage}%` }}
                />
              </div>
            </div>

            <CampaignActions campaign={campaign} onAction={onAction} />
          </div>
        </div>
      </Card>
    )
  }

  return (
    <Card className="p-6">
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <div className="flex items-center space-x-2 mb-2">
            <h3 className="font-semibold text-lg">{campaign.name}</h3>
            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(campaign.status)}`}>
              {campaign.status}
            </span>
          </div>
          <p className="text-gray-600 text-sm mb-3">{campaign.description}</p>
          
          <div className="space-y-2 text-sm text-gray-500">
            <div className="flex items-center">
              <MapPin className="h-4 w-4 mr-2" />
              {campaign.location}
            </div>
            <div className="flex items-center">
              <Target className="h-4 w-4 mr-2" />
              {campaign.industry}
            </div>
            <div className="flex items-center">
              <Calendar className="h-4 w-4 mr-2" />
              {campaign.updatedAt.toLocaleDateString()}
            </div>
          </div>
        </div>

        <CampaignActions campaign={campaign} onAction={onAction} />
      </div>

      {/* Progress */}
      <div className="mb-4">
        <div className="flex justify-between text-sm text-gray-600 mb-2">
          <span>Progress</span>
          <span>{campaign.progress.current} / {campaign.progress.total}</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-2">
          <div
            className="bg-blue-600 h-2 rounded-full"
            style={{ width: `${campaign.progress.percentage}%` }}
          />
        </div>
      </div>

      {/* Results */}
      <div className="grid grid-cols-3 gap-4 text-center">
        <div>
          <p className="text-lg font-semibold">{campaign.results.businesses}</p>
          <p className="text-xs text-gray-500">Businesses</p>
        </div>
        <div>
          <p className="text-lg font-semibold">{campaign.results.contacts}</p>
          <p className="text-xs text-gray-500">Contacts</p>
        </div>
        <div>
          <p className="text-lg font-semibold">{(campaign.results.quality * 100).toFixed(0)}%</p>
          <p className="text-xs text-gray-500">Quality</p>
        </div>
      </div>
    </Card>
  )
}

interface CampaignActionsProps {
  campaign: Campaign
  onAction: (campaignId: string, action: string) => void
}

function CampaignActions({ campaign, onAction }: CampaignActionsProps) {
  const [showMenu, setShowMenu] = useState(false)

  return (
    <div className="relative">
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setShowMenu(!showMenu)}
      >
        <MoreVertical className="h-4 w-4" />
      </Button>

      {showMenu && (
        <div className="absolute right-0 top-8 w-48 bg-white border border-gray-200 rounded-md shadow-lg z-10">
          <div className="py-1">
            {campaign.status === 'draft' || campaign.status === 'paused' ? (
              <button
                onClick={() => {
                  onAction(campaign.id, 'start')
                  setShowMenu(false)
                }}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              >
                <Play className="h-4 w-4 mr-2" />
                Start Campaign
              </button>
            ) : null}
            
            {campaign.status === 'active' ? (
              <button
                onClick={() => {
                  onAction(campaign.id, 'pause')
                  setShowMenu(false)
                }}
                className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
              >
                <Pause className="h-4 w-4 mr-2" />
                Pause Campaign
              </button>
            ) : null}

            <button
              onClick={() => {
                onAction(campaign.id, 'clone')
                setShowMenu(false)
              }}
              className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
            >
              <Copy className="h-4 w-4 mr-2" />
              Clone Campaign
            </button>

            <button
              onClick={() => {
                onAction(campaign.id, 'edit')
                setShowMenu(false)
              }}
              className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
            >
              <Edit className="h-4 w-4 mr-2" />
              Edit Campaign
            </button>

            <button
              onClick={() => {
                onAction(campaign.id, 'share')
                setShowMenu(false)
              }}
              className="flex items-center w-full px-4 py-2 text-sm text-gray-700 hover:bg-gray-100"
            >
              <Share2 className="h-4 w-4 mr-2" />
              Share Campaign
            </button>

            <hr className="my-1" />

            <button
              onClick={() => {
                onAction(campaign.id, 'delete')
                setShowMenu(false)
              }}
              className="flex items-center w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50"
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete Campaign
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// Placeholder for Campaign Wizard component
function CampaignWizard({ templates, onClose, onSuccess }: {
  templates: CampaignTemplate[]
  onClose: () => void
  onSuccess: () => void
}) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 w-full max-w-2xl">
        <h2 className="text-xl font-semibold mb-4">Create New Campaign</h2>
        <p className="text-gray-600 mb-6">Campaign creation wizard will be implemented here.</p>
        <div className="flex justify-end space-x-3">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={onSuccess}>
            Create Campaign
          </Button>
        </div>
      </div>
    </div>
  )
}

function getStatusColor(status: Campaign['status']) {
  switch (status) {
    case 'active': return 'text-green-600 bg-green-100'
    case 'paused': return 'text-yellow-600 bg-yellow-100'
    case 'completed': return 'text-blue-600 bg-blue-100'
    case 'failed': return 'text-red-600 bg-red-100'
    default: return 'text-gray-600 bg-gray-100'
  }
}
