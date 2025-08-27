/**
 * Team Workspace Component
 * Provides team and workspace management interface with member management
 */

'use client'

import React, { useState, useEffect } from 'react'
import {
  Team,
  Workspace,
  User,
  CreateTeamRequest,
  CreateWorkspaceRequest,
} from '@/types/multi-user'

interface TeamWorkspaceProps {
  currentUser: User
  onTeamCreated?: (team: Team) => void
  onWorkspaceCreated?: (workspace: Workspace) => void
}

export const TeamWorkspace: React.FC<TeamWorkspaceProps> = ({
  currentUser,
  onTeamCreated,
  onWorkspaceCreated,
}) => {
  const [teams, setTeams] = useState<Team[]>([])
  const [workspaces, setWorkspaces] = useState<Workspace[]>([])
  const [selectedTeam, setSelectedTeam] = useState<Team | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'teams' | 'workspaces'>('teams')
  const [showCreateTeamForm, setShowCreateTeamForm] = useState(false)
  const [showCreateWorkspaceForm, setShowCreateWorkspaceForm] = useState(false)

  // Form state
  const [teamFormData, setTeamFormData] = useState<CreateTeamRequest>({
    name: '',
    description: '',
  })

  const [workspaceFormData, setWorkspaceFormData] = useState<CreateWorkspaceRequest>({
    name: '',
    description: '',
    teamId: '',
    defaultSearchRadius: 25,
    defaultSearchDepth: 3,
    defaultPagesPerSite: 5,
  })

  useEffect(() => {
    fetchTeams()
    fetchWorkspaces()
  }, [])

  const fetchTeams = async () => {
    try {
      setLoading(true)
      const response = await fetch('/api/teams')
      const data = await response.json()

      if (data.success) {
        setTeams(data.data)
      } else {
        setError(data.error || 'Failed to fetch teams')
      }
    } catch (err) {
      setError('Failed to fetch teams')
    } finally {
      setLoading(false)
    }
  }

  const fetchWorkspaces = async () => {
    try {
      const response = await fetch('/api/workspaces')
      const data = await response.json()

      if (data.success) {
        setWorkspaces(data.data)
      } else {
        setError(data.error || 'Failed to fetch workspaces')
      }
    } catch (err) {
      setError('Failed to fetch workspaces')
    }
  }

  const handleCreateTeam = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const response = await fetch('/api/teams', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(teamFormData),
      })

      const data = await response.json()

      if (data.success) {
        setTeams([data.data, ...teams])
        setShowCreateTeamForm(false)
        setTeamFormData({ name: '', description: '' })
        onTeamCreated?.(data.data)
      } else {
        setError(data.error || 'Failed to create team')
      }
    } catch (err) {
      setError('Failed to create team')
    }
  }

  const handleCreateWorkspace = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const response = await fetch('/api/workspaces', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(workspaceFormData),
      })

      const data = await response.json()

      if (data.success) {
        setWorkspaces([data.data, ...workspaces])
        setShowCreateWorkspaceForm(false)
        setWorkspaceFormData({
          name: '',
          description: '',
          teamId: '',
          defaultSearchRadius: 25,
          defaultSearchDepth: 3,
          defaultPagesPerSite: 5,
        })
        onWorkspaceCreated?.(data.data)
      } else {
        setError(data.error || 'Failed to create workspace')
      }
    } catch (err) {
      setError('Failed to create workspace')
    }
  }

  const handleInviteMember = async (teamId: string, email: string, role: string) => {
    try {
      const response = await fetch(`/api/teams/${teamId}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, role }),
      })

      const data = await response.json()

      if (data.success) {
        // Refresh team data
        fetchTeams()
      } else {
        setError(data.error || 'Failed to invite member')
      }
    } catch (err) {
      setError('Failed to invite member')
    }
  }

  const canCreateTeams = currentUser.roles?.some(role =>
    role.role.permissions.includes('teams.create')
  )

  const canCreateWorkspaces = currentUser.roles?.some(role =>
    role.role.permissions.includes('workspaces.create')
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Teams & Workspaces</h2>
          <p className="text-gray-600">Manage your collaborative environments</p>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <p className="text-red-600">{error}</p>
          <button onClick={() => setError(null)} className="text-red-800 hover:text-red-900 ml-2">
            ×
          </button>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex space-x-8">
          <button
            onClick={() => setActiveTab('teams')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'teams'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Teams ({teams.length})
          </button>
          <button
            onClick={() => setActiveTab('workspaces')}
            className={`py-2 px-1 border-b-2 font-medium text-sm ${
              activeTab === 'workspaces'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Workspaces ({workspaces.length})
          </button>
        </nav>
      </div>

      {/* Teams Tab */}
      {activeTab === 'teams' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Your Teams</h3>
            {canCreateTeams && (
              <button
                onClick={() => setShowCreateTeamForm(true)}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Create Team
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {loading ? (
              <div className="col-span-full text-center py-8 text-gray-500">Loading teams...</div>
            ) : teams.length === 0 ? (
              <div className="col-span-full text-center py-8 text-gray-500">
                No teams found. Create your first team to get started.
              </div>
            ) : (
              teams.map(team => (
                <div
                  key={team.id}
                  className="bg-white rounded-lg shadow p-6 hover:shadow-md transition-shadow"
                >
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-lg font-semibold text-gray-900">{team.name}</h4>
                    <span className="text-sm text-gray-500">{team.memberCount} members</span>
                  </div>

                  {team.description && (
                    <p className="text-gray-600 text-sm mb-4">{team.description}</p>
                  )}

                  <div className="flex items-center justify-between text-sm text-gray-500">
                    <span>{team.workspaceCount} workspaces</span>
                    <span>
                      Owner: {team.owner?.firstName} {team.owner?.lastName}
                    </span>
                  </div>

                  <div className="mt-4 flex space-x-2">
                    <button
                      onClick={() => setSelectedTeam(team)}
                      className="flex-1 bg-gray-100 text-gray-700 px-3 py-2 rounded text-sm hover:bg-gray-200 transition-colors"
                    >
                      View Details
                    </button>
                    {team.ownerId === currentUser.id && (
                      <button
                        onClick={() => {
                          /* Handle edit */
                        }}
                        className="bg-blue-100 text-blue-700 px-3 py-2 rounded text-sm hover:bg-blue-200 transition-colors"
                      >
                        Edit
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Workspaces Tab */}
      {activeTab === 'workspaces' && (
        <div className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Your Workspaces</h3>
            {canCreateWorkspaces && (
              <button
                onClick={() => setShowCreateWorkspaceForm(true)}
                className="bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
              >
                Create Workspace
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {loading ? (
              <div className="col-span-full text-center py-8 text-gray-500">
                Loading workspaces...
              </div>
            ) : workspaces.length === 0 ? (
              <div className="col-span-full text-center py-8 text-gray-500">
                No workspaces found. Create your first workspace to get started.
              </div>
            ) : (
              workspaces.map(workspace => (
                <div
                  key={workspace.id}
                  className="bg-white rounded-lg shadow p-6 hover:shadow-md transition-shadow"
                >
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="text-lg font-semibold text-gray-900">{workspace.name}</h4>
                    <span className="text-sm text-gray-500">{workspace.memberCount} members</span>
                  </div>

                  {workspace.description && (
                    <p className="text-gray-600 text-sm mb-4">{workspace.description}</p>
                  )}

                  <div className="space-y-2 text-sm text-gray-500">
                    <div className="flex justify-between">
                      <span>Team:</span>
                      <span>{workspace.team?.name}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Campaigns:</span>
                      <span>{workspace.campaignCount}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Businesses:</span>
                      <span>{workspace.businessCount}</span>
                    </div>
                  </div>

                  <div className="mt-4 flex space-x-2">
                    <button
                      onClick={() => {
                        /* Navigate to workspace */
                      }}
                      className="flex-1 bg-blue-600 text-white px-3 py-2 rounded text-sm hover:bg-blue-700 transition-colors"
                    >
                      Open
                    </button>
                    {workspace.ownerId === currentUser.id && (
                      <button
                        onClick={() => {
                          /* Handle edit */
                        }}
                        className="bg-gray-100 text-gray-700 px-3 py-2 rounded text-sm hover:bg-gray-200 transition-colors"
                      >
                        Settings
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Create Team Modal */}
      {showCreateTeamForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold mb-4">Create New Team</h3>
            <form onSubmit={handleCreateTeam} className="space-y-4">
              <input
                type="text"
                placeholder="Team Name"
                value={teamFormData.name}
                onChange={e => setTeamFormData({ ...teamFormData, name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                required
              />
              <textarea
                placeholder="Team Description (optional)"
                value={teamFormData.description}
                onChange={e => setTeamFormData({ ...teamFormData, description: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
              />
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateTeamForm(false)
                    setTeamFormData({ name: '', description: '' })
                  }}
                  className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Create Team
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Workspace Modal */}
      {showCreateWorkspaceForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 w-full max-w-md">
            <h3 className="text-lg font-semibold mb-4">Create New Workspace</h3>
            <form onSubmit={handleCreateWorkspace} className="space-y-4">
              <input
                type="text"
                placeholder="Workspace Name"
                value={workspaceFormData.name}
                onChange={e => setWorkspaceFormData({ ...workspaceFormData, name: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                required
              />
              <select
                value={workspaceFormData.teamId}
                onChange={e =>
                  setWorkspaceFormData({ ...workspaceFormData, teamId: e.target.value })
                }
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                required
              >
                <option value="">Select Team</option>
                {teams.map(team => (
                  <option key={team.id} value={team.id}>
                    {team.name}
                  </option>
                ))}
              </select>
              <textarea
                placeholder="Workspace Description (optional)"
                value={workspaceFormData.description}
                onChange={e =>
                  setWorkspaceFormData({ ...workspaceFormData, description: e.target.value })
                }
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                rows={3}
              />
              <div className="grid grid-cols-3 gap-2">
                <input
                  type="number"
                  placeholder="Search Radius"
                  value={workspaceFormData.defaultSearchRadius}
                  onChange={e =>
                    setWorkspaceFormData({
                      ...workspaceFormData,
                      defaultSearchRadius: parseInt(e.target.value),
                    })
                  }
                  className="px-3 py-2 border border-gray-300 rounded-lg"
                  min="1"
                  max="100"
                />
                <input
                  type="number"
                  placeholder="Search Depth"
                  value={workspaceFormData.defaultSearchDepth}
                  onChange={e =>
                    setWorkspaceFormData({
                      ...workspaceFormData,
                      defaultSearchDepth: parseInt(e.target.value),
                    })
                  }
                  className="px-3 py-2 border border-gray-300 rounded-lg"
                  min="1"
                  max="10"
                />
                <input
                  type="number"
                  placeholder="Pages/Site"
                  value={workspaceFormData.defaultPagesPerSite}
                  onChange={e =>
                    setWorkspaceFormData({
                      ...workspaceFormData,
                      defaultPagesPerSite: parseInt(e.target.value),
                    })
                  }
                  className="px-3 py-2 border border-gray-300 rounded-lg"
                  min="1"
                  max="20"
                />
              </div>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => {
                    setShowCreateWorkspaceForm(false)
                    setWorkspaceFormData({
                      name: '',
                      description: '',
                      teamId: '',
                      defaultSearchRadius: 25,
                      defaultSearchDepth: 3,
                      defaultPagesPerSite: 5,
                    })
                  }}
                  className="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Create Workspace
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
