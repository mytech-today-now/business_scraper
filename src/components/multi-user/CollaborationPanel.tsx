/**
 * Collaboration Panel Component
 * Provides real-time collaboration features with live user presence and notifications
 */

'use client'

import React, { useState, useEffect, useRef } from 'react'
import { User, CollaborationEvent, RealtimeUpdate, NotificationMessage } from '@/types/multi-user'

interface CollaborationPanelProps {
  currentUser: User
  workspaceId: string
  onCollaborationEvent?: (event: CollaborationEvent) => void
}

interface ActiveUser {
  id: string
  username: string
  firstName: string
  lastName: string
  lastSeen: Date
  isOnline: boolean
}

export const CollaborationPanel: React.FC<CollaborationPanelProps> = ({
  currentUser,
  workspaceId,
  onCollaborationEvent,
}) => {
  const [activeUsers, setActiveUsers] = useState<ActiveUser[]>([])
  const [notifications, setNotifications] = useState<NotificationMessage[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [recentActivity, setRecentActivity] = useState<CollaborationEvent[]>([])
  const [showNotifications, setShowNotifications] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    connectWebSocket()
    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [workspaceId])

  const connectWebSocket = () => {
    try {
      const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/collaboration`
      const sessionId = document.cookie
        .split('; ')
        .find(row => row.startsWith('session-id='))
        ?.split('=')[1]

      if (!sessionId) {
        console.error('No session ID found for WebSocket connection')
        return
      }

      wsRef.current = new WebSocket(`${wsUrl}?sessionId=${sessionId}`)

      wsRef.current.onopen = () => {
        setIsConnected(true)
        console.log('WebSocket connected')

        // Send heartbeat with workspace context
        sendHeartbeat()
      }

      wsRef.current.onmessage = event => {
        try {
          const message = JSON.parse(event.data)
          handleWebSocketMessage(message)
        } catch (error) {
          console.error('Error parsing WebSocket message:', error)
        }
      }

      wsRef.current.onclose = () => {
        setIsConnected(false)
        console.log('WebSocket disconnected')

        // Attempt to reconnect after 3 seconds
        setTimeout(() => {
          if (wsRef.current?.readyState === WebSocket.CLOSED) {
            connectWebSocket()
          }
        }, 3000)
      }

      wsRef.current.onerror = error => {
        console.error('WebSocket error:', error)
        setIsConnected(false)
      }
    } catch (error) {
      console.error('Error connecting to WebSocket:', error)
    }
  }

  const sendHeartbeat = () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: 'heartbeat',
          payload: {
            userId: currentUser.id,
            workspaceId,
            timestamp: new Date(),
          },
          timestamp: new Date(),
          userId: currentUser.id,
          workspaceId,
        })
      )
    }
  }

  const handleWebSocketMessage = (message: any) => {
    switch (message.type) {
      case 'heartbeat':
        // Handle heartbeat response
        break

      case 'collaboration_event':
        const event = message.payload as CollaborationEvent
        handleCollaborationEvent(event)
        break

      case 'realtime_update':
        const update = message.payload as RealtimeUpdate
        handleRealtimeUpdate(update)
        break

      case 'notification':
        const notification = message.payload as NotificationMessage
        handleNotification(notification)
        break

      default:
        console.log('Unknown WebSocket message type:', message.type)
    }
  }

  const handleCollaborationEvent = (event: CollaborationEvent) => {
    // Update recent activity
    setRecentActivity(prev => [event, ...prev.slice(0, 9)])

    // Handle specific event types
    switch (event.type) {
      case 'user_joined':
        setActiveUsers(prev => {
          const existing = prev.find(u => u.id === event.userId)
          if (existing) {
            return prev.map(u =>
              u.id === event.userId ? { ...u, isOnline: true, lastSeen: new Date() } : u
            )
          } else {
            return [
              ...prev,
              {
                id: event.userId!,
                username: event.username!,
                firstName: event.username!.split(' ')[0] || '',
                lastName: event.username!.split(' ')[1] || '',
                lastSeen: new Date(),
                isOnline: true,
              },
            ]
          }
        })
        break

      case 'user_left':
        setActiveUsers(prev =>
          prev.map(u =>
            u.id === event.userId ? { ...u, isOnline: false, lastSeen: new Date() } : u
          )
        )
        break

      case 'resource_locked':
      case 'resource_unlocked':
      case 'data_updated':
        // These events are handled by the parent component
        onCollaborationEvent?.(event)
        break
    }
  }

  const handleRealtimeUpdate = (update: RealtimeUpdate) => {
    // Handle real-time data updates
    console.log('Real-time update received:', update)
  }

  const handleNotification = (notification: NotificationMessage) => {
    setNotifications(prev => [notification, ...prev.slice(0, 19)])

    // Show browser notification if permission granted
    if (Notification.permission === 'granted') {
      new Notification(notification.title, {
        body: notification.message,
        icon: '/favicon.ico',
      })
    }
  }

  const sendCollaborationEvent = (event: Omit<CollaborationEvent, 'userId' | 'timestamp'>) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(
        JSON.stringify({
          type: 'collaboration_event',
          payload: {
            ...event,
            userId: currentUser.id,
            timestamp: new Date(),
          },
          timestamp: new Date(),
          userId: currentUser.id,
          workspaceId,
        })
      )
    }
  }

  const markNotificationAsRead = (notificationId: string) => {
    setNotifications(prev => prev.map(n => (n.id === notificationId ? { ...n, isRead: true } : n)))
  }

  const clearAllNotifications = () => {
    setNotifications([])
  }

  const requestNotificationPermission = async () => {
    if ('Notification' in window && Notification.permission === 'default') {
      await Notification.requestPermission()
    }
  }

  useEffect(() => {
    requestNotificationPermission()
  }, [])

  // Send heartbeat every 30 seconds
  useEffect(() => {
    const interval = setInterval(sendHeartbeat, 30000)
    return () => clearInterval(interval)
  }, [workspaceId])

  const unreadNotifications = notifications.filter(n => !n.isRead).length

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-gray-900">Collaboration</h3>
        <div className="flex items-center space-x-2">
          <div className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-sm text-gray-500">
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>
      </div>

      {/* Active Users */}
      <div>
        <h4 className="text-sm font-medium text-gray-700 mb-2">
          Active Users ({activeUsers.filter(u => u.isOnline).length})
        </h4>
        <div className="space-y-2">
          {activeUsers.filter(u => u.isOnline).length === 0 ? (
            <p className="text-sm text-gray-500">No other users online</p>
          ) : (
            activeUsers
              .filter(u => u.isOnline && u.id !== currentUser.id)
              .map(user => (
                <div key={user.id} className="flex items-center space-x-2">
                  <div className="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center">
                    <span className="text-xs font-medium text-green-800">
                      {user.firstName[0]}
                      {user.lastName[0]}
                    </span>
                  </div>
                  <span className="text-sm text-gray-700">{user.username}</span>
                  <div className="w-2 h-2 bg-green-500 rounded-full" />
                </div>
              ))
          )}
        </div>
      </div>

      {/* Notifications */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-sm font-medium text-gray-700">
            Notifications
            {unreadNotifications > 0 && (
              <span className="ml-1 bg-red-500 text-white text-xs rounded-full px-2 py-0.5">
                {unreadNotifications}
              </span>
            )}
          </h4>
          <div className="flex space-x-1">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="text-xs text-blue-600 hover:text-blue-800"
            >
              {showNotifications ? 'Hide' : 'Show'}
            </button>
            {notifications.length > 0 && (
              <button
                onClick={clearAllNotifications}
                className="text-xs text-gray-500 hover:text-gray-700"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {showNotifications && (
          <div className="space-y-2 max-h-40 overflow-y-auto">
            {notifications.length === 0 ? (
              <p className="text-sm text-gray-500">No notifications</p>
            ) : (
              notifications.slice(0, 5).map(notification => (
                <div
                  key={notification.id}
                  className={`p-2 rounded text-xs border-l-4 ${
                    notification.type === 'error'
                      ? 'bg-red-50 border-red-400 text-red-700'
                      : notification.type === 'warning'
                        ? 'bg-yellow-50 border-yellow-400 text-yellow-700'
                        : notification.type === 'success'
                          ? 'bg-green-50 border-green-400 text-green-700'
                          : 'bg-blue-50 border-blue-400 text-blue-700'
                  } ${!notification.isRead ? 'font-medium' : ''}`}
                  onClick={() => markNotificationAsRead(notification.id)}
                >
                  <div className="font-medium">{notification.title}</div>
                  <div className="mt-1">{notification.message}</div>
                  <div className="mt-1 text-xs opacity-75">
                    {new Date(notification.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Recent Activity */}
      <div>
        <h4 className="text-sm font-medium text-gray-700 mb-2">Recent Activity</h4>
        <div className="space-y-1 max-h-32 overflow-y-auto">
          {recentActivity.length === 0 ? (
            <p className="text-sm text-gray-500">No recent activity</p>
          ) : (
            recentActivity.map((activity, index) => (
              <div key={index} className="text-xs text-gray-600">
                <span className="font-medium">{activity.username}</span>
                <span className="ml-1">
                  {activity.type === 'user_joined' && 'joined the workspace'}
                  {activity.type === 'user_left' && 'left the workspace'}
                  {activity.type === 'resource_locked' && `locked ${activity.resourceType}`}
                  {activity.type === 'resource_unlocked' && `unlocked ${activity.resourceType}`}
                  {activity.type === 'data_updated' && `updated ${activity.resourceType}`}
                </span>
                <span className="ml-1 text-gray-400">
                  {new Date(activity.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="pt-2 border-t border-gray-200">
        <div className="flex space-x-2">
          <button
            onClick={() =>
              sendCollaborationEvent({
                type: 'data_updated',
                workspaceId,
                resourceType: 'workspace',
                resourceId: workspaceId,
                data: { action: 'refresh_requested' },
              })
            }
            className="flex-1 bg-gray-100 text-gray-700 px-2 py-1 rounded text-xs hover:bg-gray-200 transition-colors"
          >
            Refresh Data
          </button>
          <button
            onClick={() => {
              if (Notification.permission === 'default') {
                requestNotificationPermission()
              }
            }}
            className="flex-1 bg-blue-100 text-blue-700 px-2 py-1 rounded text-xs hover:bg-blue-200 transition-colors"
          >
            Enable Notifications
          </button>
        </div>
      </div>
    </div>
  )
}
