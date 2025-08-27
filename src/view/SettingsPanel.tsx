/**
 * Settings and Preferences Panel
 * Comprehensive user preferences and application settings management
 */

'use client'

import React, { useState } from 'react'
import {
  Settings,
  User,
  Palette,
  Bell,
  Shield,
  Globe,
  Accessibility,
  Keyboard,
  Monitor,
  Save,
  RotateCcw,
  Download,
  Upload,
  Eye,
  EyeOff,
  Volume2,
  VolumeX,
  Smartphone,
  Mail,
  Clock,
  Calendar,
  Languages,
  Zap,
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from '@/view/components/ui/Card'
import { Button } from '@/view/components/ui/Button'
import { Input } from '@/view/components/ui/Input'
import { useUserExperience, UserPreferences } from './UserExperienceProvider'
import { logger } from '@/utils/logger'

export function SettingsPanel() {
  const { preferences, updatePreferences, showToast } = useUserExperience()
  const [activeSection, setActiveSection] = useState('general')
  const [hasUnsavedChanges, setHasUnsavedChanges] = useState(false)
  const [localPreferences, setLocalPreferences] = useState<UserPreferences>(preferences)

  const sections = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'performance', label: 'Performance', icon: Zap },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'accessibility', label: 'Accessibility', icon: Accessibility },
    { id: 'keyboard', label: 'Keyboard', icon: Keyboard },
    { id: 'privacy', label: 'Privacy & Security', icon: Shield },
    { id: 'advanced', label: 'Advanced', icon: Zap },
  ]

  const handlePreferenceChange = (path: string, value: any): void => {
    const keys = path.split('.')
    const newPreferences = { ...localPreferences }

    // Safe nested object property assignment
    let current: any = newPreferences
    for (let i = 0; i < keys.length - 1; i++) {
      const key = keys[i]
      if (key && typeof key === 'string' && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(key)) {
        if (
          current &&
          typeof current === 'object' &&
          Object.prototype.hasOwnProperty.call(current, key)
        ) {
          current = (current as Record<string, any>)[key]
        } else {
          // Create nested object if it doesn't exist
          Object.defineProperty(current, key, {
            value: {},
            writable: true,
            enumerable: true,
            configurable: true,
          })
          current = (current as Record<string, any>)[key]
        }
      } else {
        console.warn('Invalid preference key:', key)
        return
      }
    }

    const lastKey = keys[keys.length - 1]
    if (lastKey && typeof lastKey === 'string' && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(lastKey)) {
      Object.defineProperty(current, lastKey, {
        value,
        writable: true,
        enumerable: true,
        configurable: true,
      })
    } else {
      console.warn('Invalid preference key:', lastKey)
      return
    }

    setLocalPreferences(newPreferences)
    setHasUnsavedChanges(true)
  }

  const saveSettings = () => {
    updatePreferences(localPreferences)
    setHasUnsavedChanges(false)
    showToast('Settings saved successfully', 'success')
    logger.info('SettingsPanel', 'User preferences updated')
  }

  const resetSettings = () => {
    setLocalPreferences(preferences)
    setHasUnsavedChanges(false)
    showToast('Settings reset', 'info')
  }

  const exportSettings = () => {
    const dataStr = JSON.stringify(localPreferences, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)

    const link = document.createElement('a')
    link.href = url
    link.download = 'business-scraper-settings.json'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)

    showToast('Settings exported', 'success')
  }

  const importSettings = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = e => {
      try {
        const imported = JSON.parse(e.target?.result as string)
        setLocalPreferences(imported)
        setHasUnsavedChanges(true)
        showToast('Settings imported', 'success')
      } catch (error) {
        showToast('Failed to import settings', 'error')
        logger.error('SettingsPanel', 'Failed to import settings', error)
      }
    }
    reader.readAsText(file)
  }

  return (
    <div className="flex h-full">
      {/* Sidebar */}
      <div className="w-64 bg-gray-50 border-r">
        <div className="p-4">
          <h2 className="text-lg font-semibold mb-4">Settings</h2>
          <nav className="space-y-1">
            {sections.map(section => {
              const Icon = section.icon
              return (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={`w-full flex items-center px-3 py-2 text-left rounded-md transition-colors ${
                    activeSection === section.id
                      ? 'bg-blue-100 text-blue-700'
                      : 'text-gray-700 hover:bg-gray-100'
                  }`}
                >
                  <Icon className="h-4 w-4 mr-3" />
                  {section.label}
                </button>
              )
            })}
          </nav>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 p-6">
        <div className="max-w-2xl">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold">
                {sections.find(s => s.id === activeSection)?.label}
              </h1>
              <p className="text-gray-600 mt-1">Customize your application experience</p>
            </div>

            <div className="flex items-center space-x-3">
              {hasUnsavedChanges && (
                <Button variant="outline" onClick={resetSettings}>
                  <RotateCcw className="h-4 w-4 mr-2" />
                  Reset
                </Button>
              )}
              <Button onClick={saveSettings} disabled={!hasUnsavedChanges}>
                <Save className="h-4 w-4 mr-2" />
                Save Changes
              </Button>
            </div>
          </div>

          {/* Settings Content */}
          {activeSection === 'general' && (
            <GeneralSettings preferences={localPreferences} onChange={handlePreferenceChange} />
          )}

          {activeSection === 'appearance' && (
            <AppearanceSettings preferences={localPreferences} onChange={handlePreferenceChange} />
          )}

          {activeSection === 'performance' && (
            <PerformanceSettings preferences={localPreferences} onChange={handlePreferenceChange} />
          )}

          {activeSection === 'notifications' && (
            <NotificationSettings
              preferences={localPreferences}
              onChange={handlePreferenceChange}
            />
          )}

          {activeSection === 'accessibility' && (
            <AccessibilitySettings
              preferences={localPreferences}
              onChange={handlePreferenceChange}
            />
          )}

          {activeSection === 'keyboard' && (
            <KeyboardSettings preferences={localPreferences} onChange={handlePreferenceChange} />
          )}

          {activeSection === 'privacy' && (
            <PrivacySettings preferences={localPreferences} onChange={handlePreferenceChange} />
          )}

          {activeSection === 'advanced' && (
            <AdvancedSettings
              preferences={localPreferences}
              onChange={handlePreferenceChange}
              onExport={exportSettings}
              onImport={importSettings}
            />
          )}
        </div>
      </div>
    </div>
  )
}

function GeneralSettings({
  preferences,
  onChange,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Globe className="h-5 w-5 mr-2" />
            Language & Region
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Language</label>
            <select
              value={preferences.language}
              onChange={e => onChange('language', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            >
              <option value="en">English</option>
              <option value="es">Spanish</option>
              <option value="fr">French</option>
              <option value="de">German</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Timezone</label>
            <select
              value={preferences.timezone}
              onChange={e => onChange('timezone', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            >
              <option value="America/New_York">Eastern Time</option>
              <option value="America/Chicago">Central Time</option>
              <option value="America/Denver">Mountain Time</option>
              <option value="America/Los_Angeles">Pacific Time</option>
              <option value="UTC">UTC</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Date Format</label>
            <select
              value={preferences.dateFormat}
              onChange={e => onChange('dateFormat', e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md"
            >
              <option value="MM/dd/yyyy">MM/DD/YYYY</option>
              <option value="dd/MM/yyyy">DD/MM/YYYY</option>
              <option value="yyyy-MM-dd">YYYY-MM-DD</option>
            </select>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function AppearanceSettings({
  preferences,
  onChange,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Palette className="h-5 w-5 mr-2" />
            Theme
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Color Theme</label>
            <div className="grid grid-cols-3 gap-3">
              {['light', 'dark', 'system'].map(theme => (
                <button
                  key={theme}
                  onClick={() => onChange('theme', theme)}
                  className={`p-3 border rounded-lg text-center capitalize ${
                    preferences.theme === theme
                      ? 'border-blue-500 bg-blue-50'
                      : 'border-gray-300 hover:border-gray-400'
                  }`}
                >
                  {theme}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Compact Mode</label>
              <p className="text-xs text-gray-500">Reduce spacing and padding</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.interface.compactMode}
              onChange={e => onChange('interface.compactMode', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Show Tooltips</label>
              <p className="text-xs text-gray-500">Display helpful tooltips</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.interface.showTooltips}
              onChange={e => onChange('interface.showTooltips', e.target.checked)}
              className="rounded"
            />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function NotificationSettings({
  preferences,
  onChange,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Bell className="h-5 w-5 mr-2" />
            Notification Preferences
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Bell className="h-4 w-4 mr-2" />
              <div>
                <label className="text-sm font-medium">Enable Notifications</label>
                <p className="text-xs text-gray-500">Receive app notifications</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={preferences.notifications.enabled}
              onChange={e => onChange('notifications.enabled', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Volume2 className="h-4 w-4 mr-2" />
              <div>
                <label className="text-sm font-medium">Sound</label>
                <p className="text-xs text-gray-500">Play notification sounds</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={preferences.notifications.sound}
              onChange={e => onChange('notifications.sound', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Monitor className="h-4 w-4 mr-2" />
              <div>
                <label className="text-sm font-medium">Desktop Notifications</label>
                <p className="text-xs text-gray-500">Show browser notifications</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={preferences.notifications.desktop}
              onChange={e => onChange('notifications.desktop', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Mail className="h-4 w-4 mr-2" />
              <div>
                <label className="text-sm font-medium">Email Notifications</label>
                <p className="text-xs text-gray-500">Receive email updates</p>
              </div>
            </div>
            <input
              type="checkbox"
              checked={preferences.notifications.email}
              onChange={e => onChange('notifications.email', e.target.checked)}
              className="rounded"
            />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function AccessibilitySettings({
  preferences,
  onChange,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Accessibility className="h-5 w-5 mr-2" />
            Accessibility Options
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">High Contrast</label>
              <p className="text-xs text-gray-500">Increase color contrast</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.accessibility.highContrast}
              onChange={e => onChange('accessibility.highContrast', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Large Text</label>
              <p className="text-xs text-gray-500">Increase font size</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.accessibility.largeText}
              onChange={e => onChange('accessibility.largeText', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Reduced Motion</label>
              <p className="text-xs text-gray-500">Minimize animations</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.accessibility.reducedMotion}
              onChange={e => onChange('accessibility.reducedMotion', e.target.checked)}
              className="rounded"
            />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function KeyboardSettings({
  preferences,
  onChange,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Keyboard className="h-5 w-5 mr-2" />
            Keyboard Navigation
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Enable Keyboard Navigation</label>
              <p className="text-xs text-gray-500">Navigate using keyboard shortcuts</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.interface.keyboardNavigation}
              onChange={e => onChange('interface.keyboardNavigation', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="mt-4">
            <h4 className="text-sm font-medium mb-2">Keyboard Shortcuts</h4>
            <div className="space-y-2 text-xs text-gray-600">
              <div className="flex justify-between">
                <span>Undo</span>
                <kbd className="px-2 py-1 bg-gray-100 rounded">Ctrl + Z</kbd>
              </div>
              <div className="flex justify-between">
                <span>Redo</span>
                <kbd className="px-2 py-1 bg-gray-100 rounded">Ctrl + Y</kbd>
              </div>
              <div className="flex justify-between">
                <span>Show shortcuts</span>
                <kbd className="px-2 py-1 bg-gray-100 rounded">Ctrl + /</kbd>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function PrivacySettings({
  preferences,
  onChange,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Shield className="h-5 w-5 mr-2" />
            Privacy & Security
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Auto-save</label>
              <p className="text-xs text-gray-500">Automatically save changes</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.interface.autoSave}
              onChange={e => onChange('interface.autoSave', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="pt-4 border-t">
            <h4 className="text-sm font-medium mb-2">Data Management</h4>
            <div className="space-y-2">
              <Button variant="outline" size="sm">
                Clear Cache
              </Button>
              <Button variant="outline" size="sm">
                Export Data
              </Button>
              <Button variant="destructive" size="sm">
                Delete All Data
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function PerformanceSettings({
  preferences,
  onChange,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Zap className="h-5 w-5 mr-2" />
            Performance Optimization
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Auto-Detection</label>
              <p className="text-xs text-gray-500">
                Automatically optimize performance based on dataset size
              </p>
            </div>
            <input
              type="checkbox"
              checked={preferences.performance.autoDetection}
              onChange={e => onChange('performance.autoDetection', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="flex items-center justify-between">
            <div>
              <label className="text-sm font-medium">Performance Monitoring</label>
              <p className="text-xs text-gray-500">Monitor memory usage and performance metrics</p>
            </div>
            <input
              type="checkbox"
              checked={preferences.performance.enableMonitoring}
              onChange={e => onChange('performance.enableMonitoring', e.target.checked)}
              className="rounded"
            />
          </div>

          <div className="pt-4 border-t">
            <h4 className="text-sm font-medium mb-3">Rendering Preferences</h4>

            <div className="flex items-center justify-between mb-3">
              <div>
                <label className="text-sm font-medium">Force Disable Virtualization</label>
                <p className="text-xs text-gray-500">
                  Never use virtualized rendering, even for large datasets
                </p>
              </div>
              <input
                type="checkbox"
                checked={preferences.performance.forceDisableVirtualization}
                onChange={e => onChange('performance.forceDisableVirtualization', e.target.checked)}
                className="rounded"
              />
            </div>

            <div className="flex items-center justify-between mb-3">
              <div>
                <label className="text-sm font-medium">Force Enable Pagination</label>
                <p className="text-xs text-gray-500">
                  Always use pagination for medium to large datasets
                </p>
              </div>
              <input
                type="checkbox"
                checked={preferences.performance.forceEnablePagination}
                onChange={e => onChange('performance.forceEnablePagination', e.target.checked)}
                className="rounded"
              />
            </div>

            <div className="flex items-center justify-between">
              <div>
                <label className="text-sm font-medium">Page Size</label>
                <p className="text-xs text-gray-500">Number of items per page in pagination mode</p>
              </div>
              <select
                value={preferences.performance.pageSize}
                onChange={e => onChange('performance.pageSize', Number(e.target.value))}
                className="border rounded px-2 py-1 text-sm bg-background"
              >
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
                <option value={200}>200</option>
              </select>
            </div>
          </div>

          <div className="pt-4 border-t">
            <h4 className="text-sm font-medium mb-3">Performance Thresholds</h4>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium">Advisory Threshold</label>
                  <p className="text-xs text-gray-500">Show performance advisory at this count</p>
                </div>
                <Input
                  type="number"
                  value={preferences.performance.customThresholds.advisory}
                  onChange={e =>
                    onChange('performance.customThresholds.advisory', Number(e.target.value))
                  }
                  className="w-20 text-sm"
                  min={100}
                  max={10000}
                />
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium">Pagination Threshold</label>
                  <p className="text-xs text-gray-500">Prompt for pagination at this count</p>
                </div>
                <Input
                  type="number"
                  value={preferences.performance.customThresholds.pagination}
                  onChange={e =>
                    onChange('performance.customThresholds.pagination', Number(e.target.value))
                  }
                  className="w-20 text-sm"
                  min={500}
                  max={25000}
                />
              </div>

              <div className="flex items-center justify-between">
                <div>
                  <label className="text-sm font-medium">Virtualization Threshold</label>
                  <p className="text-xs text-gray-500">
                    Auto-switch to virtualization at this count
                  </p>
                </div>
                <Input
                  type="number"
                  value={preferences.performance.customThresholds.virtualization}
                  onChange={e =>
                    onChange('performance.customThresholds.virtualization', Number(e.target.value))
                  }
                  className="w-20 text-sm"
                  min={1000}
                  max={50000}
                />
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function AdvancedSettings({
  preferences,
  onChange,
  onExport,
  onImport,
}: {
  preferences: UserPreferences
  onChange: (path: string, value: any) => void
  onExport: () => void
  onImport: (event: React.ChangeEvent<HTMLInputElement>) => void
}) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Zap className="h-5 w-5 mr-2" />
            Advanced Settings
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h4 className="text-sm font-medium mb-2">Settings Management</h4>
            <div className="flex space-x-2">
              <Button variant="outline" onClick={onExport}>
                <Download className="h-4 w-4 mr-2" />
                Export Settings
              </Button>
              <label className="cursor-pointer">
                <span className="inline-flex items-center px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 cursor-pointer">
                  <Upload className="h-4 w-4 mr-2" />
                  Import Settings
                </span>
                <input type="file" accept=".json" onChange={onImport} className="hidden" />
              </label>
            </div>
          </div>

          <div className="pt-4 border-t">
            <h4 className="text-sm font-medium mb-2">Debug Information</h4>
            <div className="text-xs text-gray-600 space-y-1">
              <div>Version: 1.0.0</div>
              <div>Build: {new Date().toISOString().split('T')[0]}</div>
              <div>User Agent: {navigator.userAgent.substring(0, 50)}...</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
