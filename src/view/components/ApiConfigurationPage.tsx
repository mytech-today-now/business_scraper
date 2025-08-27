'use client'

import React, { useState, useEffect, useCallback } from 'react'
import {
  Key,
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Eye,
  EyeOff,
  Save,
  Trash2,
  Download,
  Upload,
  Info,
  ExternalLink,
  Lock,
  Unlock,
  Search,
  TestTube,
} from 'lucide-react'
import { Card, CardHeader, CardTitle, CardContent } from './ui/Card'
import { Button } from './ui/Button'
import { Input } from './ui/Input'
import { toast } from 'react-hot-toast'
import {
  ApiCredentials,
  storeApiCredentials,
  retrieveApiCredentials,
  clearApiCredentials,
  hasStoredCredentials,
  getCredentialsTimestamp,
  validateApiCredentials,
  testApiCredentials,
  testApiCredentialsDetailed,
  exportCredentials,
  importCredentials,
  type ApiTestResult,
} from '@/utils/secureStorage'
import { logger } from '@/utils/logger'
import SearchEngineControls from './SearchEngineControls'
import { storage } from '@/model/storage'

export interface ApiConfigurationPageProps {
  onClose: () => void
  onCredentialsUpdated?: (credentials: ApiCredentials) => void
}

/**
 * API Configuration Page Component
 * Allows users to securely configure and store API credentials
 */
export function ApiConfigurationPage({
  onClose,
  onCredentialsUpdated,
}: ApiConfigurationPageProps): JSX.Element {
  const [credentials, setCredentials] = useState<ApiCredentials>({})
  const [showPasswords, setShowPasswords] = useState<{ [key: string]: boolean }>({})
  const [isLoading, setIsLoading] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [blacklistText, setBlacklistText] = useState('')
  const [testResults, setTestResults] = useState<{ [key: string]: boolean }>({})
  const [detailedTestResults, setDetailedTestResults] = useState<{ [key: string]: ApiTestResult }>(
    {}
  )
  const [validationErrors, setValidationErrors] = useState<string[]>([])
  const [successMessage, setSuccessMessage] = useState('')
  const [hasExistingCredentials, setHasExistingCredentials] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const loadCredentials = useCallback(async () => {
    setIsLoading(true)
    try {
      const stored = await retrieveApiCredentials()
      if (stored) {
        setCredentials(stored)
        setHasExistingCredentials(true)
        setLastUpdated(getCredentialsTimestamp())
      }

      // Load domain blacklist from IndexedDB (persistent storage)
      try {
        const persistentBlacklist = await storage.getDomainBlacklist()
        if (persistentBlacklist.length > 0) {
          setBlacklistText(persistentBlacklist.join('\n'))
          // Update credentials with persistent blacklist
          setCredentials(prev => ({
            ...prev,
            domainBlacklist: persistentBlacklist,
          }))
        } else if (stored?.domainBlacklist) {
          // Fallback to localStorage blacklist if no persistent storage
          setBlacklistText(stored.domainBlacklist.join('\n'))
        }
      } catch (error) {
        logger.warn(
          'ApiConfiguration',
          'Failed to load persistent blacklist, using localStorage fallback',
          error
        )
        // Fallback to localStorage blacklist
        if (stored?.domainBlacklist) {
          setBlacklistText(stored.domainBlacklist.join('\n'))
        }
      }
    } catch (error) {
      logger.error('ApiConfiguration', 'Failed to load credentials', error)
    } finally {
      setIsLoading(false)
    }
  }, [])

  // Load existing credentials on mount
  useEffect(() => {
    loadCredentials()
  }, [loadCredentials])

  const handleInputChange = (field: keyof ApiCredentials, value: string): void => {
    setCredentials(prev => ({
      ...prev,
      [field]: value.trim(),
    }))
    setValidationErrors([])
    setSuccessMessage('')
  }

  const togglePasswordVisibility = (field: string) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field],
    }))
  }

  const handleBlacklistChange = async (value: string): Promise<void> => {
    setBlacklistText(value)
    // Parse domains from text and update credentials
    const domains = value
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'))
      .map(line => line.toLowerCase())

    setCredentials(prev => ({
      ...prev,
      domainBlacklist: domains,
    }))

    // Save to IndexedDB for persistence
    try {
      await storage.saveDomainBlacklist(domains)
      logger.info('ApiConfiguration', `Saved ${domains.length} domains to persistent blacklist`)
    } catch (error) {
      logger.error(
        'ApiConfiguration',
        'Failed to save domain blacklist to persistent storage',
        error
      )
      toast.error('Failed to save domain blacklist persistently')
    }
  }

  const exportBlacklist = async () => {
    try {
      // Get the most current blacklist from IndexedDB
      const persistentBlacklist = await storage.getDomainBlacklist()
      const blacklist =
        persistentBlacklist.length > 0 ? persistentBlacklist : credentials.domainBlacklist || []

      // Create export data with standardized Business Scraper format (same as industry export)
      const exportData = {
        name: 'Business Scraper',
        url: 'https://github.com/mytech-today-now/business_scraper',
        version: '1.0.0',
        exportDate: new Date().toISOString(),
        domainBlacklist: blacklist,
      }

      const dataStr = JSON.stringify(exportData, null, 2)
      const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr)

      const exportFileDefaultName = `domain-blacklist-${new Date().toISOString().split('T')[0]}.json`

      const linkElement = document.createElement('a')
      linkElement.setAttribute('href', dataUri)
      linkElement.setAttribute('download', exportFileDefaultName)
      linkElement.click()

      toast.success(`Exported ${blacklist.length} domains`)
    } catch (error) {
      logger.error('ApiConfiguration', 'Failed to export blacklist', error)
      toast.error('Failed to export domain blacklist')
    }
  }

  const importBlacklist = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = async e => {
      try {
        const content = e.target?.result as string
        const parsedData = JSON.parse(content)

        let domains: string[] = []

        // Handle new format with headers (same as industry export)
        if (parsedData && typeof parsedData === 'object' && parsedData.domainBlacklist) {
          if (Array.isArray(parsedData.domainBlacklist)) {
            domains = parsedData.domainBlacklist
          } else {
            toast.error('Invalid blacklist format. Expected domainBlacklist to be an array.')
            return
          }
        }
        // Handle legacy format (simple array)
        else if (Array.isArray(parsedData)) {
          domains = parsedData
        } else {
          toast.error(
            'Invalid blacklist format. Expected array of domains or Business Scraper export format.'
          )
          return
        }

        const validDomains = domains
          .filter(domain => typeof domain === 'string' && domain.trim().length > 0)
          .map(domain => domain.trim().toLowerCase())

        setBlacklistText(validDomains.join('\n'))
        setCredentials(prev => ({
          ...prev,
          domainBlacklist: validDomains,
        }))

        // Save to IndexedDB for persistence
        try {
          await storage.saveDomainBlacklist(validDomains)
          toast.success(`Imported ${validDomains.length} domains to blacklist`)
        } catch (error) {
          logger.error(
            'ApiConfiguration',
            'Failed to save imported blacklist to persistent storage',
            error
          )
          toast.error('Imported domains but failed to save persistently')
        }
      } catch (error) {
        toast.error('Failed to parse blacklist file. Please check the format.')
      }
    }
    reader.readAsText(file)

    // Reset file input
    event.target.value = ''
  }

  const handleSave = async (): Promise<void> => {
    setIsLoading(true)
    setValidationErrors([])
    setSuccessMessage('')

    try {
      // Validate credentials
      const validation = validateApiCredentials(credentials)
      if (!validation.isValid) {
        setValidationErrors(validation.errors)
        return
      }

      // Store credentials securely
      await storeApiCredentials(credentials)
      setHasExistingCredentials(true)
      setLastUpdated(new Date())
      setSuccessMessage('API credentials saved securely!')

      // Notify parent component
      onCredentialsUpdated?.(credentials)

      logger.info('ApiConfiguration', 'API credentials saved successfully')
    } catch (error) {
      setValidationErrors(['Failed to save credentials securely'])
      logger.error('ApiConfiguration', 'Failed to save credentials', error)
    } finally {
      setIsLoading(false)
    }
  }

  const handleTest = async (): Promise<void> => {
    setIsTesting(true)
    setTestResults({})
    setDetailedTestResults({})
    setValidationErrors([])
    setSuccessMessage('')

    try {
      // Get detailed test results
      const detailedResults = await testApiCredentialsDetailed(credentials)
      console.log('[DEBUG] Received detailed test results:', detailedResults)
      setDetailedTestResults(detailedResults)

      // Convert to simple boolean results for backward compatibility
      const simpleResults: { [key: string]: boolean } = {}
      Object.keys(detailedResults).forEach(key => {
        simpleResults[key] = detailedResults[key].success
      })
      setTestResults(simpleResults)

      const successCount = Object.values(simpleResults).filter(Boolean).length
      const totalCount = Object.keys(simpleResults).length

      if (successCount === totalCount) {
        setSuccessMessage(`All ${totalCount} API credentials tested successfully!`)
      } else {
        setSuccessMessage(`${successCount}/${totalCount} API credentials are working`)
      }
    } catch (error) {
      setValidationErrors(['Failed to test API credentials'])
      logger.error('ApiConfiguration', 'Failed to test credentials', error)
    } finally {
      setIsTesting(false)
    }
  }

  const handleClear = async (): Promise<void> => {
    if (
      confirm(
        'Are you sure you want to clear all stored API credentials? This action cannot be undone.'
      )
    ) {
      clearApiCredentials()
      setCredentials({})
      setHasExistingCredentials(false)
      setLastUpdated(null)
      setTestResults({})
      setDetailedTestResults({})
      setValidationErrors([])
      setSuccessMessage('All API credentials cleared')
      onCredentialsUpdated?.({})
    }
  }

  const handleExport = async (): Promise<void> => {
    try {
      // Export current form state (unsaved credentials) if no saved credentials exist
      let credentialsToExport = credentials

      // If there are saved credentials, prefer those over form state
      const savedCredentials = await retrieveApiCredentials()
      if (savedCredentials && Object.keys(savedCredentials).length > 0) {
        credentialsToExport = savedCredentials
      }

      // Create export data structure
      const exportData = {
        credentials: credentialsToExport,
        timestamp: Date.now(),
        version: '1.0',
      }

      const exportString = btoa(JSON.stringify(exportData))

      if (exportString) {
        const blob = new Blob([exportString], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `api-credentials-backup-${new Date().toISOString().split('T')[0]}.txt`
        a.click()
        URL.revokeObjectURL(url)
        setSuccessMessage('Credentials exported successfully')
      } else {
        setValidationErrors(['No credentials to export'])
      }
    } catch (error) {
      setValidationErrors(['Failed to export credentials'])
      logger.error('ApiConfiguration', 'Failed to export credentials', error)
    }
  }

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>): void => {
    const file = event.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = async e => {
        try {
          const content = e.target?.result as string
          await importCredentials(content)
          await loadCredentials()
          setSuccessMessage('Credentials imported successfully')
        } catch (error) {
          setValidationErrors(['Failed to import credentials: Invalid file format'])
        }
      }
      reader.readAsText(file)
    }
  }

  const getTestIcon = (service: string) => {
    if (isTesting) return <TestTube className="h-4 w-4 animate-pulse text-blue-500" />
    if (testResults[service] === true) return <CheckCircle className="h-4 w-4 text-green-500" />
    if (testResults[service] === false) return <XCircle className="h-4 w-4 text-red-500" />
    return null
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Key className="h-6 w-6 text-blue-600" />
            <div>
              <h2 className="text-xl font-semibold">API Configuration</h2>
              <p className="text-sm text-gray-600">
                Securely configure your search engine API credentials
              </p>
            </div>
          </div>
          <Button variant="ghost" onClick={onClose}>
            ✕
          </Button>
        </div>

        <div className="p-6 space-y-6">
          {/* Security Notice */}
          <Card className="border-blue-200 bg-blue-50">
            <CardContent className="p-6 pt-6">
              <div className="flex items-start space-x-3">
                <Shield className="h-5 w-5 text-blue-600 mt-1" />
                <div className="text-sm">
                  <p className="font-medium text-blue-800 mb-2">Secure Local Storage</p>
                  <p className="text-blue-700">
                    Your API credentials are encrypted using AES-256 encryption and stored locally
                    in your browser. They never leave your device and are not transmitted to our
                    servers.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Debug: Show detailed test results count */}
          {Object.keys(detailedTestResults).length > 0 && (
            <Card className="border-yellow-200 bg-yellow-50 mb-4">
              <CardContent className="p-4">
                <p className="text-sm text-yellow-800">
                  Debug: Found {Object.keys(detailedTestResults).length} detailed test results
                </p>
              </CardContent>
            </Card>
          )}

          {/* Detailed Test Results Display */}
          {Object.keys(detailedTestResults).length > 0 && (
            <Card className="border-blue-200 bg-blue-50">
              <CardContent className="p-6 pt-6">
                <div className="flex items-center space-x-2 mb-4">
                  <TestTube className="h-5 w-5 text-blue-600" />
                  <h3 className="text-lg font-semibold text-blue-900">
                    API Credential Test Results
                  </h3>
                </div>
                <div className="space-y-4">
                  {Object.entries(detailedTestResults).map(([service, result]) => (
                    <div
                      key={service}
                      className={`p-4 rounded-lg border-2 ${
                        result.success ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                      }`}
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center space-x-3">
                          <div
                            className={`p-2 rounded-full ${
                              result.success ? 'bg-green-100' : 'bg-red-100'
                            }`}
                          >
                            {result.success ? (
                              <CheckCircle className="h-5 w-5 text-green-600" />
                            ) : (
                              <XCircle className="h-5 w-5 text-red-600" />
                            )}
                          </div>
                          <div>
                            <h4
                              className={`text-base font-semibold ${
                                result.success ? 'text-green-800' : 'text-red-800'
                              }`}
                            >
                              {service
                                .replace(/([A-Z])/g, ' $1')
                                .trim()
                                .replace(/^./, str => str.toUpperCase())}
                            </h4>
                            <p
                              className={`text-sm ${
                                result.success ? 'text-green-700' : 'text-red-700'
                              }`}
                            >
                              {result.message}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span
                            className={`text-xs font-bold px-3 py-1 rounded-full ${
                              result.success
                                ? 'bg-green-200 text-green-800'
                                : 'bg-red-200 text-red-800'
                            }`}
                          >
                            {result.success ? 'WORKING' : 'FAILED'}
                          </span>
                          {result.statusCode && (
                            <span className="text-xs px-2 py-1 bg-gray-200 text-gray-700 rounded">
                              HTTP {result.statusCode}
                            </span>
                          )}
                        </div>
                      </div>

                      {!result.success && (
                        <div className="space-y-4">
                          {/* Basic Error Information */}
                          {result.error && (
                            <div className="p-4 bg-red-100 rounded-md">
                              <div className="flex items-start space-x-2">
                                <AlertTriangle className="h-4 w-4 text-red-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-red-800">Error Details:</p>
                                  <p className="text-sm text-red-700 mt-1">{result.error}</p>
                                  {result.errorType && (
                                    <p className="text-xs text-red-600 mt-1">
                                      Error Type:{' '}
                                      <span className="font-medium">
                                        {result.errorType.replace(/_/g, ' ').toUpperCase()}
                                      </span>
                                    </p>
                                  )}
                                  {result.estimatedFixTime && (
                                    <p className="text-xs text-red-600 mt-1">
                                      Estimated Fix Time:{' '}
                                      <span className="font-medium">{result.estimatedFixTime}</span>
                                    </p>
                                  )}
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Detailed Error Information */}
                          {result.detailedError && (
                            <div className="p-4 bg-red-50 border border-red-200 rounded-md">
                              <div className="flex items-start space-x-2">
                                <Search className="h-4 w-4 text-red-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-red-800">
                                    Detailed Analysis:
                                  </p>
                                  <p className="text-sm text-red-700 mt-1">
                                    {result.detailedError}
                                  </p>
                                  {result.requestUrl && (
                                    <p className="text-xs text-red-600 mt-2">
                                      Request URL:{' '}
                                      <code className="bg-red-200 px-1 rounded text-xs">
                                        {result.requestUrl}
                                      </code>
                                    </p>
                                  )}
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Common Causes */}
                          {result.commonCauses && result.commonCauses.length > 0 && (
                            <div className="p-4 bg-orange-50 border border-orange-200 rounded-md">
                              <div className="flex items-start space-x-2">
                                <AlertTriangle className="h-4 w-4 text-orange-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-orange-800">
                                    Common Causes:
                                  </p>
                                  <ul className="text-sm text-orange-700 mt-1 space-y-1">
                                    {result.commonCauses.map((cause, index) => (
                                      <li key={index} className="flex items-start space-x-1">
                                        <span className="text-orange-600 mt-0.5">•</span>
                                        <span>{cause}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Troubleshooting Steps */}
                          {result.troubleshootingSteps &&
                            result.troubleshootingSteps.length > 0 && (
                              <div className="p-4 bg-blue-50 border border-blue-200 rounded-md">
                                <div className="flex items-start space-x-2">
                                  <Info className="h-4 w-4 text-blue-600 mt-0.5" />
                                  <div className="flex-1">
                                    <p className="text-sm font-medium text-blue-800">
                                      Troubleshooting Steps:
                                    </p>
                                    <ol className="text-sm text-blue-700 mt-1 space-y-1">
                                      {result.troubleshootingSteps.map((step, index) => (
                                        <li key={index} className="flex items-start space-x-2">
                                          <span className="text-blue-600 font-medium min-w-[1rem]">
                                            {step.startsWith('✅')
                                              ? step.substring(0, 2)
                                              : `${index + 1}.`}
                                          </span>
                                          <span>
                                            {step.startsWith('✅')
                                              ? step.substring(2).trim()
                                              : step.replace(/^\d+\.\s*/, '')}
                                          </span>
                                        </li>
                                      ))}
                                    </ol>
                                  </div>
                                </div>
                              </div>
                            )}

                          {/* Suggested Solution */}
                          {result.suggestion && (
                            <div className="p-4 bg-yellow-100 rounded-md">
                              <div className="flex items-start space-x-2">
                                <Info className="h-4 w-4 text-yellow-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-yellow-800">
                                    Suggested Solution:
                                  </p>
                                  <p className="text-sm text-yellow-700 mt-1">
                                    {result.suggestion}
                                  </p>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Next Steps */}
                          {result.nextSteps && result.nextSteps.length > 0 && (
                            <div className="p-4 bg-green-50 border border-green-200 rounded-md">
                              <div className="flex items-start space-x-2">
                                <CheckCircle className="h-4 w-4 text-green-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-green-800">Next Steps:</p>
                                  <ul className="text-sm text-green-700 mt-1 space-y-1">
                                    {result.nextSteps.map((step, index) => (
                                      <li key={index} className="flex items-start space-x-1">
                                        <span className="text-green-600 mt-0.5">→</span>
                                        <span>{step}</span>
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Documentation Link */}
                          {result.documentationUrl && (
                            <div className="flex items-center space-x-2 pt-2">
                              <ExternalLink className="h-4 w-4 text-blue-600" />
                              <a
                                href={result.documentationUrl}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-sm text-blue-600 hover:text-blue-800 underline font-medium"
                              >
                                📚 View Official Documentation
                              </a>
                            </div>
                          )}
                        </div>
                      )}

                      {result.success && (
                        <div className="space-y-3">
                          {/* Success Message */}
                          {result.suggestion && (
                            <div className="p-4 bg-green-100 rounded-md">
                              <div className="flex items-start space-x-2">
                                <CheckCircle className="h-4 w-4 text-green-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-green-800">Success!</p>
                                  <p className="text-sm text-green-700 mt-1">{result.suggestion}</p>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Detailed Success Information */}
                          {result.detailedError && (
                            <div className="p-4 bg-green-50 border border-green-200 rounded-md">
                              <div className="flex items-start space-x-2">
                                <Info className="h-4 w-4 text-green-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-green-800">
                                    Connection Details:
                                  </p>
                                  <p className="text-sm text-green-700 mt-1">
                                    {result.detailedError}
                                  </p>
                                  {result.requestUrl && (
                                    <p className="text-xs text-green-600 mt-2">
                                      Tested URL:{' '}
                                      <code className="bg-green-200 px-1 rounded text-xs">
                                        {result.requestUrl}
                                      </code>
                                    </p>
                                  )}
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Success Verification Steps */}
                          {result.troubleshootingSteps &&
                            result.troubleshootingSteps.length > 0 && (
                              <div className="p-4 bg-green-50 border border-green-200 rounded-md">
                                <div className="flex items-start space-x-2">
                                  <CheckCircle className="h-4 w-4 text-green-600 mt-0.5" />
                                  <div className="flex-1">
                                    <p className="text-sm font-medium text-green-800">
                                      Verification Checks:
                                    </p>
                                    <ul className="text-sm text-green-700 mt-1 space-y-1">
                                      {result.troubleshootingSteps.map((step, index) => (
                                        <li key={index} className="flex items-start space-x-2">
                                          <span className="text-green-600 font-medium">
                                            {step.startsWith('✅') ? '✅' : '✓'}
                                          </span>
                                          <span>
                                            {step.startsWith('✅')
                                              ? step.substring(2).trim()
                                              : step}
                                          </span>
                                        </li>
                                      ))}
                                    </ul>
                                  </div>
                                </div>
                              </div>
                            )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                <div className="mt-6 p-4 bg-blue-100 rounded-lg">
                  <div className="flex items-start space-x-2">
                    <Info className="h-5 w-5 text-blue-600 mt-0.5" />
                    <div className="text-sm text-blue-800">
                      <p className="font-semibold mb-2">Understanding Test Results:</p>
                      <ul className="space-y-1 text-blue-700">
                        <li>
                          • <strong>WORKING</strong>: API credentials are valid and the service
                          responded successfully
                        </li>
                        <li>
                          • <strong>FAILED</strong>: There was an issue with the credentials or
                          service connectivity
                        </li>
                        <li>
                          • <strong>HTTP Status Codes</strong>: Indicate the specific type of
                          response from the API
                        </li>
                        <li>
                          • <strong>Error Types</strong>: Help identify whether the issue is with
                          credentials, network, or service availability
                        </li>
                        <li>
                          • <strong>DuckDuckGo</strong>: Always available as a fallback (no API key
                          required)
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Fallback: Always show test results if any tests have been run */}
          {Object.keys(testResults).length > 0 && Object.keys(detailedTestResults).length === 0 && (
            <Card className="border-orange-200 bg-orange-50">
              <CardContent className="p-6 pt-6">
                <div className="flex items-center space-x-2 mb-4">
                  <TestTube className="h-5 w-5 text-orange-600" />
                  <h3 className="text-lg font-semibold text-orange-900">
                    API Test Results (Basic)
                  </h3>
                </div>
                <div className="space-y-3">
                  {Object.entries(testResults).map(([service, isWorking]) => (
                    <div
                      key={service}
                      className={`p-4 rounded-lg border-2 ${
                        isWorking ? 'bg-green-50 border-green-200' : 'bg-red-50 border-red-200'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium capitalize">
                          {service.replace(/([A-Z])/g, ' $1').trim()}
                        </span>
                        <div className="flex items-center space-x-2">
                          {isWorking ? (
                            <>
                              <CheckCircle className="h-4 w-4 text-green-500" />
                              <span className="text-xs text-green-600 font-semibold px-2 py-1 bg-green-100 rounded-full">
                                WORKING
                              </span>
                            </>
                          ) : (
                            <>
                              <XCircle className="h-4 w-4 text-red-500" />
                              <span className="text-xs text-red-600 font-semibold px-2 py-1 bg-red-100 rounded-full">
                                FAILED
                              </span>
                            </>
                          )}
                        </div>
                      </div>
                      {!isWorking && (
                        <div className="mt-3 p-3 bg-red-100 rounded-md">
                          <div className="flex items-start space-x-2">
                            <AlertTriangle className="h-4 w-4 text-red-600 mt-0.5" />
                            <div>
                              <p className="text-sm font-medium text-red-800">Test Failed</p>
                              <p className="text-sm text-red-700 mt-1">
                                The API credentials for {service.replace(/([A-Z])/g, ' $1').trim()}{' '}
                                are not working. This could be due to invalid API keys, network
                                issues, or service unavailability.
                              </p>
                              <p className="text-xs text-red-600 mt-2">
                                💡 Check your API credentials and ensure they are correctly
                                configured.
                              </p>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
                <div className="mt-4 p-3 bg-orange-100 rounded-md">
                  <div className="flex items-start space-x-2">
                    <Info className="h-4 w-4 text-orange-600 mt-0.5" />
                    <div className="text-sm text-orange-700">
                      <p className="font-medium mb-1">Note:</p>
                      <p>
                        Detailed error information is not available. Basic test results only show
                        success/failure status.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Google APIs */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <span>Google APIs</span>
                {getTestIcon('googleSearch')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Google Custom Search API */}
              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-3">Google Custom Search API</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="relative">
                    <Input
                      label="API Key"
                      type={showPasswords.googleSearchApiKey ? 'text' : 'password'}
                      value={credentials.googleSearchApiKey || ''}
                      onChange={e => handleInputChange('googleSearchApiKey', e.target.value)}
                      placeholder="Enter your Google Search API key"
                    />
                    <button
                      type="button"
                      onClick={() => togglePasswordVisibility('googleSearchApiKey')}
                      className="absolute right-3 top-8 text-gray-400 hover:text-gray-600"
                    >
                      {showPasswords.googleSearchApiKey ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                  <Input
                    label="Search Engine ID"
                    value={credentials.googleSearchEngineId || ''}
                    onChange={e => handleInputChange('googleSearchEngineId', e.target.value)}
                    placeholder="Enter your Custom Search Engine ID"
                  />
                </div>
              </div>

              {/* Google Maps API */}
              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-3">Google Maps API</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="relative">
                    <Input
                      label="API Key"
                      type={showPasswords.googleMapsApiKey ? 'text' : 'password'}
                      value={credentials.googleMapsApiKey || ''}
                      onChange={e => handleInputChange('googleMapsApiKey', e.target.value)}
                      placeholder="Enter your Google Maps API key"
                    />
                    <button
                      type="button"
                      onClick={() => togglePasswordVisibility('googleMapsApiKey')}
                      className="absolute right-3 top-8 text-gray-400 hover:text-gray-600"
                    >
                      {showPasswords.googleMapsApiKey ? (
                        <EyeOff className="h-4 w-4" />
                      ) : (
                        <Eye className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                  <div></div> {/* Empty div for grid alignment */}
                </div>
              </div>

              <div className="text-xs text-gray-600 flex items-center space-x-1">
                <Info className="h-3 w-3" />
                <span>Get your credentials from </span>
                <a
                  href="https://console.cloud.google.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-600 hover:underline flex items-center"
                >
                  Google Cloud Console <ExternalLink className="h-3 w-3 ml-1" />
                </a>
              </div>
            </CardContent>
          </Card>

          {/* Additional API Services */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Bing Grounding Custom Search */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <span>Bing Grounding Custom Search</span>
                  {getTestIcon('azureSearch')}
                </CardTitle>
                <div className="text-sm text-gray-600 mt-1">Microsoft Bing Custom Search API</div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="relative">
                  <Input
                    label="Subscription Key (Key 1 or Key 2)"
                    type={showPasswords.azureSearchApiKey ? 'text' : 'password'}
                    value={credentials.azureSearchApiKey || ''}
                    onChange={e => handleInputChange('azureSearchApiKey', e.target.value)}
                    placeholder="Enter your Bing Custom Search subscription key"
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('azureSearchApiKey')}
                    className="absolute right-3 top-8 text-gray-400 hover:text-gray-600"
                  >
                    {showPasswords.azureSearchApiKey ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>

                <div>
                  <Input
                    label="Endpoint URL"
                    type="text"
                    value={credentials.azureSearchEndpoint || 'https://api.bing.microsoft.com/'}
                    onChange={e => handleInputChange('azureSearchEndpoint', e.target.value)}
                    placeholder="https://api.bing.microsoft.com/"
                    disabled
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Fixed endpoint for Bing Custom Search API
                  </p>
                </div>

                <div>
                  <Input
                    label="Resource Name (Optional)"
                    type="text"
                    value={credentials.azureSearchRegion || ''}
                    onChange={e => handleInputChange('azureSearchRegion', e.target.value)}
                    placeholder="BusinessScraperGood"
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Your Azure resource name for reference
                  </p>
                </div>

                <div className="mt-3 p-3 bg-blue-50 rounded-md">
                  <div className="flex items-start space-x-2">
                    <Info className="h-4 w-4 text-blue-600 mt-0.5 flex-shrink-0" />
                    <div className="text-sm text-blue-800 min-w-0 flex-1">
                      <p className="font-medium mb-1">Bing Grounding Custom Search Setup:</p>
                      <ul className="mt-1 space-y-1 text-xs">
                        <li className="break-words">
                          • <strong>Service Type:</strong> microsoft.bing/accounts
                        </li>
                        <li className="break-words">
                          • <strong>Kind:</strong> Bing.GroundingCustomSearch
                        </li>
                        <li className="break-words">
                          • <strong>Location:</strong> global (worldwide availability)
                        </li>
                        <li className="break-words">
                          • <strong>Portal:</strong>{' '}
                          <a
                            href="https://portal.azure.com"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 underline"
                          >
                            Azure Portal
                          </a>
                        </li>
                        <li className="break-words">
                          • <strong>Get Keys:</strong> Resource → Keys and Endpoint → Key 1 or Key 2
                        </li>
                        <li className="break-words">
                          • <strong>Endpoint:</strong> https://api.bing.microsoft.com/ (fixed)
                        </li>
                        <li className="break-words">
                          • <strong>Resource ID:</strong>{' '}
                          /subscriptions/.../providers/Microsoft.Bing/accounts/[name]
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* DuckDuckGo Search */}
            <Card className="border-green-200 bg-green-50">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <span>DuckDuckGo Search</span>
                  {getTestIcon('duckDuckGo')}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center py-4 px-2">
                  <div className="text-green-600 mb-2">
                    <CheckCircle className="h-8 w-8 mx-auto" />
                  </div>
                  <p className="text-sm font-medium text-green-800">Always Available</p>
                  <p className="text-xs text-green-600 mt-1 break-words">
                    No API key required. Used as fallback when other services are unavailable.
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Domain Blacklist */}
          <Card className="border-red-200 bg-red-50">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Shield className="h-5 w-5" />
                <span>Domain Blacklist</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-gray-900">Blocked Domains</label>
                <textarea
                  className="w-full h-32 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500 resize-y font-mono text-sm bg-white text-gray-900 placeholder-gray-500 dark:bg-gray-800 dark:text-gray-100 dark:placeholder-gray-400 dark:border-gray-600"
                  value={blacklistText}
                  onChange={e => handleBlacklistChange(e.target.value)}
                  placeholder="Enter domains to exclude from results, one per line:&#10;statefarm.com&#10;*.statefarm.com (blocks all subdomains)&#10;example.*&#10;# Comments start with #"
                  aria-label="Domain Blacklist"
                />
                <p className="text-xs text-gray-600">
                  Enter domain names (without www) to exclude from search results. One domain per
                  line. Supports wildcards: *.domain.com blocks all subdomains. Comments start with
                  #.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={exportBlacklist}
                  className="flex items-center gap-2"
                >
                  <Download className="h-4 w-4" />
                  Export
                </Button>

                <div className="relative">
                  <input
                    type="file"
                    accept=".json"
                    onChange={importBlacklist}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    aria-label="Import blacklist file"
                  />
                  <Button variant="outline" size="sm" className="flex items-center gap-2">
                    <Upload className="h-4 w-4" />
                    Import
                  </Button>
                </div>

                <div className="ml-auto text-xs text-gray-600">
                  {credentials.domainBlacklist?.length || 0} domains blocked
                </div>
              </div>

              <div className="mt-4 p-3 bg-red-100 rounded-md">
                <div className="flex items-start space-x-2">
                  <Info className="h-4 w-4 text-red-600 mt-0.5" />
                  <div className="text-sm text-red-800">
                    <p className="font-medium">Domain Blacklist Usage:</p>
                    <ul className="mt-1 space-y-1 text-xs">
                      <li>• Filters out unwanted domains from search results</li>
                      <li>• Supports exact domain matching (e.g., &quot;statefarm.com&quot;)</li>
                      <li>
                        • Supports wildcard patterns: &quot;*.statefarm.com&quot; blocks all
                        subdomains
                      </li>
                      <li>• Supports TLD wildcards: &quot;statefarm.*&quot; blocks all TLDs</li>
                      <li>• Comments can be added with # prefix</li>
                      <li>• Export/import as JSON with Business Scraper format headers</li>
                      <li>• Applied to all search providers (Google, Azure, DuckDuckGo)</li>
                      <li>• Compatible with legacy array format for backward compatibility</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Search Engine Management */}
          <SearchEngineControls />

          {/* Status Messages - Moved to bottom above action buttons */}
          {/* Status */}
          {hasExistingCredentials && (
            <Card className="border-green-200 bg-green-50">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Lock className="h-4 w-4 text-green-600" />
                    <span className="text-sm font-medium text-green-800">
                      Credentials Stored Securely
                    </span>
                  </div>
                  {lastUpdated && (
                    <span className="text-xs text-green-600">
                      Last updated: {lastUpdated.toLocaleDateString()}{' '}
                      {lastUpdated.toLocaleTimeString()}
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Messages */}
          {validationErrors.length > 0 && (
            <Card className="border-red-200 bg-red-50">
              <CardContent className="p-4">
                <div className="flex items-start space-x-2">
                  <AlertTriangle className="h-4 w-4 text-red-600 mt-1" />
                  <div>
                    {validationErrors.map((error, index) => (
                      <p key={index} className="text-sm text-red-700">
                        {error}
                      </p>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {successMessage && (
            <Card className="border-green-200 bg-green-50">
              <CardContent className="p-4">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <p className="text-sm text-green-700">{successMessage}</p>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3 pt-4 border-t">
            <Button
              onClick={handleSave}
              disabled={isLoading}
              className="flex items-center space-x-2"
            >
              <Save className="h-4 w-4" />
              <span>{isLoading ? 'Saving...' : 'Save Credentials'}</span>
            </Button>

            <Button
              variant="outline"
              onClick={handleTest}
              disabled={isTesting || !Object.values(credentials).some(Boolean)}
              className="flex items-center space-x-2"
            >
              <TestTube className="h-4 w-4" />
              <span>{isTesting ? 'Testing...' : 'Test Credentials'}</span>
            </Button>

            <Button
              variant="outline"
              onClick={handleExport}
              disabled={
                !hasExistingCredentials &&
                !Object.values(credentials).some(
                  value => value && value.toString().trim().length > 0
                )
              }
              className="flex items-center space-x-2"
            >
              <Download className="h-4 w-4" />
              <span>Export Backup</span>
            </Button>

            <div className="relative">
              <input
                type="file"
                accept=".txt"
                onChange={handleImport}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                id="import-backup-input"
              />
              <label
                htmlFor="import-backup-input"
                className="flex items-center space-x-2 px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 cursor-pointer"
              >
                <Upload className="h-4 w-4" />
                <span>Import Backup</span>
              </label>
            </div>

            <Button
              variant="destructive"
              onClick={handleClear}
              disabled={!hasExistingCredentials}
              className="flex items-center space-x-2 ml-auto"
            >
              <Trash2 className="h-4 w-4" />
              <span>Clear All</span>
            </Button>
          </div>
        </div>
      </div>
    </div>
  )
}
