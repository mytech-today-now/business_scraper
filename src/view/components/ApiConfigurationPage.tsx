'use client'

import React, { useState, useEffect } from 'react'
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
  TestTube,
  Info,
  ExternalLink,
  Lock,
  Unlock,
  Search
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
  exportCredentials,
  importCredentials
} from '@/utils/secureStorage'
import { logger } from '@/utils/logger'

export interface ApiConfigurationPageProps {
  onClose: () => void
  onCredentialsUpdated?: (credentials: ApiCredentials) => void
  isDemoMode?: boolean
  onToggleDemoMode?: () => void
}

/**
 * API Configuration Page Component
 * Allows users to securely configure and store API credentials
 */
export function ApiConfigurationPage({
  onClose,
  onCredentialsUpdated,
  isDemoMode = false,
  onToggleDemoMode
}: ApiConfigurationPageProps) {
  const [credentials, setCredentials] = useState<ApiCredentials>({})
  const [showPasswords, setShowPasswords] = useState<{ [key: string]: boolean }>({})
  const [isLoading, setIsLoading] = useState(false)
  const [isTesting, setIsTesting] = useState(false)
  const [blacklistText, setBlacklistText] = useState('')
  const [testResults, setTestResults] = useState<{ [key: string]: boolean }>({})
  const [validationErrors, setValidationErrors] = useState<string[]>([])
  const [successMessage, setSuccessMessage] = useState('')
  const [hasExistingCredentials, setHasExistingCredentials] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  // Load existing credentials on mount
  useEffect(() => {
    loadCredentials()
  }, [])

  const loadCredentials = async () => {
    setIsLoading(true)
    try {
      const stored = await retrieveApiCredentials()
      if (stored) {
        setCredentials(stored)
        setHasExistingCredentials(true)
        setLastUpdated(getCredentialsTimestamp())
        // Load domain blacklist
        if (stored.domainBlacklist) {
          setBlacklistText(stored.domainBlacklist.join('\n'))
        }
      }
    } catch (error) {
      logger.error('ApiConfiguration', 'Failed to load credentials', error)
    } finally {
      setIsLoading(false)
    }
  }

  const handleInputChange = (field: keyof ApiCredentials, value: string) => {
    setCredentials(prev => ({
      ...prev,
      [field]: value.trim()
    }))
    setValidationErrors([])
    setSuccessMessage('')
  }

  const togglePasswordVisibility = (field: string) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field]
    }))
  }

  const handleBlacklistChange = (value: string) => {
    setBlacklistText(value)
    // Parse domains from text and update credentials
    const domains = value
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'))
      .map(line => line.toLowerCase())

    setCredentials(prev => ({
      ...prev,
      domainBlacklist: domains
    }))
  }

  const exportBlacklist = () => {
    const blacklist = credentials.domainBlacklist || []

    // Create export data with standardized Business Scraper format (same as industry export)
    const exportData = {
      name: "Business Scraper",
      url: "https://github.com/mytech-today-now/business_scraper",
      version: "1.0.0",
      exportDate: new Date().toISOString(),
      domainBlacklist: blacklist
    }

    const dataStr = JSON.stringify(exportData, null, 2)
    const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr)

    const exportFileDefaultName = `domain-blacklist-${new Date().toISOString().split('T')[0]}.json`

    const linkElement = document.createElement('a')
    linkElement.setAttribute('href', dataUri)
    linkElement.setAttribute('download', exportFileDefaultName)
    linkElement.click()
  }

  const importBlacklist = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
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
        }
        else {
          toast.error('Invalid blacklist format. Expected array of domains or Business Scraper export format.')
          return
        }

        const validDomains = domains
          .filter(domain => typeof domain === 'string' && domain.trim().length > 0)
          .map(domain => domain.trim().toLowerCase())

        setBlacklistText(validDomains.join('\n'))
        setCredentials(prev => ({
          ...prev,
          domainBlacklist: validDomains
        }))

        toast.success(`Imported ${validDomains.length} domains to blacklist`)
      } catch (error) {
        toast.error('Failed to parse blacklist file. Please check the format.')
      }
    }
    reader.readAsText(file)

    // Reset file input
    event.target.value = ''
  }

  const handleSave = async () => {
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

  const handleTest = async () => {
    setIsTesting(true)
    setTestResults({})

    try {
      const results = await testApiCredentials(credentials)
      setTestResults(results)
      
      const successCount = Object.values(results).filter(Boolean).length
      const totalCount = Object.keys(results).length
      
      if (successCount === totalCount) {
        setSuccessMessage(`All ${totalCount} API credentials tested successfully!`)
      } else {
        setValidationErrors([`${successCount}/${totalCount} API credentials are working`])
      }
    } catch (error) {
      setValidationErrors(['Failed to test API credentials'])
      logger.error('ApiConfiguration', 'Failed to test credentials', error)
    } finally {
      setIsTesting(false)
    }
  }

  const handleClear = async () => {
    if (confirm('Are you sure you want to clear all stored API credentials? This action cannot be undone.')) {
      clearApiCredentials()
      setCredentials({})
      setHasExistingCredentials(false)
      setLastUpdated(null)
      setTestResults({})
      setValidationErrors([])
      setSuccessMessage('All API credentials cleared')
      onCredentialsUpdated?.({})
    }
  }

  const handleExport = async () => {
    try {
      const exportData = await exportCredentials()
      if (exportData) {
        const blob = new Blob([exportData], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `api-credentials-backup-${new Date().toISOString().split('T')[0]}.txt`
        a.click()
        URL.revokeObjectURL(url)
        setSuccessMessage('Credentials exported successfully')
      }
    } catch (error) {
      setValidationErrors(['Failed to export credentials'])
    }
  }

  const handleImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = async (e) => {
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
              <p className="text-sm text-gray-600">Securely configure your search engine API credentials</p>
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
                    Your API credentials are encrypted using AES-256 encryption and stored locally in your browser.
                    They never leave your device and are not transmitted to our servers.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Status */}
          {hasExistingCredentials && (
            <Card className="border-green-200 bg-green-50">
              <CardContent className="p-6 pt-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Lock className="h-4 w-4 text-green-600" />
                    <span className="text-sm font-medium text-green-800">
                      Credentials Stored Securely
                    </span>
                  </div>
                  {lastUpdated && (
                    <span className="text-xs text-green-600">
                      Last updated: {lastUpdated.toLocaleDateString()} {lastUpdated.toLocaleTimeString()}
                    </span>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Messages */}
          {validationErrors.length > 0 && (
            <Card className="border-red-200 bg-red-50">
              <CardContent className="p-6 pt-6">
                <div className="flex items-start space-x-2">
                  <AlertTriangle className="h-4 w-4 text-red-600 mt-1" />
                  <div>
                    {validationErrors.map((error, index) => (
                      <p key={index} className="text-sm text-red-700">{error}</p>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {successMessage && (
            <Card className="border-green-200 bg-green-50">
              <CardContent className="p-6 pt-6">
                <div className="flex items-center space-x-2">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <p className="text-sm text-green-700">{successMessage}</p>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Google Search API */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <span>Google Custom Search API</span>
                {getTestIcon('googleSearch')}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="relative">
                  <Input
                    label="API Key"
                    type={showPasswords.googleSearchApiKey ? 'text' : 'password'}
                    value={credentials.googleSearchApiKey || ''}
                    onChange={(e) => handleInputChange('googleSearchApiKey', e.target.value)}
                    placeholder="Enter your Google Search API key"
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('googleSearchApiKey')}
                    className="absolute right-3 top-8 text-gray-400 hover:text-gray-600"
                  >
                    {showPasswords.googleSearchApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
                <Input
                  label="Search Engine ID"
                  value={credentials.googleSearchEngineId || ''}
                  onChange={(e) => handleInputChange('googleSearchEngineId', e.target.value)}
                  placeholder="Enter your Custom Search Engine ID"
                />
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
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Azure AI Foundry - Grounding with Bing Custom Search */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <span>Azure AI Foundry</span>
                  {getTestIcon('azureSearch')}
                </CardTitle>
                <div className="text-sm text-gray-600 mt-1">
                  Grounding with Bing Custom Search
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="relative">
                  <Input
                    label="API Key (Key 1 or Key 2)"
                    type={showPasswords.azureSearchApiKey ? 'text' : 'password'}
                    value={credentials.azureSearchApiKey || ''}
                    onChange={(e) => handleInputChange('azureSearchApiKey', e.target.value)}
                    placeholder="Enter your Azure AI Foundry API key"
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('azureSearchApiKey')}
                    className="absolute right-3 top-8 text-gray-400 hover:text-gray-600"
                  >
                    {showPasswords.azureSearchApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>

                <div>
                  <Input
                    label="Endpoint URL"
                    type="text"
                    value={credentials.azureSearchEndpoint || ''}
                    onChange={(e) => handleInputChange('azureSearchEndpoint', e.target.value)}
                    placeholder="https://businessscraper.cognitiveservices.azure.com/"
                  />
                </div>

                <div>
                  <Input
                    label="Region"
                    type="text"
                    value={credentials.azureSearchRegion || ''}
                    onChange={(e) => handleInputChange('azureSearchRegion', e.target.value)}
                    placeholder="eastus"
                  />
                </div>

                <div className="mt-3 p-3 bg-blue-50 rounded-md">
                  <div className="flex items-start space-x-2">
                    <Info className="h-4 w-4 text-blue-600 mt-0.5 flex-shrink-0" />
                    <div className="text-sm text-blue-800 min-w-0 flex-1">
                      <p className="font-medium mb-1">Azure AI Foundry Setup:</p>
                      <ul className="mt-1 space-y-1 text-xs">
                        <li className="break-words">• <strong>NEW:</strong> Replaces deprecated Bing Search API (ends Aug 2025)</li>
                        <li className="break-words">• Service: "Grounding with Bing Custom Search"</li>
                        <li className="break-words">• Portal: <a href="https://portal.azure.com" target="_blank" rel="noopener noreferrer" className="text-blue-600 underline">Azure Portal</a></li>
                        <li className="break-words">• Use either Key 1 or Key 2 from your resource</li>
                        <li className="break-words">• Endpoint format: <span className="break-all">https://[name].cognitiveservices.azure.com/</span></li>
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

            {/* Google Maps API */}
            <Card>
              <CardHeader>
                <CardTitle>Google Maps API</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="relative">
                  <Input
                    label="API Key"
                    type={showPasswords.googleMapsApiKey ? 'text' : 'password'}
                    value={credentials.googleMapsApiKey || ''}
                    onChange={(e) => handleInputChange('googleMapsApiKey', e.target.value)}
                    placeholder="Enter your Google Maps API key"
                  />
                  <button
                    type="button"
                    onClick={() => togglePasswordVisibility('googleMapsApiKey')}
                    className="absolute right-3 top-8 text-gray-400 hover:text-gray-600"
                  >
                    {showPasswords.googleMapsApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Search Configuration */}
          <Card className="border-blue-200 bg-blue-50">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Search className="h-5 w-5" />
                <span>Search Configuration</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    DuckDuckGo SERP Pages
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={credentials.duckduckgoSerpPages || 2}
                    onChange={(e) => handleInputChange('duckduckgoSerpPages' as keyof ApiCredentials, e.target.value)}
                    aria-label="DuckDuckGo SERP Pages"
                  >
                    <option value={1}>1 page (~30 results)</option>
                    <option value={2}>2 pages (~60 results)</option>
                    <option value={3}>3 pages (~90 results)</option>
                    <option value={4}>4 pages (~120 results)</option>
                    <option value={5}>5 pages (~150 results)</option>
                  </select>
                  <p className="text-xs text-gray-600 mt-1">
                    Number of DuckDuckGo search result pages to scrape per query
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    Max Results Per Search
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={credentials.maxSearchResults || 1000}
                    onChange={(e) => handleInputChange('maxSearchResults' as keyof ApiCredentials, e.target.value)}
                    aria-label="Max Results Per Search"
                  >
                    <option value={50}>50 results</option>
                    <option value={100}>100 results</option>
                    <option value={500}>500 results</option>
                    <option value={1000}>1000 results</option>
                    <option value={10000}>Unlimited (10,000+)</option>
                  </select>
                  <p className="text-xs text-gray-600 mt-1">
                    Maximum number of business websites to find per search (higher values gather more comprehensive results)
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-4 border-t border-blue-200">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    BBB Search Type
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={credentials.bbbAccreditedOnly ? 'accredited' : 'all'}
                    onChange={(e) => handleInputChange('bbbAccreditedOnly' as keyof ApiCredentials, e.target.value === 'accredited' ? 'true' : 'false')}
                    aria-label="BBB Search Type"
                  >
                    <option value="accredited">BBB Accredited Businesses Only</option>
                    <option value="all">All Businesses</option>
                  </select>
                  <p className="text-xs text-gray-600 mt-1">
                    Choose whether to search only BBB accredited businesses or all businesses
                  </p>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">
                    ZIP Code Radius (miles)
                  </label>
                  <select
                    className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={credentials.zipRadius || 10}
                    onChange={(e) => handleInputChange('zipRadius' as keyof ApiCredentials, e.target.value)}
                    aria-label="ZIP Code Radius"
                  >
                    <option value={5}>5 miles</option>
                    <option value={10}>10 miles</option>
                    <option value={15}>15 miles</option>
                    <option value={25}>25 miles</option>
                    <option value={50}>50 miles</option>
                  </select>
                  <p className="text-xs text-gray-600 mt-1">
                    Radius around the ZIP code to include businesses
                  </p>
                </div>
              </div>
              <div className="mt-4 p-3 bg-blue-100 rounded-md">
                <div className="flex items-start space-x-2">
                  <Info className="h-4 w-4 text-blue-600 mt-0.5" />
                  <div className="text-sm text-blue-800">
                    <p className="font-medium">Comprehensive Search Strategy:</p>
                    <ul className="mt-1 space-y-1 text-xs">
                      <li>• Scrapes actual DuckDuckGo search result pages (SERP)</li>
                      <li>• Searches each industry criteria individually (medical, healthcare, clinic, etc.)</li>
                      <li>• Uses BBB as business discovery platform to find real business websites</li>
                      <li>• Validates ZIP code radius and extracts "Visit Website" URLs from BBB</li>
                      <li>• Scrapes actual business websites for contact information</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

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
                <label className="text-sm font-medium text-gray-900">
                  Blocked Domains
                </label>
                <textarea
                  className="w-full h-32 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-red-500 resize-y font-mono text-sm bg-white text-gray-900 placeholder-gray-500 dark:bg-gray-800 dark:text-gray-100 dark:placeholder-gray-400 dark:border-gray-600"
                  value={blacklistText}
                  onChange={(e) => handleBlacklistChange(e.target.value)}
                  placeholder="Enter domains to exclude from results, one per line:&#10;statefarm.com&#10;*.statefarm.com (blocks all subdomains)&#10;example.*&#10;# Comments start with #"
                  aria-label="Domain Blacklist"
                />
                <p className="text-xs text-gray-600">
                  Enter domain names (without www) to exclude from search results. One domain per line. Supports wildcards: *.domain.com blocks all subdomains. Comments start with #.
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
                  <Button
                    variant="outline"
                    size="sm"
                    className="flex items-center gap-2"
                  >
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
                      <li>• Supports exact domain matching (e.g., "statefarm.com")</li>
                      <li>• Supports wildcard patterns: "*.statefarm.com" blocks all subdomains</li>
                      <li>• Supports TLD wildcards: "statefarm.*" blocks all TLDs</li>
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

          {/* Application Mode Settings */}
          {onToggleDemoMode && (
            <Card className="border-purple-200 bg-purple-50">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <TestTube className="h-5 w-5" />
                  <span>Application Mode</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between p-4 bg-white rounded-lg border border-purple-200">
                  <div className="space-y-1">
                    <label className="text-sm font-medium text-gray-900">Demo Mode</label>
                    <p className="text-xs text-gray-600">
                      {isDemoMode
                        ? 'Using demo data for testing and development'
                        : 'Using real web scraping (requires API setup)'}
                    </p>
                  </div>
                  <Button
                    variant={isDemoMode ? "default" : "outline"}
                    size="sm"
                    onClick={onToggleDemoMode}
                    className="min-w-[80px]"
                  >
                    {isDemoMode ? 'Demo' : 'Real'}
                  </Button>
                </div>
                <div className="mt-4 p-3 bg-purple-100 rounded-md">
                  <div className="flex items-start space-x-2">
                    <Info className="h-4 w-4 text-purple-600 mt-0.5 flex-shrink-0" />
                    <div className="text-sm text-purple-800 min-w-0 flex-1">
                      <p className="font-medium mb-1">Mode Information:</p>
                      <ul className="mt-1 space-y-1 text-xs">
                        <li className="break-words">• <strong>Demo Mode:</strong> Uses sample data for testing without real web scraping</li>
                        <li className="break-words">• <strong>Real Mode:</strong> Performs actual web scraping using configured APIs</li>
                        <li className="break-words">• Demo mode is automatically enabled in development environment</li>
                        <li className="break-words">• Real mode requires proper API credentials to be configured</li>
                      </ul>
                    </div>
                  </div>
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
              disabled={!hasExistingCredentials}
              className="flex items-center space-x-2"
            >
              <Download className="h-4 w-4" />
              <span>Export Backup</span>
            </Button>

            <label className="flex items-center space-x-2 px-4 py-2 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 cursor-pointer">
              <Upload className="h-4 w-4" />
              <span>Import Backup</span>
              <input
                type="file"
                accept=".txt"
                onChange={handleImport}
                className="hidden"
              />
            </label>

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
