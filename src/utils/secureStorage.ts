'use client'

/**
 * Secure client-side storage for sensitive data like API keys
 * Uses Web Crypto API for encryption and localStorage for persistence
 */

export interface ApiCredentials {
  googleSearchApiKey?: string
  googleSearchEngineId?: string
  // Bing Grounding Custom Search - Microsoft Bing Custom Search API (microsoft.bing/accounts)
  azureSearchApiKey?: string // Subscription Key 1 or Key 2 from Bing Custom Search resource
  azureSearchEndpoint?: string // https://api.bing.microsoft.com/ (fixed endpoint)
  azureSearchRegion?: string // Resource name for reference (e.g., BusinessScraperGood)
  yandexSearchApiKey?: string
  googleMapsApiKey?: string
  openCageApiKey?: string
  // Search configuration
  duckduckgoSerpPages?: number
  maxSearchResults?: number
  bbbAccreditedOnly?: boolean
  zipRadius?: number
  // Domain blacklist for filtering results
  domainBlacklist?: string[]
}

export interface EncryptedData {
  encrypted: string
  iv: string
  salt: string
}

/**
 * Generate a cryptographic key from a password using PBKDF2
 */
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  )

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

/**
 * Generate a device-specific encryption key
 * Uses browser fingerprinting for consistency across sessions
 */
function generateDeviceKey(): string {
  try {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    let canvasFingerprint = 'fallback'

    if (ctx) {
      ctx.textBaseline = 'top'
      ctx.font = '14px Arial'
      ctx.fillText('Device fingerprint', 2, 2)
      canvasFingerprint = canvas.toDataURL()
    }

    const fingerprint = [
      navigator.userAgent || 'unknown',
      navigator.language || 'en',
      `${screen.width}x${screen.height}`,
      new Date().getTimezoneOffset().toString(),
      canvasFingerprint,
      'business_scraper_v1',
    ].join('|')

    // Create a simple hash of the fingerprint
    let hash = 0
    for (let i = 0; i < fingerprint.length; i++) {
      const char = fingerprint.charCodeAt(i)
      hash = (hash << 5) - hash + char
      hash = hash & hash // Convert to 32-bit integer
    }

    return `device_key_${Math.abs(hash)}`
  } catch (error) {
    // Fallback to a simple static key if fingerprinting fails
    console.warn('Device fingerprinting failed, using fallback key')
    return 'device_key_fallback_12345'
  }
}

/**
 * Encrypt sensitive data using AES-GCM
 */
async function encryptData(data: string, password: string): Promise<EncryptedData> {
  const encoder = new TextEncoder()
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))

  const key = await deriveKey(password, salt)
  const encodedData = encoder.encode(data)

  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, encodedData)

  return {
    encrypted: Array.from(new Uint8Array(encrypted))
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''),
    iv: Array.from(iv)
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''),
    salt: Array.from(salt)
      .map(b => b.toString(16).padStart(2, '0'))
      .join(''),
  }
}

/**
 * Decrypt sensitive data using AES-GCM
 */
async function decryptData(encryptedData: EncryptedData, password: string): Promise<string> {
  const decoder = new TextDecoder()

  const salt = new Uint8Array(encryptedData.salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16)))
  const iv = new Uint8Array(encryptedData.iv.match(/.{2}/g)!.map(byte => parseInt(byte, 16)))
  const encrypted = new Uint8Array(
    encryptedData.encrypted.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
  )

  const key = await deriveKey(password, salt)

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, encrypted)

  return decoder.decode(decrypted)
}

/**
 * Store API credentials securely in localStorage
 */
export async function storeApiCredentials(credentials: ApiCredentials): Promise<void> {
  try {
    // Check if Web Crypto API is available
    if (!crypto.subtle) {
      console.warn(
        'Web Crypto API not available, storing credentials in plain text (development only)'
      )
      localStorage.setItem('api_credentials_plain', JSON.stringify(credentials))
      localStorage.setItem('credentials_timestamp', Date.now().toString())
      console.log('API credentials stored (plain text fallback)')
      return
    }

    const deviceKey = generateDeviceKey()
    const dataToEncrypt = JSON.stringify(credentials)
    const encryptedData = await encryptData(dataToEncrypt, deviceKey)

    localStorage.setItem('encrypted_api_credentials', JSON.stringify(encryptedData))
    localStorage.setItem('credentials_timestamp', Date.now().toString())

    console.log('API credentials stored securely')
  } catch (error) {
    console.error('Failed to store API credentials:', error)

    // Fallback to plain text storage in development
    if (process.env.NODE_ENV === 'development') {
      console.warn('Falling back to plain text storage for development')
      localStorage.setItem('api_credentials_plain', JSON.stringify(credentials))
      localStorage.setItem('credentials_timestamp', Date.now().toString())
      return
    }

    throw new Error('Failed to store API credentials securely')
  }
}

/**
 * Retrieve API credentials from secure localStorage
 */
export async function retrieveApiCredentials(): Promise<ApiCredentials | null> {
  try {
    // First try encrypted storage
    const encryptedDataStr = localStorage.getItem('encrypted_api_credentials')
    if (encryptedDataStr && crypto.subtle) {
      try {
        const deviceKey = generateDeviceKey()
        const encryptedData: EncryptedData = JSON.parse(encryptedDataStr)
        const decryptedData = await decryptData(encryptedData, deviceKey)
        const credentials = JSON.parse(decryptedData) as ApiCredentials
        console.log('Successfully retrieved encrypted credentials')
        return credentials
      } catch (decryptError) {
        console.warn('Failed to decrypt credentials, trying fallback:', decryptError)
        // Clear corrupted encrypted data
        localStorage.removeItem('encrypted_api_credentials')
      }
    }

    // Fallback to plain text storage
    const plainDataStr = localStorage.getItem('api_credentials_plain')
    if (plainDataStr) {
      try {
        const credentials = JSON.parse(plainDataStr) as ApiCredentials
        console.warn('Using plain text credentials (development fallback)')
        return credentials
      } catch (parseError) {
        console.warn('Failed to parse plain text credentials, clearing corrupted data:', parseError)
        localStorage.removeItem('api_credentials_plain')
      }
    }

    console.info('No API credentials found in storage')
    return null
  } catch (error) {
    console.error('Failed to retrieve API credentials:', error)
    // If all methods fail, clear the corrupted data
    clearApiCredentials()
    return null
  }
}

/**
 * Clear stored API credentials
 */
export function clearApiCredentials(): void {
  localStorage.removeItem('encrypted_api_credentials')
  localStorage.removeItem('api_credentials_plain')
  localStorage.removeItem('credentials_timestamp')
  console.log('API credentials cleared')
}

/**
 * Check if API credentials are stored
 */
export function hasStoredCredentials(): boolean {
  return (
    localStorage.getItem('encrypted_api_credentials') !== null ||
    localStorage.getItem('api_credentials_plain') !== null
  )
}

/**
 * Get the timestamp when credentials were last stored
 */
export function getCredentialsTimestamp(): Date | null {
  const timestamp = localStorage.getItem('credentials_timestamp')
  return timestamp ? new Date(parseInt(timestamp)) : null
}

/**
 * Validate API credentials format
 */
export function validateApiCredentials(credentials: ApiCredentials): {
  isValid: boolean
  errors: string[]
} {
  const errors: string[] = []

  // Google Search API validation
  if (credentials.googleSearchApiKey) {
    if (credentials.googleSearchApiKey.length < 20) {
      errors.push('Google Search API key appears to be too short')
    }
    if (!credentials.googleSearchEngineId) {
      errors.push('Google Search Engine ID is required when API key is provided')
    }
  }

  if (credentials.googleSearchEngineId) {
    if (credentials.googleSearchEngineId.length < 10) {
      errors.push('Google Search Engine ID appears to be too short')
    }
    if (!credentials.googleSearchApiKey) {
      errors.push('Google Search API key is required when Engine ID is provided')
    }
  }

  // Azure AI Foundry / Cognitive Services validation
  if (credentials.azureSearchApiKey) {
    if (credentials.azureSearchApiKey.length < 20) {
      errors.push('Azure Search API key appears to be too short')
    }
    if (!credentials.azureSearchEndpoint) {
      errors.push('Azure Search endpoint is required when API key is provided')
    }
    if (!credentials.azureSearchRegion) {
      errors.push('Azure Search region is required when API key is provided')
    }
  }

  if (credentials.azureSearchEndpoint) {
    if (!credentials.azureSearchEndpoint.startsWith('https://')) {
      errors.push('Azure Search endpoint must be a valid HTTPS URL')
    }
    if (!credentials.azureSearchApiKey) {
      errors.push('Azure Search API key is required when endpoint is provided')
    }
  }

  // Google Maps API validation
  if (credentials.googleMapsApiKey && credentials.googleMapsApiKey.length < 20) {
    errors.push('Google Maps API key appears to be too short')
  }

  // OpenCage API validation
  if (credentials.openCageApiKey && credentials.openCageApiKey.length < 20) {
    errors.push('OpenCage API key appears to be too short')
  }

  return {
    isValid: errors.length === 0,
    errors,
  }
}

/**
 * Detailed test result interface
 */
export interface ApiTestResult {
  success: boolean
  statusCode?: number
  error?: string
  errorType?: 'network' | 'auth' | 'quota' | 'invalid_key' | 'service_unavailable' | 'unknown'
  message?: string
  suggestion?: string
  documentationUrl?: string
  // Enhanced verbose error details
  detailedError?: string
  requestUrl?: string
  responseHeaders?: { [key: string]: string }
  troubleshootingSteps?: string[]
  commonCauses?: string[]
  nextSteps?: string[]
  estimatedFixTime?: string
}

/**
 * Test API credentials by making a simple request with detailed error reporting
 */
export async function testApiCredentials(
  credentials: ApiCredentials
): Promise<{ [key: string]: boolean }> {
  const results = await testApiCredentialsDetailed(credentials)

  // Convert detailed results to simple boolean format for backward compatibility
  const simpleResults: { [key: string]: boolean } = {}
  Object.keys(results).forEach(key => {
    simpleResults[key] = results[key].success
  })

  return simpleResults
}

/**
 * Test API credentials with detailed error reporting
 */
export async function testApiCredentialsDetailed(
  credentials: ApiCredentials
): Promise<{ [key: string]: ApiTestResult }> {
  console.log('[DEBUG] testApiCredentialsDetailed called with credentials:', credentials)
  const results: { [key: string]: ApiTestResult } = {}

  // Test Google Search API
  if (credentials.googleSearchApiKey && credentials.googleSearchEngineId) {
    try {
      const testUrl = `https://www.googleapis.com/customsearch/v1?key=${credentials.googleSearchApiKey}&cx=${credentials.googleSearchEngineId}&q=test&num=1`
      const response = await fetch(testUrl)

      if (response.ok) {
        const responseData = await response.json().catch(() => ({}))
        results.googleSearch = {
          success: true,
          statusCode: response.status,
          message: 'Google Custom Search API is working correctly',
          suggestion: 'Your Google API credentials are valid and the service is accessible.',
          requestUrl: testUrl.replace(credentials.googleSearchApiKey, '***API_KEY***'),
          detailedError: `Successfully connected to Google Custom Search API. Response contains ${responseData.items?.length || 0} search results.`,
          troubleshootingSteps: [
            '✅ API key is valid',
            '✅ Search Engine ID is valid',
            '✅ Network connectivity is working',
            '✅ Google Custom Search service is operational',
          ],
        }
      } else {
        const errorText = await response.text().catch(() => 'Unknown error')
        let errorType: ApiTestResult['errorType'] = 'unknown'
        let suggestion = 'Please check your Google API credentials and try again.'
        let commonCauses: string[] = []
        let troubleshootingSteps: string[] = []
        let nextSteps: string[] = []
        let estimatedFixTime = '5-15 minutes'

        switch (response.status) {
          case 400:
            errorType = 'invalid_key'
            suggestion =
              'Invalid API key or Search Engine ID. Please verify your credentials in Google Cloud Console.'
            commonCauses = [
              'API key is incorrect or malformed',
              'Search Engine ID (cx parameter) is incorrect',
              "API key and Search Engine ID don't belong to the same project",
              'Custom Search Engine is not properly configured',
            ]
            troubleshootingSteps = [
              '1. Verify API key in Google Cloud Console > APIs & Services > Credentials',
              '2. Check Search Engine ID in Google Custom Search Control Panel',
              '3. Ensure both credentials belong to the same Google Cloud project',
              '4. Verify Custom Search Engine is enabled and configured',
            ]
            nextSteps = [
              'Visit Google Cloud Console to verify API key',
              'Visit Google Custom Search Control Panel to verify Search Engine ID',
              "Test credentials manually using Google's API Explorer",
            ]
            break
          case 401:
            errorType = 'auth'
            suggestion =
              'Authentication failed. Please check your Google API key and ensure it has the necessary permissions.'
            commonCauses = [
              'API key is missing or invalid',
              "API key doesn't have Custom Search API enabled",
              'API key restrictions are blocking the request',
              'API key has expired or been revoked',
            ]
            troubleshootingSteps = [
              '1. Verify API key exists in Google Cloud Console',
              '2. Enable Custom Search API for your project',
              '3. Check API key restrictions (HTTP referrers, IP addresses)',
              '4. Regenerate API key if necessary',
            ]
            nextSteps = [
              'Enable Custom Search API in Google Cloud Console',
              'Check and update API key restrictions',
              'Generate a new API key if current one is compromised',
            ]
            break
          case 403:
            errorType = 'quota'
            suggestion =
              'API quota exceeded or access forbidden. Check your Google Cloud Console for quota limits and billing.'
            commonCauses = [
              'Daily quota limit exceeded (100 free queries per day)',
              'Billing account is not set up for paid usage',
              'Project billing is disabled',
              'API key restrictions are too restrictive',
            ]
            troubleshootingSteps = [
              '1. Check quota usage in Google Cloud Console > APIs & Services > Quotas',
              '2. Verify billing account is active and has sufficient funds',
              '3. Enable billing for the project if using more than free tier',
              '4. Review API key restrictions',
            ]
            nextSteps = [
              'Set up billing account for paid usage beyond free tier',
              'Monitor daily quota usage',
              'Consider implementing request caching to reduce API calls',
            ]
            estimatedFixTime = '10-30 minutes'
            break
          case 429:
            errorType = 'quota'
            suggestion = 'Rate limit exceeded. Please wait a moment and try again.'
            commonCauses = [
              'Too many requests sent in a short time period',
              'Concurrent requests exceeding rate limits',
              'Shared IP address with high usage',
            ]
            troubleshootingSteps = [
              '1. Wait 1-2 minutes before retrying',
              '2. Implement exponential backoff in your application',
              '3. Reduce request frequency',
              '4. Check for other applications using the same API key',
            ]
            nextSteps = [
              'Wait before retrying the test',
              'Implement rate limiting in your application',
              'Consider upgrading to higher rate limits if needed',
            ]
            estimatedFixTime = '1-5 minutes'
            break
          case 503:
            errorType = 'service_unavailable'
            suggestion =
              'Google Custom Search service is temporarily unavailable. Please try again later.'
            commonCauses = [
              'Google Custom Search service is experiencing downtime',
              'Temporary server maintenance',
              'Regional service disruption',
            ]
            troubleshootingSteps = [
              '1. Check Google Cloud Status page for service disruptions',
              '2. Wait 5-10 minutes and retry',
              '3. Try again from a different network/location',
              '4. Contact Google Cloud Support if issue persists',
            ]
            nextSteps = [
              'Monitor Google Cloud Status page',
              'Retry the test in a few minutes',
              'Implement fallback search providers in your application',
            ]
            estimatedFixTime = '5-60 minutes (depends on Google)'
            break
        }

        let detailedErrorMessage = `HTTP ${response.status} error from Google Custom Search API.`
        try {
          const errorData = JSON.parse(errorText)
          if (errorData.error?.message) {
            detailedErrorMessage += ` Google says: "${errorData.error.message}"`
          }
          if (errorData.error?.code) {
            detailedErrorMessage += ` (Error code: ${errorData.error.code})`
          }
        } catch {
          detailedErrorMessage += ` Raw response: ${errorText.substring(0, 200)}${errorText.length > 200 ? '...' : ''}`
        }

        results.googleSearch = {
          success: false,
          statusCode: response.status,
          error: errorText,
          errorType,
          message: `Google Custom Search API test failed (HTTP ${response.status})`,
          suggestion,
          documentationUrl: 'https://developers.google.com/custom-search/v1/introduction',
          detailedError: detailedErrorMessage,
          requestUrl: testUrl.replace(credentials.googleSearchApiKey, '***API_KEY***'),
          commonCauses,
          troubleshootingSteps,
          nextSteps,
          estimatedFixTime,
        }
      }
    } catch (error) {
      const networkError = error instanceof Error ? error.message : 'Network error'
      results.googleSearch = {
        success: false,
        error: networkError,
        errorType: 'network',
        message: 'Failed to connect to Google Custom Search API',
        suggestion:
          'Check your internet connection and ensure the Google API endpoint is accessible.',
        documentationUrl: 'https://developers.google.com/custom-search/v1/introduction',
        detailedError: `Network connection failed: ${networkError}. This could indicate internet connectivity issues, firewall blocking, or DNS resolution problems.`,
        requestUrl: 'https://www.googleapis.com/customsearch/v1',
        commonCauses: [
          'No internet connection',
          'Firewall blocking HTTPS requests',
          'DNS resolution issues',
          'Proxy server configuration problems',
          'Corporate network restrictions',
        ],
        troubleshootingSteps: [
          '1. Check your internet connection',
          '2. Try accessing https://www.googleapis.com in your browser',
          '3. Check firewall and proxy settings',
          '4. Try from a different network (mobile hotspot)',
          '5. Contact your network administrator if on corporate network',
        ],
        nextSteps: [
          'Verify internet connectivity',
          'Test from different network',
          'Check network security settings',
        ],
        estimatedFixTime: '5-30 minutes',
      }
    }
  } else {
    const missingFields = []
    if (!credentials.googleSearchApiKey) missingFields.push('API Key')
    if (!credentials.googleSearchEngineId) missingFields.push('Search Engine ID')

    results.googleSearch = {
      success: false,
      error: 'Missing credentials',
      errorType: 'invalid_key',
      message: 'Google API credentials not configured',
      suggestion: 'Please enter your Google Custom Search API key and Search Engine ID.',
      documentationUrl: 'https://developers.google.com/custom-search/v1/introduction',
      detailedError: `Missing required Google Custom Search credentials: ${missingFields.join(', ')}. Both API Key and Search Engine ID are required for Google Custom Search to work.`,
      commonCauses: [
        'API Key field is empty',
        'Search Engine ID field is empty',
        'Credentials were not saved properly',
        'First time setup not completed',
      ],
      troubleshootingSteps: [
        '1. Get API Key from Google Cloud Console > APIs & Services > Credentials',
        '2. Get Search Engine ID from Google Custom Search Control Panel',
        '3. Enter both credentials in the form above',
        '4. Click "Save Credentials" to store them securely',
      ],
      nextSteps: [
        'Visit Google Cloud Console to create/get API Key',
        'Visit Google Custom Search Control Panel to create/get Search Engine ID',
        'Enter credentials and save them',
      ],
      estimatedFixTime: '10-20 minutes',
    }
  }

  // Test Bing Grounding Custom Search API
  if (credentials.azureSearchApiKey && credentials.azureSearchEndpoint) {
    try {
      // Ensure proper URL construction (avoid double slashes)
      const baseUrl = credentials.azureSearchEndpoint.endsWith('/')
        ? credentials.azureSearchEndpoint.slice(0, -1)
        : credentials.azureSearchEndpoint

      // Test with a simple search request to Bing Custom Search API
      const testUrl = `${baseUrl}/v7.0/custom/search?q=test&count=1`
      const response = await fetch(testUrl, {
        headers: {
          'Ocp-Apim-Subscription-Key': credentials.azureSearchApiKey,
          'Content-Type': 'application/json',
        },
      })

      if (response.ok) {
        const responseData = await response.json().catch(() => ({}))
        results.azureSearch = {
          success: true,
          statusCode: response.status,
          message: 'Bing Grounding Custom Search API is working correctly',
          suggestion:
            'Your Bing Custom Search credentials are valid and the service is accessible.',
          requestUrl: testUrl.replace(credentials.azureSearchApiKey, '***API_KEY***'),
          detailedError: `Successfully connected to Bing Grounding Custom Search API. Service is operational and responding correctly.`,
          troubleshootingSteps: [
            '✅ Subscription key is valid',
            '✅ Endpoint URL is correct',
            '✅ Network connectivity is working',
            '✅ Bing Custom Search service is operational',
          ],
        }
      } else {
        const errorText = await response.text().catch(() => 'Unknown error')
        let errorType: ApiTestResult['errorType'] = 'unknown'
        let suggestion = 'Please check your Bing Custom Search credentials and try again.'
        let commonCauses: string[] = []
        let troubleshootingSteps: string[] = []
        let nextSteps: string[] = []
        let estimatedFixTime = '5-15 minutes'

        switch (response.status) {
          case 401:
            errorType = 'auth'
            suggestion =
              'Authentication failed. Please verify your Bing Custom Search subscription key.'
            commonCauses = [
              'Subscription key is incorrect or expired',
              "Subscription key doesn't match the resource",
              'Resource has been deleted or moved',
              'Billing account is suspended',
            ]
            troubleshootingSteps = [
              '1. Verify subscription key in Azure Portal > Your Resource > Keys and Endpoint',
              '2. Check that endpoint URL is https://api.bing.microsoft.com/',
              '3. Ensure subscription is active and not expired',
              '4. Verify resource exists and is not deleted',
            ]
            nextSteps = [
              'Visit Azure Portal to verify subscription key',
              'Check resource status and subscription',
              'Regenerate subscription key if necessary',
            ]
            break
          case 403:
            errorType = 'quota'
            suggestion =
              'Access forbidden or quota exceeded. Check your Azure subscription and resource limits.'
            commonCauses = [
              'Subscription quota exceeded',
              'Resource pricing tier limits reached',
              'Geographic restrictions',
              'Service not enabled for subscription',
            ]
            troubleshootingSteps = [
              '1. Check quota usage in Azure Portal > Subscriptions > Usage + quotas',
              '2. Verify pricing tier supports your usage',
              '3. Check if service is available in your region',
              '4. Ensure billing account is active',
            ]
            nextSteps = [
              'Upgrade pricing tier if needed',
              'Request quota increase from Azure Support',
              'Check billing and subscription status',
            ]
            estimatedFixTime = '15-60 minutes'
            break
          case 404:
            errorType = 'invalid_key'
            suggestion = 'Endpoint not found. Please verify your Azure endpoint URL is correct.'
            commonCauses = [
              'Endpoint URL is incorrect',
              'Resource name is wrong',
              'Resource has been deleted',
              'Wrong Azure region specified',
            ]
            troubleshootingSteps = [
              '1. Verify endpoint URL in Azure Portal > Your Resource > Keys and Endpoint',
              '2. Check resource name and region',
              '3. Ensure resource exists and is not deleted',
              '4. Verify URL format: https://[name].cognitiveservices.azure.com/',
            ]
            nextSteps = [
              'Copy exact endpoint URL from Azure Portal',
              'Verify resource exists and is accessible',
              'Check resource region and name',
            ]
            break
          case 429:
            errorType = 'quota'
            suggestion = 'Rate limit exceeded. Please wait a moment and try again.'
            commonCauses = [
              'Too many requests in short time period',
              'Pricing tier rate limits exceeded',
              'Concurrent request limits reached',
            ]
            troubleshootingSteps = [
              '1. Wait 1-2 minutes before retrying',
              '2. Check pricing tier rate limits',
              '3. Implement request throttling',
              '4. Consider upgrading pricing tier',
            ]
            nextSteps = [
              'Wait before retrying the test',
              'Review and upgrade pricing tier if needed',
              'Implement rate limiting in application',
            ]
            estimatedFixTime = '1-5 minutes'
            break
          case 503:
            errorType = 'service_unavailable'
            suggestion =
              'Azure AI Foundry service is temporarily unavailable. Please try again later.'
            commonCauses = [
              'Azure service experiencing downtime',
              'Regional service disruption',
              'Maintenance in progress',
            ]
            troubleshootingSteps = [
              '1. Check Azure Status page for service health',
              '2. Wait 5-10 minutes and retry',
              '3. Try different Azure region if available',
              '4. Contact Azure Support if issue persists',
            ]
            nextSteps = [
              'Monitor Azure Status page',
              'Retry test in a few minutes',
              'Consider multi-region deployment',
            ]
            estimatedFixTime = '5-60 minutes (depends on Azure)'
            break
        }

        let detailedErrorMessage = `HTTP ${response.status} error from Azure AI Foundry API.`
        try {
          const errorData = JSON.parse(errorText)
          if (errorData.message) {
            detailedErrorMessage += ` Azure says: "${errorData.message}"`
          }
          if (errorData.code) {
            detailedErrorMessage += ` (Error code: ${errorData.code})`
          }
        } catch {
          detailedErrorMessage += ` Raw response: ${errorText.substring(0, 200)}${errorText.length > 200 ? '...' : ''}`
        }

        results.azureSearch = {
          success: false,
          statusCode: response.status,
          error: errorText,
          errorType,
          message: `Azure AI Foundry API test failed (HTTP ${response.status})`,
          suggestion,
          documentationUrl: 'https://docs.microsoft.com/en-us/azure/cognitive-services/',
          detailedError: detailedErrorMessage,
          requestUrl: testUrl.replace(credentials.azureSearchApiKey, '***API_KEY***'),
          commonCauses,
          troubleshootingSteps,
          nextSteps,
          estimatedFixTime,
        }
      }
    } catch (error) {
      const networkError = error instanceof Error ? error.message : 'Network error'
      results.azureSearch = {
        success: false,
        error: networkError,
        errorType: 'network',
        message: 'Failed to connect to Azure AI Foundry API',
        suggestion: 'Check your internet connection and verify your Azure endpoint URL is correct.',
        documentationUrl: 'https://docs.microsoft.com/en-us/azure/cognitive-services/',
        detailedError: `Network connection failed: ${networkError}. This could indicate connectivity issues or incorrect endpoint URL.`,
        requestUrl: credentials.azureSearchEndpoint || 'Not provided',
        commonCauses: [
          'No internet connection',
          'Incorrect endpoint URL format',
          'Firewall blocking HTTPS requests',
          'DNS resolution issues',
          'Corporate network restrictions',
        ],
        troubleshootingSteps: [
          '1. Check your internet connection',
          '2. Verify endpoint URL format: https://[name].cognitiveservices.azure.com/',
          '3. Try accessing the endpoint URL in your browser',
          '4. Check firewall and proxy settings',
          '5. Contact network administrator if on corporate network',
        ],
        nextSteps: [
          'Verify internet connectivity',
          'Check endpoint URL format',
          'Test from different network',
        ],
        estimatedFixTime: '5-30 minutes',
      }
    }
  } else {
    const missingFields = []
    if (!credentials.azureSearchApiKey) missingFields.push('API Key')
    if (!credentials.azureSearchEndpoint) missingFields.push('Endpoint URL')

    results.azureSearch = {
      success: false,
      error: 'Missing credentials',
      errorType: 'invalid_key',
      message: 'Azure AI Foundry credentials not configured',
      suggestion: 'Please enter your Azure API key, endpoint URL, and region.',
      documentationUrl: 'https://docs.microsoft.com/en-us/azure/cognitive-services/',
      detailedError: `Missing required Azure AI Foundry credentials: ${missingFields.join(', ')}. Both API Key and Endpoint URL are required.`,
      commonCauses: [
        'API Key field is empty',
        'Endpoint URL field is empty',
        'Credentials were not saved properly',
        'Azure resource not created yet',
      ],
      troubleshootingSteps: [
        '1. Create Azure AI Foundry resource in Azure Portal',
        '2. Get API Key from resource > Keys and Endpoint',
        '3. Get Endpoint URL from resource > Keys and Endpoint',
        '4. Enter both credentials in the form above',
      ],
      nextSteps: [
        'Visit Azure Portal to create/access your resource',
        'Copy API Key and Endpoint URL',
        'Enter credentials and save them',
      ],
      estimatedFixTime: '10-20 minutes',
    }
  }

  // Test DuckDuckGo (always available, no API key needed)
  try {
    const testUrl = 'https://api.duckduckgo.com/?q=test&format=json&no_html=1&skip_disambig=1'
    const response = await fetch(testUrl)

    if (response.ok) {
      const responseData = await response.json().catch(() => ({}))
      results.duckDuckGo = {
        success: true,
        statusCode: response.status,
        message: 'DuckDuckGo search is working correctly',
        suggestion: 'DuckDuckGo is available as a fallback search provider (no API key required).',
        requestUrl: testUrl,
        detailedError: `Successfully connected to DuckDuckGo API. This service is free and requires no API key, making it an excellent fallback option.`,
        troubleshootingSteps: [
          '✅ No API key required',
          '✅ Free service with no quotas',
          '✅ Network connectivity is working',
          '✅ DuckDuckGo service is operational',
        ],
      }
    } else {
      results.duckDuckGo = {
        success: false,
        statusCode: response.status,
        error: 'DuckDuckGo API returned an error',
        errorType: 'service_unavailable',
        message: `DuckDuckGo API test failed (HTTP ${response.status})`,
        suggestion:
          'DuckDuckGo service may be temporarily unavailable. This is rare but can happen.',
        requestUrl: testUrl,
        detailedError: `DuckDuckGo API returned HTTP ${response.status}. This is unusual as DuckDuckGo is typically very reliable.`,
        commonCauses: [
          'DuckDuckGo service experiencing downtime (rare)',
          'Network routing issues',
          'Temporary server maintenance',
          'Geographic restrictions (very rare)',
        ],
        troubleshootingSteps: [
          '1. Wait 2-3 minutes and retry',
          '2. Check if https://duckduckgo.com works in your browser',
          '3. Try from a different network',
          '4. Check DuckDuckGo status on social media',
        ],
        nextSteps: [
          'Retry the test in a few minutes',
          'DuckDuckGo is usually very reliable, so this should resolve quickly',
          'Consider this a temporary issue',
        ],
        estimatedFixTime: '2-10 minutes',
      }
    }
  } catch (error) {
    const networkError = error instanceof Error ? error.message : 'Network error'
    results.duckDuckGo = {
      success: false,
      error: networkError,
      errorType: 'network',
      message: 'Failed to connect to DuckDuckGo API',
      suggestion: 'Check your internet connection. DuckDuckGo should normally be accessible.',
      requestUrl: 'https://api.duckduckgo.com',
      detailedError: `Network connection to DuckDuckGo failed: ${networkError}. This indicates a connectivity issue since DuckDuckGo is normally very accessible.`,
      commonCauses: [
        'No internet connection',
        'Firewall blocking DuckDuckGo',
        'DNS resolution issues',
        'Corporate network restrictions',
        'ISP blocking (rare)',
      ],
      troubleshootingSteps: [
        '1. Check your internet connection',
        '2. Try visiting https://duckduckgo.com in your browser',
        '3. Check firewall and proxy settings',
        '4. Try from a different network (mobile hotspot)',
        '5. Contact network administrator if on corporate network',
      ],
      nextSteps: [
        'Verify internet connectivity',
        'Test DuckDuckGo website access',
        'Check network security settings',
      ],
      estimatedFixTime: '5-30 minutes',
    }
  }

  console.log('[DEBUG] testApiCredentialsDetailed returning results:', results)
  return results
}

/**
 * Export credentials for backup (encrypted)
 */
export async function exportCredentials(): Promise<string | null> {
  const credentials = await retrieveApiCredentials()
  if (!credentials) return null

  const exportData = {
    credentials,
    timestamp: Date.now(),
    version: '1.0',
  }

  return btoa(JSON.stringify(exportData))
}

/**
 * Import credentials from backup
 */
export async function importCredentials(exportedData: string): Promise<void> {
  try {
    const importData = JSON.parse(atob(exportedData))
    if (importData.credentials && importData.version) {
      await storeApiCredentials(importData.credentials)
    } else {
      throw new Error('Invalid import data format')
    }
  } catch (error) {
    throw new Error('Failed to import credentials: Invalid format')
  }
}
