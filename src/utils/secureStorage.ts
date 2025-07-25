'use client'

/**
 * Secure client-side storage for sensitive data like API keys
 * Uses Web Crypto API for encryption and localStorage for persistence
 */

export interface ApiCredentials {
  googleSearchApiKey?: string
  googleSearchEngineId?: string
  // Azure AI Foundry - "Grounding with Bing Custom Search" (replaces deprecated Bing Search API ending Aug 2025)
  azureSearchApiKey?: string        // Key 1 or Key 2 from Azure AI Foundry resource
  azureSearchEndpoint?: string      // https://[name].cognitiveservices.azure.com/
  azureSearchRegion?: string        // e.g., eastus, westus2, etc.
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
      hash: 'SHA-256'
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
      'business_scraper_v1'
    ].join('|')

    // Create a simple hash of the fingerprint
    let hash = 0
    for (let i = 0; i < fingerprint.length; i++) {
      const char = fingerprint.charCodeAt(i)
      hash = ((hash << 5) - hash) + char
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
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encodedData
  )
  
  return {
    encrypted: Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join(''),
    iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
    salt: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('')
  }
}

/**
 * Decrypt sensitive data using AES-GCM
 */
async function decryptData(encryptedData: EncryptedData, password: string): Promise<string> {
  const decoder = new TextDecoder()
  
  const salt = new Uint8Array(encryptedData.salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16)))
  const iv = new Uint8Array(encryptedData.iv.match(/.{2}/g)!.map(byte => parseInt(byte, 16)))
  const encrypted = new Uint8Array(encryptedData.encrypted.match(/.{2}/g)!.map(byte => parseInt(byte, 16)))
  
  const key = await deriveKey(password, salt)
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encrypted
  )
  
  return decoder.decode(decrypted)
}

/**
 * Store API credentials securely in localStorage
 */
export async function storeApiCredentials(credentials: ApiCredentials): Promise<void> {
  try {
    // Check if Web Crypto API is available
    if (!crypto.subtle) {
      console.warn('Web Crypto API not available, storing credentials in plain text (development only)')
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
        return JSON.parse(decryptedData) as ApiCredentials
      } catch (decryptError) {
        console.warn('Failed to decrypt credentials, trying fallback:', decryptError)
      }
    }

    // Fallback to plain text storage
    const plainDataStr = localStorage.getItem('api_credentials_plain')
    if (plainDataStr) {
      console.warn('Using plain text credentials (development fallback)')
      return JSON.parse(plainDataStr) as ApiCredentials
    }

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
  return localStorage.getItem('encrypted_api_credentials') !== null ||
         localStorage.getItem('api_credentials_plain') !== null
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
export function validateApiCredentials(credentials: ApiCredentials): { isValid: boolean; errors: string[] } {
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
    errors
  }
}

/**
 * Test API credentials by making a simple request
 */
export async function testApiCredentials(credentials: ApiCredentials): Promise<{ [key: string]: boolean }> {
  const results: { [key: string]: boolean } = {}

  // Test Google Search API
  if (credentials.googleSearchApiKey && credentials.googleSearchEngineId) {
    try {
      const response = await fetch(`https://www.googleapis.com/customsearch/v1?key=${credentials.googleSearchApiKey}&cx=${credentials.googleSearchEngineId}&q=test&num=1`)
      results.googleSearch = response.ok
    } catch {
      results.googleSearch = false
    }
  }

  // Test Azure AI Foundry / Cognitive Services API
  if (credentials.azureSearchApiKey && credentials.azureSearchEndpoint) {
    try {
      // Ensure proper URL construction (avoid double slashes)
      const baseUrl = credentials.azureSearchEndpoint.endsWith('/')
        ? credentials.azureSearchEndpoint.slice(0, -1)
        : credentials.azureSearchEndpoint

      // Test with a simple search request to Azure Cognitive Services
      const response = await fetch(`${baseUrl}/search?api-version=2023-11-01&q=test&count=1`, {
        headers: {
          'Ocp-Apim-Subscription-Key': credentials.azureSearchApiKey,
          'Content-Type': 'application/json'
        }
      })
      results.azureSearch = response.ok
    } catch {
      results.azureSearch = false
    }
  }

  // Test DuckDuckGo (always available, no API key needed)
  try {
    const response = await fetch('https://api.duckduckgo.com/?q=test&format=json&no_html=1&skip_disambig=1')
    results.duckDuckGo = response.ok
  } catch {
    results.duckDuckGo = false
  }

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
    version: '1.0'
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
