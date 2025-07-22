'use strict'

import { BusinessRecord } from '@/types/business'

/**
 * Format a phone number to a standard format
 * @param phone - Raw phone number string
 * @returns Formatted phone number
 */
export function formatPhoneNumber(phone: string): string {
  if (!phone) return ''
  
  // Remove all non-digit characters
  const digits = phone.replace(/\D/g, '')
  
  // Handle different phone number lengths
  if (digits.length === 10) {
    return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`
  } else if (digits.length === 11 && digits[0] === '1') {
    return `+1 (${digits.slice(1, 4)}) ${digits.slice(4, 7)}-${digits.slice(7)}`
  }
  
  return phone // Return original if can't format
}

/**
 * Format an email address (basic validation and normalization)
 * @param email - Raw email string
 * @returns Formatted email or null if invalid
 */
export function formatEmail(email: string): string | null {
  if (!email) return null
  
  const trimmed = email.trim().toLowerCase()
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  
  return emailRegex.test(trimmed) ? trimmed : null
}

/**
 * Format a business address
 * @param address - Address object
 * @returns Formatted address string
 */
export function formatAddress(address: BusinessRecord['address']): string {
  if (!address) return ''
  
  const parts: string[] = []
  
  if (address.street) {
    parts.push(address.street)
  }
  
  if (address.suite) {
    parts.push(address.suite)
  }
  
  const cityStateZip = [address.city, address.state, address.zipCode]
    .filter(Boolean)
    .join(', ')
  
  if (cityStateZip) {
    parts.push(cityStateZip)
  }
  
  return parts.join(', ')
}

/**
 * Format a business name (title case)
 * @param name - Raw business name
 * @returns Formatted business name
 */
export function formatBusinessName(name: string): string {
  if (!name) return ''
  
  return name
    .trim()
    .split(' ')
    .map(word => {
      // Handle common business abbreviations
      const upperWords = ['LLC', 'INC', 'CORP', 'LTD', 'CO', 'LP', 'PC']
      if (upperWords.includes(word.toUpperCase())) {
        return word.toUpperCase()
      }
      
      // Title case for regular words
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
    })
    .join(' ')
}

/**
 * Format a date for display
 * @param date - Date object
 * @param format - Format type ('short', 'long', 'time')
 * @returns Formatted date string
 */
export function formatDate(date: Date, format: 'short' | 'long' | 'time' = 'short'): string {
  if (!date || !(date instanceof Date)) return ''
  
  switch (format) {
    case 'short':
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      })
    case 'long':
      return date.toLocaleDateString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
      })
    case 'time':
      return date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
      })
    default:
      return date.toLocaleDateString()
  }
}

/**
 * Format file size in human-readable format
 * @param bytes - Size in bytes
 * @returns Formatted size string
 */
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes'
  
  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

/**
 * Format duration in human-readable format
 * @param milliseconds - Duration in milliseconds
 * @returns Formatted duration string
 */
export function formatDuration(milliseconds: number): string {
  if (milliseconds < 1000) {
    return `${milliseconds}ms`
  }
  
  const seconds = Math.floor(milliseconds / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`
  } else {
    return `${seconds}s`
  }
}

/**
 * Format a number with thousand separators
 * @param num - Number to format
 * @returns Formatted number string
 */
export function formatNumber(num: number): string {
  return num.toLocaleString('en-US')
}

/**
 * Format percentage
 * @param value - Decimal value (0.5 = 50%)
 * @param decimals - Number of decimal places
 * @returns Formatted percentage string
 */
export function formatPercentage(value: number, decimals: number = 1): string {
  return `${(value * 100).toFixed(decimals)}%`
}

/**
 * Truncate text with ellipsis
 * @param text - Text to truncate
 * @param maxLength - Maximum length
 * @returns Truncated text
 */
export function truncateText(text: string, maxLength: number): string {
  if (!text || text.length <= maxLength) return text
  return text.slice(0, maxLength - 3) + '...'
}

/**
 * Sanitize text for safe display (remove HTML tags, etc.)
 * @param text - Text to sanitize
 * @returns Sanitized text
 */
export function sanitizeText(text: string): string {
  if (!text) return ''

  return text
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags and content
    .replace(/<[^>]*>/g, '') // Remove HTML tags
    .replace(/&[^;]+;/g, '') // Remove HTML entities
    .trim()
}

/**
 * Format coordinates for display
 * @param lat - Latitude
 * @param lng - Longitude
 * @param precision - Number of decimal places
 * @returns Formatted coordinates string
 */
export function formatCoordinates(lat: number, lng: number, precision: number = 6): string {
  return `${lat.toFixed(precision)}, ${lng.toFixed(precision)}`
}

/**
 * Format industry name for display
 * @param industry - Raw industry string
 * @returns Formatted industry name
 */
export function formatIndustry(industry: string): string {
  if (!industry) return 'Unknown'
  
  return industry
    .split(/[-_\s]+/)
    .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    .join(' ')
}

/**
 * Format URL for display (remove protocol, www, etc.)
 * @param url - URL to format
 * @returns Formatted URL
 */
export function formatUrl(url: string): string {
  if (!url) return ''
  
  try {
    const urlObj = new URL(url)
    let hostname = urlObj.hostname
    
    // Remove www prefix
    if (hostname.startsWith('www.')) {
      hostname = hostname.slice(4)
    }
    
    return hostname
  } catch {
    return url
  }
}

/**
 * Format search query for display
 * @param query - Search query
 * @param maxLength - Maximum length
 * @returns Formatted query
 */
export function formatSearchQuery(query: string, maxLength: number = 50): string {
  if (!query) return ''
  
  const formatted = query.trim().replace(/\s+/g, ' ')
  return truncateText(formatted, maxLength)
}

/**
 * Format validation error messages
 * @param errors - Array of error messages
 * @returns Formatted error string
 */
export function formatValidationErrors(errors: string[]): string {
  if (!errors || errors.length === 0) return ''

  if (errors.length === 1) {
    return errors[0] || ''
  }

  return `• ${errors.join('\n• ')}`
}

/**
 * Format CSV cell value (escape quotes, handle commas)
 * @param value - Cell value
 * @returns CSV-safe value
 */
export function formatCsvCell(value: any): string {
  if (value === null || value === undefined) return ''
  
  const str = String(value)
  
  // If contains comma, quote, or newline, wrap in quotes and escape quotes
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  
  return str
}

/**
 * Format business record for export
 * @param business - Business record
 * @returns Formatted business object
 */
export function formatBusinessForExport(business: BusinessRecord): Record<string, any> {
  return {
    'Business Name': formatBusinessName(business.businessName),
    'Email': business.email.join('; '),
    'Phone': business.phone ? formatPhoneNumber(business.phone) : '',
    'Website': business.websiteUrl,
    'Address': formatAddress(business.address),
    'Contact Person': business.contactPerson || '',
    'Industry': formatIndustry(business.industry),
    'Coordinates': business.coordinates 
      ? formatCoordinates(business.coordinates.lat, business.coordinates.lng)
      : '',
    'Scraped Date': formatDate(business.scrapedAt),
  }
}
