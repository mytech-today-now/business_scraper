/**
 * Enhanced Address Parser
 * 
 * Provides comprehensive address parsing to isolate street number, street name,
 * city, state, and ZIP code components from raw address strings.
 */

import { logger } from './logger'

export interface ParsedAddress {
  streetNumber: string
  streetName: string
  suite?: string
  city: string
  state: string
  zipCode: string
  confidence: number
}

export interface AddressParsingOptions {
  strictMode?: boolean
  allowPartialMatches?: boolean
  logErrors?: boolean
}

/**
 * Enhanced Address Parser Class
 */
export class AddressParser {
  // US State abbreviations and full names mapping
  private readonly stateMap = new Map([
    // Standard abbreviations
    ['AL', 'Alabama'], ['AK', 'Alaska'], ['AZ', 'Arizona'], ['AR', 'Arkansas'],
    ['CA', 'California'], ['CO', 'Colorado'], ['CT', 'Connecticut'], ['DE', 'Delaware'],
    ['FL', 'Florida'], ['GA', 'Georgia'], ['HI', 'Hawaii'], ['ID', 'Idaho'],
    ['IL', 'Illinois'], ['IN', 'Indiana'], ['IA', 'Iowa'], ['KS', 'Kansas'],
    ['KY', 'Kentucky'], ['LA', 'Louisiana'], ['ME', 'Maine'], ['MD', 'Maryland'],
    ['MA', 'Massachusetts'], ['MI', 'Michigan'], ['MN', 'Minnesota'], ['MS', 'Mississippi'],
    ['MO', 'Missouri'], ['MT', 'Montana'], ['NE', 'Nebraska'], ['NV', 'Nevada'],
    ['NH', 'New Hampshire'], ['NJ', 'New Jersey'], ['NM', 'New Mexico'], ['NY', 'New York'],
    ['NC', 'North Carolina'], ['ND', 'North Dakota'], ['OH', 'Ohio'], ['OK', 'Oklahoma'],
    ['OR', 'Oregon'], ['PA', 'Pennsylvania'], ['RI', 'Rhode Island'], ['SC', 'South Carolina'],
    ['SD', 'South Dakota'], ['TN', 'Tennessee'], ['TX', 'Texas'], ['UT', 'Utah'],
    ['VT', 'Vermont'], ['VA', 'Virginia'], ['WA', 'Washington'], ['WV', 'West Virginia'],
    ['WI', 'Wisconsin'], ['WY', 'Wyoming'], ['DC', 'District of Columbia']
  ])

  // Reverse mapping for full state names to abbreviations
  private readonly stateNameToAbbrev = new Map(
    Array.from(this.stateMap.entries()).map(([abbrev, name]) => [name.toLowerCase(), abbrev])
  )

  // Street type abbreviations and variations
  private readonly streetTypes = [
    'street', 'st', 'avenue', 'ave', 'road', 'rd', 'drive', 'dr', 'lane', 'ln',
    'boulevard', 'blvd', 'circle', 'cir', 'court', 'ct', 'place', 'pl',
    'way', 'parkway', 'pkwy', 'highway', 'hwy', 'trail', 'trl'
  ]

  // Suite/unit indicators
  private readonly suiteIndicators = [
    'suite', 'ste', 'unit', 'apt', 'apartment', 'floor', 'fl', 'room', 'rm',
    'building', 'bldg', 'office', 'ofc', '#'
  ]

  /**
   * Parse a raw address string into structured components
   */
  parseAddress(rawAddress: string, options: AddressParsingOptions = {}): ParsedAddress {
    const {
      strictMode = false,
      allowPartialMatches = true,
      logErrors = false
    } = options

    if (!rawAddress || typeof rawAddress !== 'string') {
      return this.createEmptyAddress()
    }

    try {
      // Clean and normalize the input
      const cleanAddress = this.cleanAddressString(rawAddress)
      
      // Try different parsing strategies
      const result = this.parseWithMultipleStrategies(cleanAddress, strictMode, allowPartialMatches)
      
      if (logErrors && result.confidence < 0.7) {
        logger.warn('AddressParser', `Low confidence address parse: ${rawAddress}`, { result })
      }

      return result
    } catch (error) {
      if (logErrors) {
        logger.error('AddressParser', `Failed to parse address: ${rawAddress}`, error)
      }
      return this.createEmptyAddress()
    }
  }

  /**
   * Clean and normalize address string
   */
  private cleanAddressString(address: string): string {
    return address
      .trim()
      .replace(/[\n\r]+/g, ', ') // Convert newlines to commas first
      .replace(/\s+/g, ' ') // Normalize whitespace
      .replace(/,\s*,+/g, ', ') // Remove duplicate commas
      .replace(/\s*,\s*/g, ', ') // Clean comma spacing
      .replace(/,\s*$/, '') // Remove trailing comma
  }

  /**
   * Try multiple parsing strategies
   */
  private parseWithMultipleStrategies(
    address: string, 
    strictMode: boolean, 
    allowPartialMatches: boolean
  ): ParsedAddress {
    // Strategy 1: Full structured address (most common)
    let result = this.parseStructuredAddress(address)
    if (result.confidence >= 0.8) return result

    // Strategy 2: Comma-separated components
    result = this.parseCommaSeparated(address)
    if (result.confidence >= 0.7) return result

    // Strategy 3: Pattern-based parsing
    result = this.parseWithPatterns(address)
    if (result.confidence >= 0.6) return result

    // Strategy 4: Partial parsing (if allowed)
    if (allowPartialMatches && !strictMode) {
      result = this.parsePartialAddress(address)
      if (result.confidence >= 0.4) return result
    }

    // Fallback: Return best effort
    return result.confidence > 0 ? result : this.createEmptyAddress()
  }

  /**
   * Parse structured address format: "123 Main St, Anytown, CA 12345"
   */
  private parseStructuredAddress(address: string): ParsedAddress {
    const result = this.createEmptyAddress()

    // Pattern for full address with ZIP
    const fullPattern = /^(.+?),\s*([^,]+),\s*([A-Z]{2}|[A-Za-z\s]+)\s+(\d{5}(?:-\d{4})?)$/
    const match = address.match(fullPattern)

    if (match) {
      const [, streetPart, city, stateRaw, zipCode] = match

      // Parse street components
      const streetInfo = this.parseStreetComponent(streetPart.trim())

      // Parse state
      const state = this.normalizeState(stateRaw)

      if (streetInfo.streetName && city && state && zipCode) {
        result.streetNumber = streetInfo.streetNumber
        result.streetName = streetInfo.streetName
        result.suite = streetInfo.suite
        result.city = city.trim()
        result.state = state
        result.zipCode = zipCode
        result.confidence = 0.9
      }
    }

    return result
  }

  /**
   * Parse comma-separated address components
   */
  private parseCommaSeparated(address: string): ParsedAddress {
    const result = this.createEmptyAddress()
    const parts = address.split(',').map(part => part.trim())

    if (parts.length >= 3) {
      // Extract ZIP and state from last part
      const lastPart = parts[parts.length - 1]
      const zipMatch = lastPart.match(/(\d{5}(?:-\d{4})?)/)
      const stateMatch = lastPart.match(/([A-Z]{2}|[A-Za-z\s]+)/)

      if (zipMatch && stateMatch) {
        result.zipCode = zipMatch[1]
        result.state = this.normalizeState(stateMatch[1])

        // City is second to last part
        if (parts.length >= 2) {
          result.city = parts[parts.length - 2].trim()
        }

        // Street is first part(s) - join them properly
        const streetParts = parts.slice(0, -2)
        if (streetParts.length > 0) {
          const streetString = streetParts.join(' ').trim()
          const streetInfo = this.parseStreetComponent(streetString)
          result.streetNumber = streetInfo.streetNumber
          result.streetName = streetInfo.streetName
          result.suite = streetInfo.suite
        }

        result.confidence = 0.8
      }
    }

    return result
  }

  /**
   * Parse using regex patterns
   */
  private parseWithPatterns(address: string): ParsedAddress {
    const result = this.createEmptyAddress()
    
    // Extract ZIP code
    const zipMatch = address.match(/\b(\d{5}(?:-\d{4})?)\b/)
    if (zipMatch) {
      result.zipCode = zipMatch[1]
    }
    
    // Extract state (2-letter abbreviation or full name)
    const stateMatch = address.match(/\b([A-Z]{2})\b|\b([A-Za-z\s]{4,20})\s+\d{5}/)
    if (stateMatch) {
      result.state = this.normalizeState(stateMatch[1] || stateMatch[2])
    }
    
    // Extract street number and name from beginning
    const streetMatch = address.match(/^(\d+[A-Za-z]?)\s+(.+?)(?:,|$)/)
    if (streetMatch) {
      result.streetNumber = streetMatch[1]
      result.streetName = streetMatch[2].trim()
    }
    
    result.confidence = (result.zipCode ? 0.3 : 0) + (result.state ? 0.2 : 0) + (result.streetName ? 0.2 : 0)
    
    return result
  }

  /**
   * Parse partial address information
   */
  private parsePartialAddress(address: string): ParsedAddress {
    const result = this.createEmptyAddress()
    
    // Try to extract any recognizable components
    const zipMatch = address.match(/\b(\d{5}(?:-\d{4})?)\b/)
    if (zipMatch) {
      result.zipCode = zipMatch[1]
      result.confidence += 0.3
    }
    
    const stateMatch = address.match(/\b([A-Z]{2})\b/)
    if (stateMatch && this.stateMap.has(stateMatch[1])) {
      result.state = stateMatch[1]
      result.confidence += 0.2
    }
    
    const streetMatch = address.match(/^(\d+[A-Za-z]?)\s+(.+)/)
    if (streetMatch) {
      result.streetNumber = streetMatch[1]
      result.streetName = streetMatch[2].split(',')[0].trim()
      result.confidence += 0.2
    }
    
    return result
  }

  /**
   * Parse street component into number, name, and suite
   */
  private parseStreetComponent(streetPart: string): {
    streetNumber: string
    streetName: string
    suite?: string
  } {
    const result = { streetNumber: '', streetName: '', suite: undefined as string | undefined }

    // Look for suite/unit information (more comprehensive pattern)
    // Escape special regex characters in suite indicators
    const escapedIndicators = this.suiteIndicators.map(indicator =>
      indicator.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    )
    // Use a more flexible pattern that handles # without word boundary
    const suitePattern = new RegExp(`(?:^|\\s)(${escapedIndicators.join('|')})\\s*([A-Za-z0-9-]+)`, 'i')
    const suiteMatch = streetPart.match(suitePattern)

    let cleanStreet = streetPart.trim()
    if (suiteMatch) {
      result.suite = `${suiteMatch[1]} ${suiteMatch[2]}`
      // Remove the suite part from the street
      cleanStreet = streetPart.replace(suiteMatch[0], '').trim()
      // Clean up any trailing commas or extra spaces
      cleanStreet = cleanStreet.replace(/,\s*$/, '').trim()
    }

    // Extract street number and name
    const streetMatch = cleanStreet.match(/^(\d+[A-Za-z]?)\s+(.+)/)
    if (streetMatch) {
      result.streetNumber = streetMatch[1]
      result.streetName = streetMatch[2].trim()
    } else {
      // No street number found, treat entire string as street name
      result.streetName = cleanStreet
    }

    return result
  }

  /**
   * Normalize state name to standard abbreviation
   */
  private normalizeState(stateInput: string): string {
    if (!stateInput) return ''
    
    const cleaned = stateInput.trim().toUpperCase()
    
    // Check if it's already a valid abbreviation
    if (this.stateMap.has(cleaned)) {
      return cleaned
    }
    
    // Check if it's a full state name
    const abbrev = this.stateNameToAbbrev.get(stateInput.toLowerCase())
    if (abbrev) {
      return abbrev
    }
    
    return cleaned // Return as-is if not recognized
  }

  /**
   * Create empty address structure
   */
  private createEmptyAddress(): ParsedAddress {
    return {
      streetNumber: '',
      streetName: '',
      suite: undefined,
      city: '',
      state: '',
      zipCode: '',
      confidence: 0
    }
  }
}

/**
 * Default address parser instance
 */
export const addressParser = new AddressParser()
