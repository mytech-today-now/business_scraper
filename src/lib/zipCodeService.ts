import { logger } from '@/utils/logger'

export interface ZipCodeLocation {
  zipCode: string
  latitude: number
  longitude: number
  city?: string
  state?: string
}

export interface DistanceCalculationResult {
  distance: number
  withinRadius: boolean
}

export class ZipCodeService {
  private zipCodeCache = new Map<string, ZipCodeLocation>()

  /**
   * Calculate distance between two ZIP codes
   */
  async calculateDistance(
    zipCode1: string,
    zipCode2: string,
    radiusMiles: number
  ): Promise<DistanceCalculationResult> {
    try {
      const location1 = await this.getZipCodeLocation(zipCode1)
      const location2 = await this.getZipCodeLocation(zipCode2)

      if (!location1 || !location2) {
        logger.warn(
          'ZipCodeService',
          `Could not find coordinates for ZIP codes: ${zipCode1}, ${zipCode2}`
        )
        return { distance: 0, withinRadius: true } // Default to allowing if we can't calculate
      }

      const distance = this.calculateHaversineDistance(
        location1.latitude,
        location1.longitude,
        location2.latitude,
        location2.longitude
      )

      return {
        distance,
        withinRadius: distance <= radiusMiles,
      }
    } catch (error) {
      logger.error('ZipCodeService', 'Error calculating distance', error)
      return { distance: 0, withinRadius: true } // Default to allowing if error occurs
    }
  }

  /**
   * Get coordinates for a ZIP code
   */
  private async getZipCodeLocation(zipCode: string): Promise<ZipCodeLocation | null> {
    // Clean ZIP code (remove +4 extension if present)
    const cleanZip = zipCode.split('-')[0]?.trim() || zipCode.trim()

    // Check cache first
    if (this.zipCodeCache.has(cleanZip)) {
      return this.zipCodeCache.get(cleanZip)!
    }

    try {
      // Try to get coordinates from a free geocoding service
      const location = await this.fetchZipCodeFromAPI(cleanZip)

      if (location) {
        this.zipCodeCache.set(cleanZip, location)
        return location
      }

      // Fallback to hardcoded major ZIP codes if API fails
      const fallbackLocation = this.getFallbackZipCodeLocation(cleanZip)
      if (fallbackLocation) {
        this.zipCodeCache.set(cleanZip, fallbackLocation)
        return fallbackLocation
      }

      return null
    } catch (error) {
      logger.warn('ZipCodeService', `Failed to get location for ZIP ${cleanZip}`, error)
      return null
    }
  }

  /**
   * Fetch ZIP code coordinates from a free API
   */
  private async fetchZipCodeFromAPI(zipCode: string): Promise<ZipCodeLocation | null> {
    try {
      // Use a free ZIP code API (you may want to replace with a more reliable service)
      const response = await fetch(`https://api.zippopotam.us/us/${zipCode}`)

      if (!response.ok) {
        return null
      }

      const data = await response.json()

      if (data.places && data.places.length > 0) {
        const place = data.places[0]
        return {
          zipCode: zipCode,
          latitude: parseFloat(place.latitude),
          longitude: parseFloat(place.longitude),
          city: place['place name'],
          state: place['state abbreviation'],
        }
      }

      return null
    } catch (error) {
      logger.warn('ZipCodeService', `API request failed for ZIP ${zipCode}`, error)
      return null
    }
  }

  /**
   * Fallback ZIP code coordinates for major cities
   */
  private getFallbackZipCodeLocation(zipCode: string): ZipCodeLocation | null {
    // Hardcoded coordinates for major ZIP codes as fallback
    const majorZipCodes: Record<string, ZipCodeLocation> = {
      // New York
      '10001': {
        zipCode: '10001',
        latitude: 40.7505,
        longitude: -73.9934,
        city: 'New York',
        state: 'NY',
      },
      '10002': {
        zipCode: '10002',
        latitude: 40.7156,
        longitude: -73.9877,
        city: 'New York',
        state: 'NY',
      },

      // Los Angeles
      '90210': {
        zipCode: '90210',
        latitude: 34.0901,
        longitude: -118.4065,
        city: 'Beverly Hills',
        state: 'CA',
      },
      '90001': {
        zipCode: '90001',
        latitude: 33.9731,
        longitude: -118.2479,
        city: 'Los Angeles',
        state: 'CA',
      },

      // Chicago
      '60601': {
        zipCode: '60601',
        latitude: 41.8825,
        longitude: -87.6441,
        city: 'Chicago',
        state: 'IL',
      },
      '60602': {
        zipCode: '60602',
        latitude: 41.8796,
        longitude: -87.6355,
        city: 'Chicago',
        state: 'IL',
      },

      // Houston
      '77001': {
        zipCode: '77001',
        latitude: 29.7749,
        longitude: -95.389,
        city: 'Houston',
        state: 'TX',
      },
      '77002': {
        zipCode: '77002',
        latitude: 29.7604,
        longitude: -95.3698,
        city: 'Houston',
        state: 'TX',
      },

      // Phoenix
      '85001': {
        zipCode: '85001',
        latitude: 33.4484,
        longitude: -112.074,
        city: 'Phoenix',
        state: 'AZ',
      },
      '85002': {
        zipCode: '85002',
        latitude: 33.4734,
        longitude: -112.058,
        city: 'Phoenix',
        state: 'AZ',
      },

      // Philadelphia
      '19101': {
        zipCode: '19101',
        latitude: 39.9526,
        longitude: -75.1652,
        city: 'Philadelphia',
        state: 'PA',
      },
      '19102': {
        zipCode: '19102',
        latitude: 39.95,
        longitude: -75.1667,
        city: 'Philadelphia',
        state: 'PA',
      },

      // San Antonio
      '78201': {
        zipCode: '78201',
        latitude: 29.4241,
        longitude: -98.4936,
        city: 'San Antonio',
        state: 'TX',
      },
      '78202': {
        zipCode: '78202',
        latitude: 29.4252,
        longitude: -98.4946,
        city: 'San Antonio',
        state: 'TX',
      },

      // San Diego
      '92101': {
        zipCode: '92101',
        latitude: 32.7157,
        longitude: -117.1611,
        city: 'San Diego',
        state: 'CA',
      },
      '92102': {
        zipCode: '92102',
        latitude: 32.7081,
        longitude: -117.137,
        city: 'San Diego',
        state: 'CA',
      },

      // Dallas
      '75201': {
        zipCode: '75201',
        latitude: 32.7767,
        longitude: -96.797,
        city: 'Dallas',
        state: 'TX',
      },
      '75202': {
        zipCode: '75202',
        latitude: 32.7831,
        longitude: -96.8067,
        city: 'Dallas',
        state: 'TX',
      },

      // San Jose
      '95101': {
        zipCode: '95101',
        latitude: 37.3382,
        longitude: -121.8863,
        city: 'San Jose',
        state: 'CA',
      },
      '95102': {
        zipCode: '95102',
        latitude: 37.3541,
        longitude: -121.9552,
        city: 'San Jose',
        state: 'CA',
      },
    }

    return majorZipCodes[zipCode] || null
  }

  /**
   * Calculate distance between two points using Haversine formula
   */
  private calculateHaversineDistance(
    lat1: number,
    lon1: number,
    lat2: number,
    lon2: number
  ): number {
    const R = 3959 // Earth's radius in miles
    const dLat = this.toRadians(lat2 - lat1)
    const dLon = this.toRadians(lon2 - lon1)

    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) *
        Math.cos(this.toRadians(lat2)) *
        Math.sin(dLon / 2) *
        Math.sin(dLon / 2)

    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
    const distance = R * c

    return Math.round(distance * 100) / 100 // Round to 2 decimal places
  }

  /**
   * Convert degrees to radians
   */
  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180)
  }

  /**
   * Extract ZIP code from address string
   */
  extractZipCodeFromAddress(address: string): string | null {
    // Look for 5-digit ZIP codes, optionally followed by 4-digit extension
    const zipRegex = /\b(\d{5})(?:-\d{4})?\b/
    const match = address.match(zipRegex)
    return match && match[1] ? match[1] : null
  }

  /**
   * Validate if a business address is within the specified radius
   */
  async isBusinessWithinRadius(
    businessAddress: string,
    centerZipCode: string,
    radiusMiles: number
  ): Promise<boolean> {
    try {
      const businessZip = this.extractZipCodeFromAddress(businessAddress)

      if (!businessZip) {
        logger.warn('ZipCodeService', `Could not extract ZIP code from address: ${businessAddress}`)
        return true // Default to allowing if we can't extract ZIP
      }

      const result = await this.calculateDistance(centerZipCode, businessZip, radiusMiles)

      logger.info(
        'ZipCodeService',
        `Distance from ${centerZipCode} to ${businessZip}: ${result.distance} miles (within ${radiusMiles}mi: ${result.withinRadius})`
      )

      return result.withinRadius
    } catch (error) {
      logger.error('ZipCodeService', 'Error validating business radius', error)
      return true // Default to allowing if error occurs
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      cacheSize: this.zipCodeCache.size,
      cachedZipCodes: Array.from(this.zipCodeCache.keys()),
    }
  }

  /**
   * Clear the cache
   */
  clearCache() {
    this.zipCodeCache.clear()
    logger.info('ZipCodeService', 'Cache cleared')
  }
}

// Export singleton instance
export const zipCodeService = new ZipCodeService()
