'use strict'

import axios from 'axios'
import { logger } from '@/utils/logger'

/**
 * Interface for geocoding results
 */
export interface GeocodingResult {
  lat: number
  lng: number
  formattedAddress?: string
  confidence?: number
}

/**
 * Interface for geocoding service configuration
 */
export interface GeocoderConfig {
  timeout: number
  maxRetries: number
  retryDelay: number
}

/**
 * Default geocoder configuration
 */
const DEFAULT_CONFIG: GeocoderConfig = {
  timeout: 10000,
  maxRetries: 3,
  retryDelay: 1000,
}

/**
 * Geocoder service for converting addresses to coordinates
 * Implements multiple geocoding providers with fallback support
 */
export class GeocoderService {
  private config: GeocoderConfig
  private cache: Map<string, GeocodingResult> = new Map()

  constructor(config: Partial<GeocoderConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config }
  }

  /**
   * Geocode an address to coordinates
   * @param address - The address to geocode
   * @returns Promise resolving to geocoding result
   */
  async geocodeAddress(address: string): Promise<GeocodingResult | null> {
    if (!address?.trim()) {
      logger.warn('Geocoder', 'Empty address provided')
      return null
    }

    const normalizedAddress = this.normalizeAddress(address)

    // Check cache first
    if (this.cache.has(normalizedAddress)) {
      logger.info('Geocoder', `Cache hit for address: ${normalizedAddress}`)
      return this.cache.get(normalizedAddress)!
    }

    try {
      // Try multiple geocoding services with fallback
      const result = await this.geocodeWithFallback(normalizedAddress)

      if (result) {
        // Cache successful results
        this.cache.set(normalizedAddress, result)
        logger.info('Geocoder', `Successfully geocoded: ${normalizedAddress}`)
      }

      return result
    } catch (error) {
      logger.error('Geocoder', `Failed to geocode address: ${normalizedAddress}`, error)
      return null
    }
  }

  /**
   * Geocode using multiple services with fallback
   * @param address - Normalized address
   * @returns Promise resolving to geocoding result
   */
  private async geocodeWithFallback(address: string): Promise<GeocodingResult | null> {
    const services = [
      () => this.geocodeWithNominatim(address),
      () => this.geocodeWithOpenCage(address),
      () => this.geocodeWithGoogle(address),
    ]

    for (const service of services) {
      try {
        const result = await this.withRetry(service)
        if (result) return result
      } catch (error) {
        logger.warn('Geocoder', 'Service failed, trying next fallback', error)
        continue
      }
    }

    return null
  }

  /**
   * Geocode using Nominatim (OpenStreetMap) - Free service
   * @param address - Address to geocode
   * @returns Promise resolving to geocoding result
   */
  private async geocodeWithNominatim(address: string): Promise<GeocodingResult | null> {
    const url = 'https://nominatim.openstreetmap.org/search'
    const params = {
      q: address,
      format: 'json',
      limit: 1,
      addressdetails: 1,
    }

    const response = await axios.get(url, {
      params,
      timeout: this.config.timeout,
      headers: {
        'User-Agent': 'BusinessScraperApp/1.0.0',
      },
    })

    const data = response.data
    if (!data || data.length === 0) return null

    const result = data[0]
    return {
      lat: parseFloat(result.lat),
      lng: parseFloat(result.lon),
      formattedAddress: result.display_name,
      confidence: parseFloat(result.importance || '0.5'),
    }
  }

  /**
   * Geocode using OpenCage API (requires API key)
   * @param address - Address to geocode
   * @returns Promise resolving to geocoding result
   */
  private async geocodeWithOpenCage(address: string): Promise<GeocodingResult | null> {
    const apiKey = process.env.OPENCAGE_API_KEY
    if (!apiKey) return null

    const url = 'https://api.opencagedata.com/geocode/v1/json'
    const params = {
      q: address,
      key: apiKey,
      limit: 1,
      no_annotations: 1,
    }

    const response = await axios.get(url, {
      params,
      timeout: this.config.timeout,
    })

    const data = response.data
    if (!data?.results || data.results.length === 0) return null

    const result = data.results[0]
    return {
      lat: result.geometry.lat,
      lng: result.geometry.lng,
      formattedAddress: result.formatted,
      confidence: result.confidence / 10, // Normalize to 0-1
    }
  }

  /**
   * Geocode using Google Maps API (requires API key)
   * @param address - Address to geocode
   * @returns Promise resolving to geocoding result
   */
  private async geocodeWithGoogle(address: string): Promise<GeocodingResult | null> {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY
    if (!apiKey) return null

    const url = 'https://maps.googleapis.com/maps/api/geocode/json'
    const params = {
      address,
      key: apiKey,
    }

    const response = await axios.get(url, {
      params,
      timeout: this.config.timeout,
    })

    const data = response.data
    if (!data?.results || data.results.length === 0) return null

    const result = data.results[0]
    return {
      lat: result.geometry.location.lat,
      lng: result.geometry.location.lng,
      formattedAddress: result.formatted_address,
      confidence: 0.9, // Google typically has high confidence
    }
  }

  /**
   * Execute a function with retry logic
   * @param fn - Function to execute
   * @returns Promise resolving to function result
   */
  private async withRetry<T>(fn: () => Promise<T>): Promise<T> {
    let lastError: Error | null = null

    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        return await fn()
      } catch (error) {
        lastError = error as Error

        if (attempt < this.config.maxRetries) {
          const delay = this.config.retryDelay * Math.pow(2, attempt - 1) // Exponential backoff
          await new Promise(resolve => setTimeout(resolve, delay))
        }
      }
    }

    throw lastError
  }

  /**
   * Normalize address for consistent caching
   * @param address - Raw address
   * @returns Normalized address
   */
  private normalizeAddress(address: string): string {
    return address
      .trim()
      .toLowerCase()
      .replace(/\s+/g, ' ')
      .replace(/[^\w\s,.-]/g, '')
  }

  /**
   * Clear the geocoding cache
   */
  clearCache(): void {
    this.cache.clear()
    logger.info('Geocoder', 'Cache cleared')
  }

  /**
   * Get cache statistics
   * @returns Cache statistics
   */
  getCacheStats(): { size: number; keys: string[] } {
    return {
      size: this.cache.size,
      keys: Array.from(this.cache.keys()),
    }
  }
}

/**
 * Default geocoder instance
 */
export const geocoder = new GeocoderService()
