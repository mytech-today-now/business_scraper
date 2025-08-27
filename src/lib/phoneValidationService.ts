'use strict'

import { PhoneValidationResult } from '@/types/business'
import { logger } from '@/utils/logger'

/**
 * Phone Number Intelligence Service
 * Comprehensive phone number validation, carrier identification, and intelligence gathering
 */
export class PhoneValidationService {
  private static instance: PhoneValidationService
  private validationCache = new Map<string, PhoneValidationResult>()
  private carrierCache = new Map<string, any>()
  private dncCache = new Map<string, { isOnDnc: boolean; timestamp: number }>()

  // Cache TTL settings
  private readonly CACHE_TTL = 24 * 60 * 60 * 1000 // 24 hours
  private readonly DNC_CACHE_TTL = 7 * 24 * 60 * 60 * 1000 // 7 days

  // Major US carriers and their identifiers
  private readonly carrierDatabase = new Map([
    // Verizon
    ['310004', { name: 'Verizon Wireless', type: 'wireless', mno: 'Verizon' }],
    ['310005', { name: 'Verizon Wireless', type: 'wireless', mno: 'Verizon' }],
    ['310006', { name: 'Verizon Wireless', type: 'wireless', mno: 'Verizon' }],
    ['310010', { name: 'Verizon Wireless', type: 'wireless', mno: 'Verizon' }],
    ['310012', { name: 'Verizon Wireless', type: 'wireless', mno: 'Verizon' }],
    ['310013', { name: 'Verizon Wireless', type: 'wireless', mno: 'Verizon' }],

    // AT&T
    ['310070', { name: 'AT&T Mobility', type: 'wireless', mno: 'AT&T' }],
    ['310150', { name: 'AT&T Mobility', type: 'wireless', mno: 'AT&T' }],
    ['310170', { name: 'AT&T Mobility', type: 'wireless', mno: 'AT&T' }],
    ['310280', { name: 'AT&T Mobility', type: 'wireless', mno: 'AT&T' }],
    ['310380', { name: 'AT&T Mobility', type: 'wireless', mno: 'AT&T' }],
    ['310410', { name: 'AT&T Mobility', type: 'wireless', mno: 'AT&T' }],

    // T-Mobile
    ['310160', { name: 'T-Mobile USA', type: 'wireless', mno: 'T-Mobile' }],
    ['310200', { name: 'T-Mobile USA', type: 'wireless', mno: 'T-Mobile' }],
    ['310210', { name: 'T-Mobile USA', type: 'wireless', mno: 'T-Mobile' }],
    ['310220', { name: 'T-Mobile USA', type: 'wireless', mno: 'T-Mobile' }],
    ['310230', { name: 'T-Mobile USA', type: 'wireless', mno: 'T-Mobile' }],
    ['310240', { name: 'T-Mobile USA', type: 'wireless', mno: 'T-Mobile' }],

    // Sprint (now part of T-Mobile)
    ['310120', { name: 'Sprint', type: 'wireless', mno: 'T-Mobile' }],
    ['311490', { name: 'Sprint', type: 'wireless', mno: 'T-Mobile' }],
    ['311870', { name: 'Sprint', type: 'wireless', mno: 'T-Mobile' }],
    ['312190', { name: 'Sprint', type: 'wireless', mno: 'T-Mobile' }],
  ])

  // Area code to region mapping (sample)
  private readonly areaCodeRegions = new Map([
    ['212', { region: 'New York, NY', timeZone: 'America/New_York' }],
    ['213', { region: 'Los Angeles, CA', timeZone: 'America/Los_Angeles' }],
    ['312', { region: 'Chicago, IL', timeZone: 'America/Chicago' }],
    ['415', { region: 'San Francisco, CA', timeZone: 'America/Los_Angeles' }],
    ['617', { region: 'Boston, MA', timeZone: 'America/New_York' }],
    ['713', { region: 'Houston, TX', timeZone: 'America/Chicago' }],
    ['305', { region: 'Miami, FL', timeZone: 'America/New_York' }],
    ['206', { region: 'Seattle, WA', timeZone: 'America/Los_Angeles' }],
    ['404', { region: 'Atlanta, GA', timeZone: 'America/New_York' }],
    ['602', { region: 'Phoenix, AZ', timeZone: 'America/Phoenix' }],
  ])

  // VoIP provider patterns
  private readonly voipProviders = [
    'google voice',
    'skype',
    'vonage',
    'magicjack',
    'ooma',
    'ringcentral',
    '8x8',
    'nextiva',
    'grasshopper',
    'dialpad',
  ]

  private constructor() {
    this.initializeCarrierDatabase()
  }

  public static getInstance(): PhoneValidationService {
    if (!PhoneValidationService.instance) {
      PhoneValidationService.instance = new PhoneValidationService()
    }
    return PhoneValidationService.instance
  }

  /**
   * Validate phone number with comprehensive intelligence
   */
  public async validatePhone(
    phone: string,
    businessLocation?: string
  ): Promise<PhoneValidationResult> {
    const normalizedPhone = this.normalizePhoneNumber(phone)

    // Check cache first
    const cacheKey = normalizedPhone
    if (this.validationCache.has(cacheKey)) {
      const cachedResult = this.validationCache.get(cacheKey)!
      return { ...cachedResult, originalNumber: phone }
    }

    const result = await this.performPhoneValidation(phone, normalizedPhone, businessLocation)

    // Cache the result
    this.validationCache.set(cacheKey, result)

    return result
  }

  /**
   * Validate multiple phone numbers in batch
   */
  public async validatePhones(
    phones: string[],
    businessLocation?: string
  ): Promise<PhoneValidationResult[]> {
    const validationPromises = phones.map(phone => this.validatePhone(phone, businessLocation))
    return Promise.all(validationPromises)
  }

  /**
   * Perform comprehensive phone validation
   */
  private async performPhoneValidation(
    originalPhone: string,
    normalizedPhone: string,
    businessLocation?: string
  ): Promise<PhoneValidationResult> {
    const validationTimestamp = new Date().toISOString()
    const errors: string[] = []

    // 1. Basic format validation
    const isValid = this.validatePhoneFormat(normalizedPhone)
    if (!isValid) {
      errors.push('Invalid phone number format')
    }

    // 2. Parse phone number components
    const phoneComponents = this.parsePhoneNumber(normalizedPhone)

    // 3. Carrier identification
    const carrierInfo = await this.identifyCarrier(normalizedPhone)

    // 4. Line type detection
    const lineType = this.detectLineType(normalizedPhone, carrierInfo)

    // 5. Region and timezone detection
    const regionInfo = this.getRegionInfo(phoneComponents.areaCode)

    // 6. DNC registry check
    const dncStatus = await this.checkDncRegistry(normalizedPhone)

    // 7. Reputation and risk scoring
    const reputationScore = this.calculatePhoneReputation(normalizedPhone, carrierInfo, lineType)
    const riskScore = this.calculateRiskScore(normalizedPhone, carrierInfo, lineType, dncStatus)

    // 8. Porting detection
    const isPorted = this.detectPorting(normalizedPhone, carrierInfo)

    // 9. Calculate confidence score
    const confidence = this.calculateConfidence(
      isValid,
      carrierInfo,
      lineType,
      reputationScore,
      businessLocation
    )

    const result: PhoneValidationResult = {
      originalNumber: originalPhone,
      standardizedNumber: this.formatE164(normalizedPhone),
      isValid,
      carrier: carrierInfo?.name,
      lineType,
      country: 'US', // Currently US-focused
      region: regionInfo?.region,
      isPorted,
      confidence,
      validationTimestamp,
      carrierDetails: carrierInfo,
      dncStatus,
      reputationScore,
      riskScore,
      timeZone: regionInfo?.timeZone,
      errors: errors.length > 0 ? errors : undefined,
    }

    logger.debug('PhoneValidationService', `Validated phone ${originalPhone}`, {
      isValid: result.isValid,
      confidence: result.confidence,
      carrier: result.carrier,
      lineType: result.lineType,
    })

    return result
  }

  /**
   * Normalize phone number to standard format
   */
  private normalizePhoneNumber(phone: string): string {
    // Remove all non-digit characters
    let cleaned = phone.replace(/\D/g, '')

    // Handle US numbers
    if (cleaned.length === 10) {
      cleaned = '1' + cleaned // Add US country code
    } else if (cleaned.length === 11 && cleaned.startsWith('1')) {
      // Already has country code
    } else {
      // Invalid length for US number
      return cleaned
    }

    return cleaned
  }

  /**
   * Validate phone number format
   */
  private validatePhoneFormat(phone: string): boolean {
    // US phone number should be 11 digits starting with 1
    if (phone.length !== 11 || !phone.startsWith('1')) {
      return false
    }

    const areaCode = phone.substring(1, 4)
    const exchange = phone.substring(4, 7)

    // Area code cannot start with 0 or 1
    if (areaCode.startsWith('0') || areaCode.startsWith('1')) {
      return false
    }

    // Exchange cannot start with 0 or 1
    if (exchange.startsWith('0') || exchange.startsWith('1')) {
      return false
    }

    return true
  }

  /**
   * Parse phone number into components
   */
  private parsePhoneNumber(phone: string): {
    countryCode: string
    areaCode: string
    exchange: string
    number: string
  } {
    if (phone.length !== 11) {
      return { countryCode: '', areaCode: '', exchange: '', number: '' }
    }

    return {
      countryCode: phone.substring(0, 1),
      areaCode: phone.substring(1, 4),
      exchange: phone.substring(4, 7),
      number: phone.substring(7, 11),
    }
  }

  /**
   * Format phone number in E.164 format
   */
  private formatE164(phone: string): string {
    if (phone.length === 11 && phone.startsWith('1')) {
      return `+${phone}`
    }
    return phone
  }

  /**
   * Identify carrier for phone number
   */
  private async identifyCarrier(phone: string): Promise<any> {
    const areaCode = phone.substring(1, 4)
    const exchange = phone.substring(4, 7)

    // Check cache first
    const cacheKey = `${areaCode}${exchange}`
    if (this.carrierCache.has(cacheKey)) {
      return this.carrierCache.get(cacheKey)
    }

    try {
      // In production, this would query a carrier database or API
      // For now, use pattern matching and known ranges
      const carrierInfo = this.lookupCarrierByPattern(areaCode, exchange)

      // Cache the result
      this.carrierCache.set(cacheKey, carrierInfo)

      return carrierInfo
    } catch (error) {
      logger.debug('PhoneValidationService', `Carrier lookup failed for ${phone}`, error)
      return null
    }
  }

  /**
   * Lookup carrier by area code and exchange patterns
   */
  private lookupCarrierByPattern(areaCode: string, exchange: string): any {
    // This is a simplified lookup - in production, use comprehensive database
    const pattern = `310${exchange.substring(0, 2)}0`

    if (this.carrierDatabase.has(pattern)) {
      return this.carrierDatabase.get(pattern)
    }

    // Default carrier info for unknown numbers
    return {
      name: 'Unknown Carrier',
      type: 'unknown',
      mno: 'Unknown',
    }
  }

  /**
   * Detect line type (mobile, landline, VoIP)
   */
  private detectLineType(
    phone: string,
    carrierInfo: any
  ): 'mobile' | 'landline' | 'voip' | 'unknown' {
    if (!carrierInfo) return 'unknown'

    // Check if it's a known VoIP provider
    if (this.isVoipNumber(phone, carrierInfo)) {
      return 'voip'
    }

    // Use carrier type information
    if (carrierInfo.type === 'wireless') {
      return 'mobile'
    } else if (carrierInfo.type === 'landline') {
      return 'landline'
    }

    // Pattern-based detection for unknown carriers
    const areaCode = phone.substring(1, 4)
    const exchange = phone.substring(4, 7)

    // Some exchanges are typically mobile
    const mobileExchanges = ['555', '666', '777', '888', '999']
    if (mobileExchanges.includes(exchange)) {
      return 'mobile'
    }

    return 'unknown'
  }

  /**
   * Check if number is VoIP
   */
  private isVoipNumber(phone: string, carrierInfo: any): boolean {
    if (!carrierInfo) return false

    const carrierName = carrierInfo.name?.toLowerCase() || ''
    return this.voipProviders.some(provider => carrierName.includes(provider))
  }

  /**
   * Get region information for area code
   */
  private getRegionInfo(areaCode: string): { region: string; timeZone: string } | null {
    return this.areaCodeRegions.get(areaCode) || null
  }

  /**
   * Check Do Not Call registry status
   */
  private async checkDncRegistry(phone: string): Promise<{
    isOnDncRegistry: boolean
    registryType?: 'federal' | 'state' | 'wireless'
    lastChecked?: string
  }> {
    // Check cache first
    const cached = this.dncCache.get(phone)
    if (cached && Date.now() - cached.timestamp < this.DNC_CACHE_TTL) {
      return {
        isOnDncRegistry: cached.isOnDnc,
        registryType: cached.isOnDnc ? 'federal' : undefined,
        lastChecked: new Date(cached.timestamp).toISOString(),
      }
    }

    try {
      // In production, this would query the actual DNC registry
      // For now, simulate the check
      const isOnDnc = await this.simulateDncCheck(phone)

      // Cache the result
      this.dncCache.set(phone, {
        isOnDnc,
        timestamp: Date.now(),
      })

      return {
        isOnDncRegistry: isOnDnc,
        registryType: isOnDnc ? 'federal' : undefined,
        lastChecked: new Date().toISOString(),
      }
    } catch (error) {
      logger.debug('PhoneValidationService', `DNC check failed for ${phone}`, error)
      return {
        isOnDncRegistry: false,
        lastChecked: new Date().toISOString(),
      }
    }
  }

  /**
   * Simulate DNC registry check (placeholder)
   */
  private async simulateDncCheck(phone: string): Promise<boolean> {
    // In production, this would make an API call to the DNC registry
    // For simulation, randomly mark some numbers as on DNC (about 10%)
    const hash = phone.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)
    return hash % 10 === 0
  }

  /**
   * Calculate phone reputation score
   */
  private calculatePhoneReputation(phone: string, carrierInfo: any, lineType: string): number {
    let score = 50 // Start with neutral score

    // Carrier reputation factors
    if (carrierInfo) {
      const majorCarriers = ['Verizon', 'AT&T', 'T-Mobile', 'Sprint']
      if (majorCarriers.includes(carrierInfo.mno)) {
        score += 20 // Major carriers get positive score
      }
    }

    // Line type factors
    switch (lineType) {
      case 'landline':
        score += 15 // Landlines generally more trustworthy
        break
      case 'mobile':
        score += 10 // Mobile numbers are common and generally OK
        break
      case 'voip':
        score -= 10 // VoIP numbers can be more suspicious
        break
    }

    // Pattern analysis
    const components = this.parsePhoneNumber(phone)

    // Sequential numbers are suspicious
    if (this.hasSequentialDigits(components.number)) {
      score -= 15
    }

    // Repeated digits are suspicious
    if (this.hasRepeatedDigits(components.number)) {
      score -= 10
    }

    return Math.min(100, Math.max(0, score))
  }

  /**
   * Calculate risk score for phone number
   */
  private calculateRiskScore(
    phone: string,
    carrierInfo: any,
    lineType: string,
    dncStatus: any
  ): number {
    let risk = 0

    // DNC status increases risk for marketing calls
    if (dncStatus.isOnDncRegistry) {
      risk += 30
    }

    // VoIP numbers have higher risk
    if (lineType === 'voip') {
      risk += 25
    }

    // Unknown carriers have higher risk
    if (!carrierInfo || carrierInfo.name === 'Unknown Carrier') {
      risk += 20
    }

    // Pattern-based risk factors
    const components = this.parsePhoneNumber(phone)

    if (this.hasSequentialDigits(components.number)) {
      risk += 15
    }

    if (this.hasRepeatedDigits(components.number)) {
      risk += 10
    }

    return Math.min(100, Math.max(0, risk))
  }

  /**
   * Detect if number has been ported
   */
  private detectPorting(phone: string, carrierInfo: any): boolean {
    // In production, this would use a porting database
    // For now, simulate based on patterns
    if (!carrierInfo) return false

    // Simplified porting detection - in reality this requires specialized databases
    const hash = phone.split('').reduce((acc, char) => acc + char.charCodeAt(0), 0)
    return hash % 5 === 0 // Simulate ~20% porting rate
  }

  /**
   * Calculate overall confidence score
   */
  private calculateConfidence(
    isValid: boolean,
    carrierInfo: any,
    lineType: string,
    reputationScore: number,
    businessLocation?: string
  ): number {
    if (!isValid) return 0

    let confidence = 50

    // Carrier information boosts confidence
    if (carrierInfo && carrierInfo.name !== 'Unknown Carrier') {
      confidence += 20
    }

    // Known line type boosts confidence
    if (lineType !== 'unknown') {
      confidence += 15
    }

    // Reputation factor
    confidence += (reputationScore - 50) * 0.3

    // Geographic consistency (if business location provided)
    if (businessLocation) {
      // This would check if phone area code matches business location
      // For now, add small boost for having location context
      confidence += 5
    }

    return Math.min(100, Math.max(0, Math.round(confidence)))
  }

  /**
   * Check for sequential digits in phone number
   */
  private hasSequentialDigits(number: string): boolean {
    for (let i = 0; i < number.length - 2; i++) {
      const digit1 = parseInt(number[i])
      const digit2 = parseInt(number[i + 1])
      const digit3 = parseInt(number[i + 2])

      if (digit2 === digit1 + 1 && digit3 === digit2 + 1) {
        return true
      }
    }
    return false
  }

  /**
   * Check for repeated digits in phone number
   */
  private hasRepeatedDigits(number: string): boolean {
    const digitCounts = new Map<string, number>()

    for (const digit of number) {
      digitCounts.set(digit, (digitCounts.get(digit) || 0) + 1)
    }

    // If any digit appears more than 3 times, consider it suspicious
    return Array.from(digitCounts.values()).some(count => count > 3)
  }

  /**
   * Clear all caches
   */
  public clearCache(): void {
    this.validationCache.clear()
    this.carrierCache.clear()
    this.dncCache.clear()
    logger.debug('PhoneValidationService', 'All caches cleared')
  }

  /**
   * Get cache statistics
   */
  public getCacheStats(): {
    validationCacheSize: number
    carrierCacheSize: number
    dncCacheSize: number
  } {
    return {
      validationCacheSize: this.validationCache.size,
      carrierCacheSize: this.carrierCache.size,
      dncCacheSize: this.dncCache.size,
    }
  }

  /**
   * Initialize carrier database (placeholder for external data)
   */
  private async initializeCarrierDatabase(): Promise<void> {
    // In production, this would load from external carrier database
    logger.debug(
      'PhoneValidationService',
      `Initialized with ${this.carrierDatabase.size} carrier entries`
    )
  }
}
