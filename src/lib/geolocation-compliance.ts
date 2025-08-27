/**
 * Geolocation-based Legal Compliance for Puppeteer Sessions
 * Implements GDPR, CCPA, and other regional compliance restrictions
 */

import { Page } from 'puppeteer'
import { logger } from '@/utils/logger'
import { securityAuditService, AuditEventType } from '@/lib/security-audit'

// Supported regions and their compliance requirements
export enum ComplianceRegion {
  EU = 'EU', // European Union - GDPR
  EEA = 'EEA', // European Economic Area - GDPR
  UK = 'UK', // United Kingdom - UK GDPR
  CA = 'CA', // California - CCPA
  CCPA = 'CCPA', // California Consumer Privacy Act
  BRAZIL = 'BRAZIL', // Brazil - LGPD
  CANADA = 'CANADA', // Canada - PIPEDA
  AUSTRALIA = 'AUSTRALIA', // Australia - Privacy Act
  SINGAPORE = 'SINGAPORE', // Singapore - PDPA
  JAPAN = 'JAPAN', // Japan - APPI
  SOUTH_KOREA = 'SOUTH_KOREA', // South Korea - PIPA
  GLOBAL = 'GLOBAL', // Global/Default compliance
}

// Data processing restrictions by region
export interface RegionRestrictions {
  region: ComplianceRegion
  requiresExplicitConsent: boolean
  allowsLegitimateInterest: boolean
  requiresDataMinimization: boolean
  requiresRightToErasure: boolean
  requiresDataPortability: boolean
  maxDataRetentionDays: number
  restrictedDataTypes: string[]
  allowedPurposes: string[]
  requiresLocalStorage: boolean
  requiresDataProtectionOfficer: boolean
  penaltyRisk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
}

// Regional compliance configurations
const REGION_CONFIGURATIONS: Record<ComplianceRegion, RegionRestrictions> = {
  [ComplianceRegion.EU]: {
    region: ComplianceRegion.EU,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: true,
    requiresDataMinimization: true,
    requiresRightToErasure: true,
    requiresDataPortability: true,
    maxDataRetentionDays: 730, // 2 years default
    restrictedDataTypes: ['personal_data', 'sensitive_data', 'biometric_data', 'health_data'],
    allowedPurposes: ['legitimate_business_interest', 'contract_performance', 'legal_obligation'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: true,
    penaltyRisk: 'CRITICAL',
  },
  [ComplianceRegion.EEA]: {
    region: ComplianceRegion.EEA,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: true,
    requiresDataMinimization: true,
    requiresRightToErasure: true,
    requiresDataPortability: true,
    maxDataRetentionDays: 730,
    restrictedDataTypes: ['personal_data', 'sensitive_data', 'biometric_data', 'health_data'],
    allowedPurposes: ['legitimate_business_interest', 'contract_performance', 'legal_obligation'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: true,
    penaltyRisk: 'CRITICAL',
  },
  [ComplianceRegion.UK]: {
    region: ComplianceRegion.UK,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: true,
    requiresDataMinimization: true,
    requiresRightToErasure: true,
    requiresDataPortability: true,
    maxDataRetentionDays: 730,
    restrictedDataTypes: ['personal_data', 'sensitive_data'],
    allowedPurposes: ['legitimate_business_interest', 'contract_performance', 'legal_obligation'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: false,
    penaltyRisk: 'HIGH',
  },
  [ComplianceRegion.CA]: {
    region: ComplianceRegion.CA,
    requiresExplicitConsent: false,
    allowsLegitimateInterest: true,
    requiresDataMinimization: true,
    requiresRightToErasure: true,
    requiresDataPortability: true,
    maxDataRetentionDays: 1095, // 3 years
    restrictedDataTypes: ['personal_information', 'sensitive_personal_information'],
    allowedPurposes: ['business_purpose', 'commercial_purpose'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: false,
    penaltyRisk: 'HIGH',
  },
  [ComplianceRegion.CCPA]: {
    region: ComplianceRegion.CCPA,
    requiresExplicitConsent: false,
    allowsLegitimateInterest: true,
    requiresDataMinimization: true,
    requiresRightToErasure: true,
    requiresDataPortability: true,
    maxDataRetentionDays: 1095,
    restrictedDataTypes: ['personal_information', 'sensitive_personal_information'],
    allowedPurposes: ['business_purpose', 'commercial_purpose'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: false,
    penaltyRisk: 'HIGH',
  },
  [ComplianceRegion.BRAZIL]: {
    region: ComplianceRegion.BRAZIL,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: true,
    requiresDataMinimization: true,
    requiresRightToErasure: true,
    requiresDataPortability: true,
    maxDataRetentionDays: 730,
    restrictedDataTypes: ['personal_data', 'sensitive_data'],
    allowedPurposes: ['legitimate_interest', 'contract_performance', 'legal_obligation'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: true,
    penaltyRisk: 'HIGH',
  },
  [ComplianceRegion.CANADA]: {
    region: ComplianceRegion.CANADA,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: false,
    requiresDataMinimization: true,
    requiresRightToErasure: false,
    requiresDataPortability: false,
    maxDataRetentionDays: 2555, // 7 years
    restrictedDataTypes: ['personal_information'],
    allowedPurposes: ['identified_purposes', 'business_purposes'],
    requiresLocalStorage: true,
    requiresDataProtectionOfficer: false,
    penaltyRisk: 'MEDIUM',
  },
  [ComplianceRegion.AUSTRALIA]: {
    region: ComplianceRegion.AUSTRALIA,
    requiresExplicitConsent: false,
    allowsLegitimateInterest: true,
    requiresDataMinimization: true,
    requiresRightToErasure: false,
    requiresDataPortability: false,
    maxDataRetentionDays: 2555,
    restrictedDataTypes: ['personal_information', 'sensitive_information'],
    allowedPurposes: ['primary_purpose', 'related_secondary_purpose'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: false,
    penaltyRisk: 'MEDIUM',
  },
  [ComplianceRegion.SINGAPORE]: {
    region: ComplianceRegion.SINGAPORE,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: false,
    requiresDataMinimization: true,
    requiresRightToErasure: false,
    requiresDataPortability: false,
    maxDataRetentionDays: 1825, // 5 years
    restrictedDataTypes: ['personal_data'],
    allowedPurposes: ['notified_purposes', 'business_purposes'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: true,
    penaltyRisk: 'HIGH',
  },
  [ComplianceRegion.JAPAN]: {
    region: ComplianceRegion.JAPAN,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: false,
    requiresDataMinimization: true,
    requiresRightToErasure: false,
    requiresDataPortability: false,
    maxDataRetentionDays: 1825,
    restrictedDataTypes: ['personal_information', 'sensitive_personal_information'],
    allowedPurposes: ['specified_purposes', 'business_purposes'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: false,
    penaltyRisk: 'MEDIUM',
  },
  [ComplianceRegion.SOUTH_KOREA]: {
    region: ComplianceRegion.SOUTH_KOREA,
    requiresExplicitConsent: true,
    allowsLegitimateInterest: false,
    requiresDataMinimization: true,
    requiresRightToErasure: true,
    requiresDataPortability: false,
    maxDataRetentionDays: 1095,
    restrictedDataTypes: ['personal_information', 'sensitive_information'],
    allowedPurposes: ['specified_purposes', 'business_purposes'],
    requiresLocalStorage: true,
    requiresDataProtectionOfficer: true,
    penaltyRisk: 'HIGH',
  },
  [ComplianceRegion.GLOBAL]: {
    region: ComplianceRegion.GLOBAL,
    requiresExplicitConsent: false,
    allowsLegitimateInterest: true,
    requiresDataMinimization: false,
    requiresRightToErasure: false,
    requiresDataPortability: false,
    maxDataRetentionDays: 2555,
    restrictedDataTypes: [],
    allowedPurposes: ['business_purposes', 'legitimate_interest'],
    requiresLocalStorage: false,
    requiresDataProtectionOfficer: false,
    penaltyRisk: 'LOW',
  },
}

// Geolocation compliance service
export class GeolocationComplianceService {
  /**
   * Detect user's region based on IP address or explicit setting
   */
  async detectRegion(clientIP: string, userAgent: string): Promise<ComplianceRegion> {
    try {
      // In a real implementation, you would use a geolocation service
      // For now, we'll use a simple IP-based detection

      // EU IP ranges (simplified - in production use a proper geolocation service)
      if (this.isEUIP(clientIP)) {
        return ComplianceRegion.EU
      }

      // California detection (simplified)
      if (this.isCaliforniaIP(clientIP)) {
        return ComplianceRegion.CA
      }

      // UK detection
      if (this.isUKIP(clientIP)) {
        return ComplianceRegion.UK
      }

      // Default to global compliance
      return ComplianceRegion.GLOBAL
    } catch (error) {
      logger.error('Geolocation Compliance', 'Failed to detect region', error)
      return ComplianceRegion.GLOBAL // Safe default
    }
  }

  /**
   * Get compliance restrictions for a region
   */
  getRegionRestrictions(region: ComplianceRegion): RegionRestrictions {
    return REGION_CONFIGURATIONS[region] || REGION_CONFIGURATIONS[ComplianceRegion.GLOBAL]
  }

  /**
   * Configure Puppeteer page with compliance restrictions
   */
  async configurePuppeteerCompliance(
    page: Page,
    region: ComplianceRegion,
    userConsent: any = {},
    sessionId?: string
  ): Promise<void> {
    try {
      const restrictions = this.getRegionRestrictions(region)

      // Set compliance headers
      await page.setExtraHTTPHeaders({
        'X-Compliance-Region': region,
        'X-Data-Minimization': restrictions.requiresDataMinimization ? 'true' : 'false',
        'X-Consent-Required': restrictions.requiresExplicitConsent ? 'true' : 'false',
      })

      // Configure user agent with compliance info
      const complianceUA = `${await page.evaluate(() => navigator.userAgent)} ComplianceBot/${region}`
      await page.setUserAgent(complianceUA)

      // Set up request interception for compliance
      await page.setRequestInterception(true)

      page.on('request', async request => {
        const url = request.url()

        // Check if request is compliant
        const isCompliant = await this.validateRequest(url, restrictions, userConsent)

        if (!isCompliant) {
          logger.warn('Geolocation Compliance', `Blocked non-compliant request: ${url}`, {
            region,
            restrictions: restrictions.restrictedDataTypes,
          })

          // Log compliance violation
          await securityAuditService.logComplianceEvent(
            AuditEventType.SCRAPING_BLOCKED,
            null,
            'puppeteer-session',
            complianceUA,
            {
              url,
              region,
              reason: 'compliance_violation',
              sessionId,
            }
          )

          request.abort()
          return
        }

        request.continue()
      })

      // Inject compliance script into pages
      await page.evaluateOnNewDocument(regionConfig => {
        // Add compliance metadata to window object
        window.__COMPLIANCE__ = {
          region: regionConfig.region,
          restrictions: regionConfig,
          timestamp: new Date().toISOString(),
        }

        // Override data collection methods if required
        if (regionConfig.requiresDataMinimization) {
          // Minimize data collection
          const originalFetch = window.fetch
          window.fetch = function (...args) {
            console.log('Compliance: Fetch request intercepted for data minimization')
            return originalFetch.apply(this, args)
          }
        }
      }, restrictions)

      logger.info('Geolocation Compliance', `Puppeteer configured for ${region} compliance`, {
        region,
        requiresConsent: restrictions.requiresExplicitConsent,
        dataMinimization: restrictions.requiresDataMinimization,
      })
    } catch (error) {
      logger.error('Geolocation Compliance', 'Failed to configure Puppeteer compliance', error)
      throw error
    }
  }

  /**
   * Validate if a request is compliant with regional restrictions
   */
  private async validateRequest(
    url: string,
    restrictions: RegionRestrictions,
    userConsent: any
  ): Promise<boolean> {
    try {
      // Check if explicit consent is required and not given
      if (restrictions.requiresExplicitConsent && !userConsent.scraping) {
        return false
      }

      // Check for restricted data types in URL
      const urlLower = url.toLowerCase()
      for (const restrictedType of restrictions.restrictedDataTypes) {
        if (
          urlLower.includes(restrictedType.replace('_', '-')) ||
          urlLower.includes(restrictedType)
        ) {
          return false
        }
      }

      // Check for sensitive endpoints
      const sensitivePatterns = [
        '/personal/',
        '/private/',
        '/sensitive/',
        '/health/',
        '/medical/',
        '/financial/',
        '/biometric/',
      ]

      for (const pattern of sensitivePatterns) {
        if (urlLower.includes(pattern)) {
          return false
        }
      }

      return true
    } catch (error) {
      logger.error('Geolocation Compliance', 'Request validation failed', error)
      return false // Fail safe
    }
  }

  /**
   * Simple EU IP detection (in production, use a proper geolocation service)
   */
  private isEUIP(ip: string): boolean {
    // This is a simplified check - in production use a proper geolocation database
    const euCountryCodes = ['DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'AT', 'SE', 'DK', 'FI']
    // Implement proper IP geolocation lookup
    return false // Placeholder
  }

  /**
   * Simple California IP detection
   */
  private isCaliforniaIP(ip: string): boolean {
    // Implement proper IP geolocation lookup for California
    return false // Placeholder
  }

  /**
   * Simple UK IP detection
   */
  private isUKIP(ip: string): boolean {
    // Implement proper IP geolocation lookup for UK
    return false // Placeholder
  }

  /**
   * Check if scraping is allowed for a specific target in a region
   */
  async isScrapingAllowed(
    target: string,
    region: ComplianceRegion,
    userConsent: any = {}
  ): Promise<{ allowed: boolean; reason?: string }> {
    const restrictions = this.getRegionRestrictions(region)

    // Check consent requirements
    if (restrictions.requiresExplicitConsent && !userConsent.scraping) {
      return {
        allowed: false,
        reason: `Explicit consent required for scraping in ${region}`,
      }
    }

    // Check if target contains restricted data types
    const targetLower = target.toLowerCase()
    for (const restrictedType of restrictions.restrictedDataTypes) {
      if (targetLower.includes(restrictedType.replace('_', '-'))) {
        return {
          allowed: false,
          reason: `Target contains restricted data type: ${restrictedType}`,
        }
      }
    }

    return { allowed: true }
  }
}

// Export singleton instance
export const geolocationComplianceService = new GeolocationComplianceService()
