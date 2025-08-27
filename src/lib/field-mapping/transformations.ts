/**
 * Data Transformation Utilities
 * Collection of reusable data transformation functions
 */

import { DataTransformation, TransformationParams } from '@/types/field-mapping'
import { BusinessRecord } from '@/types/business'

/**
 * Business-specific transformations for CRM and email marketing platforms
 */
export class BusinessDataTransformations {
  /**
   * Transform business record to CRM format
   */
  static transformToCRM(
    business: BusinessRecord,
    platform: 'salesforce' | 'hubspot' | 'pipedrive'
  ): any {
    switch (platform) {
      case 'salesforce':
        return this.transformToSalesforce(business)
      case 'hubspot':
        return this.transformToHubSpot(business)
      case 'pipedrive':
        return this.transformToPipedrive(business)
      default:
        return business
    }
  }

  /**
   * Transform to Salesforce format
   */
  private static transformToSalesforce(business: BusinessRecord): any {
    return {
      Company: business.businessName || '',
      Phone: this.formatPhone(business.phone?.[0] || ''),
      Email: business.email?.[0] || '',
      Website: business.website || '',
      BillingStreet: business.address?.street || '',
      BillingCity: business.address?.city || '',
      BillingState: business.address?.state || '',
      BillingPostalCode: business.address?.zipCode || '',
      BillingCountry: business.address?.country || 'United States',
      Industry: business.industry || '',
      Description: business.description || '',
      'Lead Source': 'Web Scraping',
      Rating: this.calculateLeadRating(business),
      'Annual Revenue': this.estimateRevenue(business),
      'Number of Employees': this.estimateEmployees(business),
    }
  }

  /**
   * Transform to HubSpot format
   */
  private static transformToHubSpot(business: BusinessRecord): any {
    return {
      'Company name': business.businessName || '',
      'Phone number': this.formatPhone(business.phone?.[0] || ''),
      'Company domain name': this.extractDomain(business.website || ''),
      'Website URL': business.website || '',
      'Street address': business.address?.street || '',
      City: business.address?.city || '',
      'State/Region': business.address?.state || '',
      'Postal code': business.address?.zipCode || '',
      Country: business.address?.country || 'United States',
      Industry: business.industry || '',
      Description: business.description || '',
      'Lead source': 'Web Scraping',
      'Lifecycle stage': 'lead',
      'Company size': this.estimateEmployees(business),
      'Annual revenue': this.estimateRevenue(business),
    }
  }

  /**
   * Transform to Pipedrive format
   */
  private static transformToPipedrive(business: BusinessRecord): any {
    return {
      'Organization name': business.businessName || '',
      Phone: this.formatPhone(business.phone?.[0] || ''),
      Email: business.email?.[0] || '',
      Website: business.website || '',
      Address: this.formatFullAddress(business.address),
      Industry: business.industry || '',
      Notes: business.description || '',
      Label: 'Web Scraped Lead',
      Owner: 'Admin',
      'Visible to': 'Everyone',
    }
  }

  /**
   * Transform business record to email marketing format
   */
  static transformToEmailMarketing(
    business: BusinessRecord,
    platform: 'mailchimp' | 'constant-contact'
  ): any {
    switch (platform) {
      case 'mailchimp':
        return this.transformToMailchimp(business)
      case 'constant-contact':
        return this.transformToConstantContact(business)
      default:
        return business
    }
  }

  /**
   * Transform to Mailchimp format
   */
  private static transformToMailchimp(business: BusinessRecord): any {
    const email = business.email?.[0] || ''
    const name = business.businessName || ''

    // Split business name into first/last name for contact
    const nameParts = name.split(' ')
    const firstName = nameParts[0] || ''
    const lastName = nameParts.slice(1).join(' ') || ''

    return {
      'Email Address': email,
      'First Name': firstName,
      'Last Name': lastName,
      Company: name,
      Phone: this.formatPhone(business.phone?.[0] || ''),
      Address: business.address?.street || '',
      City: business.address?.city || '',
      State: business.address?.state || '',
      Zip: business.address?.zipCode || '',
      Country: business.address?.country || 'US',
      Website: business.website || '',
      Industry: business.industry || '',
      Tags: this.generateTags(business).join(','),
      'GDPR Permission': 'No', // Default to no, must be explicitly set
      Source: 'Web Scraping',
    }
  }

  /**
   * Transform to Constant Contact format
   */
  private static transformToConstantContact(business: BusinessRecord): any {
    const email = business.email?.[0] || ''
    const name = business.businessName || ''

    // Split business name into first/last name for contact
    const nameParts = name.split(' ')
    const firstName = nameParts[0] || ''
    const lastName = nameParts.slice(1).join(' ') || ''

    return {
      Email: email,
      'First Name': firstName,
      'Last Name': lastName,
      'Company Name': name,
      'Work Phone': this.formatPhone(business.phone?.[0] || ''),
      'Home Street Address': business.address?.street || '',
      'Home City': business.address?.city || '',
      'Home State': business.address?.state || '',
      'Home Zip': business.address?.zipCode || '',
      'Home Country': business.address?.country || 'United States',
      Website: business.website || '',
      'Custom Field 1': business.industry || '',
      'Custom Field 2': business.description || '',
      'Opt-in Source': 'Web Scraping',
      'Permission to Email': 'No', // Default to no, must be explicitly set
    }
  }

  /**
   * Format phone number to standard format
   */
  private static formatPhone(phone: string): string {
    if (!phone) return ''

    const digits = phone.replace(/\D/g, '')

    if (digits.length === 10) {
      return `(${digits.substr(0, 3)}) ${digits.substr(3, 3)}-${digits.substr(6, 4)}`
    } else if (digits.length === 11 && digits.startsWith('1')) {
      return `+1 (${digits.substr(1, 3)}) ${digits.substr(4, 3)}-${digits.substr(7, 4)}`
    }

    return phone // Return original if can't format
  }

  /**
   * Extract domain from URL
   */
  private static extractDomain(url: string): string {
    if (!url) return ''

    try {
      if (url.includes('://')) {
        return new URL(url).hostname.replace('www.', '')
      } else {
        return url.replace('www.', '')
      }
    } catch {
      return url.replace('www.', '')
    }
  }

  /**
   * Format full address
   */
  private static formatFullAddress(address?: BusinessRecord['address']): string {
    if (!address) return ''

    const parts = [address.street, address.city, address.state, address.zipCode].filter(Boolean)

    return parts.join(', ')
  }

  /**
   * Calculate lead rating based on available data
   */
  private static calculateLeadRating(business: BusinessRecord): string {
    let score = 0

    if (business.email?.length) score += 2
    if (business.phone?.length) score += 2
    if (business.website) score += 2
    if (business.address?.street) score += 1
    if (business.description) score += 1
    if (business.industry) score += 1

    if (score >= 7) return 'Hot'
    if (score >= 5) return 'Warm'
    if (score >= 3) return 'Cold'
    return 'Unqualified'
  }

  /**
   * Estimate company revenue based on available data
   */
  private static estimateRevenue(business: BusinessRecord): string {
    // Simple heuristic based on website presence and contact info completeness
    const hasWebsite = !!business.website
    const hasMultipleContacts = (business.email?.length || 0) + (business.phone?.length || 0) > 2
    const hasCompleteAddress = !!(
      business.address?.street &&
      business.address?.city &&
      business.address?.state
    )

    if (hasWebsite && hasMultipleContacts && hasCompleteAddress) {
      return '$1M - $5M'
    } else if (hasWebsite && (hasMultipleContacts || hasCompleteAddress)) {
      return '$500K - $1M'
    } else if (hasWebsite) {
      return '$100K - $500K'
    }

    return 'Unknown'
  }

  /**
   * Estimate number of employees
   */
  private static estimateEmployees(business: BusinessRecord): string {
    // Simple heuristic based on available data richness
    const dataPoints = [
      business.email?.length || 0,
      business.phone?.length || 0,
      business.website ? 1 : 0,
      business.address?.street ? 1 : 0,
      business.description ? 1 : 0,
    ].reduce((sum, val) => sum + val, 0)

    if (dataPoints >= 6) return '11-50'
    if (dataPoints >= 4) return '2-10'
    return '1'
  }

  /**
   * Generate tags for email marketing
   */
  private static generateTags(business: BusinessRecord): string[] {
    const tags: string[] = ['web-scraped']

    if (business.industry) {
      tags.push(business.industry.toLowerCase().replace(/\s+/g, '-'))
    }

    if (business.address?.state) {
      tags.push(business.address.state.toLowerCase())
    }

    if (business.website) {
      tags.push('has-website')
    }

    if (business.email?.length) {
      tags.push('has-email')
    }

    if (business.phone?.length) {
      tags.push('has-phone')
    }

    return tags
  }
}

/**
 * Create transformation functions for the mapping engine
 */
export function createBusinessTransformations(): DataTransformation[] {
  return [
    {
      id: 'business_to_salesforce',
      name: 'Business to Salesforce',
      description: 'Transform business record to Salesforce format',
      inputTypes: ['object'],
      outputType: 'object',
      transform: (input: BusinessRecord) =>
        BusinessDataTransformations.transformToCRM(input, 'salesforce'),
    },
    {
      id: 'business_to_hubspot',
      name: 'Business to HubSpot',
      description: 'Transform business record to HubSpot format',
      inputTypes: ['object'],
      outputType: 'object',
      transform: (input: BusinessRecord) =>
        BusinessDataTransformations.transformToCRM(input, 'hubspot'),
    },
    {
      id: 'business_to_pipedrive',
      name: 'Business to Pipedrive',
      description: 'Transform business record to Pipedrive format',
      inputTypes: ['object'],
      outputType: 'object',
      transform: (input: BusinessRecord) =>
        BusinessDataTransformations.transformToCRM(input, 'pipedrive'),
    },
    {
      id: 'business_to_mailchimp',
      name: 'Business to Mailchimp',
      description: 'Transform business record to Mailchimp format',
      inputTypes: ['object'],
      outputType: 'object',
      transform: (input: BusinessRecord) =>
        BusinessDataTransformations.transformToEmailMarketing(input, 'mailchimp'),
    },
    {
      id: 'business_to_constant_contact',
      name: 'Business to Constant Contact',
      description: 'Transform business record to Constant Contact format',
      inputTypes: ['object'],
      outputType: 'object',
      transform: (input: BusinessRecord) =>
        BusinessDataTransformations.transformToEmailMarketing(input, 'constant-contact'),
    },
  ]
}
