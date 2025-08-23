/**
 * Email validation result interface for advanced email validation
 */
export interface EmailValidationResult {
  email: string;
  isValid: boolean;
  deliverabilityScore: number; // 0-100
  isDisposable: boolean;
  isRoleBased: boolean;
  domain: string;
  mxRecords: boolean;
  confidence: number; // 0-100
  validationTimestamp?: string;
  errors?: string[];
}

/**
 * Enhanced email validation metadata
 */
export interface EmailValidationMetadata {
  validationResults: EmailValidationResult[];
  overallConfidence: number;
  bestEmail?: string;
  validEmailCount: number;
  totalEmailCount: number;
}

export interface BusinessRecord {
  id: string;
  businessName: string;
  email: string[];
  phone?: string;
  websiteUrl: string;
  address: {
    street: string;
    suite?: string;
    city: string;
    state: string;
    zipCode: string;
  };
  contactPerson?: string;
  coordinates?: {
    lat: number;
    lng: number;
  };
  industry: string;
  scrapedAt: Date;
  emailValidation?: EmailValidationMetadata;
}

export interface ScrapingConfig {
  industries: string[];
  zipCode: string;
  searchRadius: number;
  searchDepth: number;
  pagesPerSite: number;
  // Search configuration
  duckduckgoSerpPages?: number;
  maxSearchResults?: number;
  bbbAccreditedOnly?: boolean;
  zipRadius?: number;
}

export interface IndustryCategory {
  id: string;
  name: string;
  keywords: string[];
  isCustom: boolean;
  domainBlacklist?: string[];
}