/**
 * Advanced Email Validation Result Interface
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
  // Advanced validation features
  smtpVerified?: boolean;
  catchAllDomain?: boolean;
  reputationScore?: number; // 0-100
  bounceRatePrediction?: number; // 0-100 (probability of bounce)
  mailServerResponse?: string;
  greylisted?: boolean;
}

/**
 * Enhanced Email Validation Metadata
 */
export interface EmailValidationMetadata {
  validationResults: EmailValidationResult[];
  overallConfidence: number;
  bestEmail?: string;
  validEmailCount: number;
  totalEmailCount: number;
  averageReputationScore?: number;
  averageBounceRate?: number;
  smtpVerifiedCount?: number;
}

/**
 * Phone Number Intelligence Result
 */
export interface PhoneValidationResult {
  originalNumber: string;
  standardizedNumber: string; // E.164 format
  isValid: boolean;
  carrier?: string;
  lineType: 'mobile' | 'landline' | 'voip' | 'unknown';
  country: string;
  region?: string;
  isPorted?: boolean;
  confidence: number; // 0-100
  validationTimestamp: string;
  // Advanced phone intelligence
  carrierDetails?: {
    name: string;
    type: 'wireless' | 'landline' | 'voip';
    mno?: string; // Mobile Network Operator
  };
  dncStatus?: {
    isOnDncRegistry: boolean;
    registryType?: 'federal' | 'state' | 'wireless';
    lastChecked?: string;
  };
  reputationScore?: number; // 0-100
  riskScore?: number; // 0-100 (higher = more risky)
  timeZone?: string;
  errors?: string[];
}

/**
 * Business Intelligence Enrichment Data
 */
export interface BusinessIntelligence {
  companySize?: {
    employeeCount?: number;
    employeeRange?: string; // e.g., "1-10", "11-50", "51-200"
    confidence: number;
    source?: string;
    lastUpdated?: string;
  };
  revenue?: {
    estimatedRevenue?: number;
    revenueRange?: string; // e.g., "$1M-$5M", "$5M-$10M"
    confidence: number;
    source?: string;
    lastUpdated?: string;
  };
  businessMaturity?: {
    yearsInBusiness?: number;
    maturityStage?: 'startup' | 'growth' | 'mature' | 'enterprise';
    confidence: number;
    indicators?: string[];
  };
  technologyStack?: {
    platforms?: TechnologyPlatform[];
    confidence: number;
    lastScanned?: string;
  };
  socialMediaPresence?: {
    profiles: SocialMediaProfile[];
    overallPresence: number; // 0-100
    engagement?: {
      totalFollowers?: number;
      averageEngagement?: number;
      lastActivity?: string;
    };
  };
}

/**
 * Technology Platform Detection
 */
export interface TechnologyPlatform {
  name: string;
  category: 'cms' | 'ecommerce' | 'analytics' | 'marketing' | 'hosting' | 'other';
  confidence: number;
  version?: string;
  indicators: string[]; // What indicated this technology
}

/**
 * Enhanced Social Media Profile
 */
export interface SocialMediaProfile {
  platform: string;
  url: string;
  handle?: string;
  verified?: boolean;
  followers?: number;
  lastActivity?: string;
  confidence: number;
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
  // Enhanced validation and enrichment data
  emailValidation?: EmailValidationMetadata;
  phoneValidation?: PhoneValidationResult;
  businessIntelligence?: BusinessIntelligence;
  dataQualityScore?: number; // 0-100 overall quality score
  enrichmentSources?: string[]; // Sources used for enrichment
  lastEnriched?: Date;
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

/**
 * Industry Sub-Category Interface
 */
export interface IndustrySubCategory {
  id: string;
  name: string;
  description?: string;
  isExpanded?: boolean; // UI state for expand/collapse
}

/**
 * Industry Category with Sub-Category Support
 */
export interface IndustryCategory {
  id: string;
  name: string;
  keywords: string[];
  isCustom: boolean;
  domainBlacklist?: string[];
  subCategoryId?: string; // Reference to sub-category
}

/**
 * Grouped Industries by Sub-Category for UI Display
 */
export interface IndustryGroup {
  subCategory: IndustrySubCategory;
  industries: IndustryCategory[];
  isSelected: boolean; // All industries in group selected
  isPartiallySelected: boolean; // Some industries in group selected
}

/**
 * Sub-Category Management Operations
 */
export interface SubCategoryOperations {
  createSubCategory: (name: string, description?: string) => Promise<IndustrySubCategory>;
  updateSubCategory: (subCategory: IndustrySubCategory) => Promise<void>;
  deleteSubCategory: (id: string) => Promise<void>;
  moveIndustryToSubCategory: (industryId: string, subCategoryId: string) => Promise<void>;
}