import { IndustryCategory } from '@/types/business';

/**
 * Default industry categories with associated search keywords
 * Each entry includes search terms you can use in Google, LinkedIn, Yelp, Clutch, or other directories
 * to find businesses that may need IT support.
 */
export const DEFAULT_INDUSTRIES: IndustryCategory[] = [
  {
    id: 'legal-services',
    name: 'Law Firms & Legal Services',
    keywords: [
      'law firm near me',
      'corporate law office',
      'family law services',
      'divorce lawyer',
      'legal services',
      'criminal defense attorney',
      'business attorney',
      'intellectual property lawyer'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.justia.*',
      '*.findlaw.*',
      '*.avvo.*'
    ]
  },
  {
    id: 'accounting',
    name: 'Accounting & Tax Services',
    keywords: [
      'CPA firm',
      'accounting services for businesses',
      'bookkeeping service',
      'tax advisory firms',
      'small business accountant',
      'tax preparation services',
      'financial auditing firms'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.hrblock.*',
      '*.intuit.*'
    ]
  },
  {
    id: 'architecture',
    name: 'Architectural Services',
    keywords: [
      'architectural design services',
      'architecture firm',
      'commercial architects',
      'residential architecture',
      'licensed architect',
      'building design services',
      'interior architecture'
    ],
    isCustom: false,
    domainBlacklist: []
  },
  {
    id: 'medical-clinics',
    name: 'Medical Clinics',
    keywords: [
      'primary care clinic',
      'family medical practice',
      'urgent care near me',
      'walk-in clinic',
      'internal medicine',
      'pediatric clinic',
      'healthcare provider'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.zocdoc.*',
      '*.healthgrades.*'
    ]
  },
  {
    id: 'dental',
    name: 'Dental Offices',
    keywords: [
      'dental clinic',
      'family dentist',
      'cosmetic dentistry services',
      'orthodontist near me',
      'dental implants',
      'emergency dental care',
      'pediatric dentist'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.1-800-dentist.*',
      '*.zocdoc.*'
    ]
  },
  {
    id: 'real-estate',
    name: 'Real Estate Agencies',
    keywords: [
      'real estate brokerage',
      'commercial real estate agency',
      'realtors near me',
      'residential real estate office',
      'real estate investment firm',
      'property sales agency'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.zillow.*',
      '*.realtor.*',
      '*.redfin.*'
    ]
  },
  {
    id: 'insurance',
    name: 'Insurance Agencies',
    keywords: [
      'insurance broker',
      'independent insurance agency',
      'commercial insurance providers',
      'homeowners insurance agency',
      'auto insurance agents',
      'life insurance advisors'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.statefarm.*',
      '*.progressive.*',
      '*.geico.*',
      '*.farmers.*',
      '*.nationwide.*',
      '*.travelers.*',
      '*.allstate.*'
    ]
  },
  {
    id: 'financial-advisory',
    name: 'Financial Advisory Services',
    keywords: [
      'wealth management firm',
      'financial planner near me',
      'investment advisory services',
      'fiduciary financial advisor',
      'retirement planning consultant',
      'fee-only financial planner',
      'private wealth management'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.fidelity.*',
      '*.vanguard.*'
    ]
  },
  {
    id: 'nonprofit',
    name: 'Nonprofit Organizations',
    keywords: [
      '501c3 organizations',
      'nonprofit services',
      'charity organizations near me',
      'foundation services',
      'youth nonprofit programs',
      'education-based nonprofits'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.guidestar.*'
    ]
  },
  {
    id: 'staffing',
    name: 'Staffing & Recruiting Firms',
    keywords: [
      'recruiting services',
      'staffing agency',
      'executive search firm',
      'temp agency',
      'IT staffing firm',
      'technical recruiter',
      'headhunting service'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.indeed.*',
      '*.ziprecruiter.*',
      '*.monster.*'
    ]
  },
  {
    id: 'event-services',
    name: 'Event Planning & Management',
    keywords: [
      'event planning services',
      'corporate event organizer',
      'wedding planner business',
      'party planner',
      'conference planning company',
      'event production services'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.theknot.*',
      '*.weddingwire.*'
    ]
  },
  {
    id: 'hospitality',
    name: 'Hospitality & Hotel Management',
    keywords: [
      'hotel management company',
      'hospitality services',
      'resort operations firms',
      'lodging management',
      'boutique hotel group'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.tripadvisor.*',
      '*.booking.*'
    ]
  },
  {
    id: 'engineering',
    name: 'Engineering Firms',
    keywords: [
      'mechanical engineering firm',
      'civil engineering services',
      'structural engineers near me',
      'electrical engineering consultants',
      'environmental engineering firm'
    ],
    isCustom: false,
    domainBlacklist: []
  },
  {
    id: 'education',
    name: 'Private & Charter Schools',
    keywords: [
      'private elementary school',
      'independent high school',
      'charter school near me',
      'college preparatory school',
      'Montessori academy'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.greatschools.*'
    ]
  },
  {
    id: 'marketing-agency',
    name: 'Marketing & Creative Agencies',
    keywords: [
      'digital marketing agency',
      'branding services',
      'advertising firms near me',
      'creative agency',
      'SEO marketing company',
      'content marketing agency'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.fiverr.*',
      '*.upwork.*'
    ]
  },
  {
    id: 'ecommerce',
    name: 'E-commerce Businesses',
    keywords: [
      'online clothing store',
      'DTC product brand',
      'dropshipping store',
      'e-commerce',
      'online store',
      'digital marketplace',
      'online retail',
      'shopping platform',
      'online business'
    ],
    isCustom: true,
    domainBlacklist: [
      '*.amazon.*',
      '*.etsy.*',
      '*.ebay.*'
    ]
  },
  {
    id: 'manufacturing',
    name: 'Manufacturing Companies',
    keywords: [
      'precision manufacturing',
      'industrial fabrication services',
      'OEM manufacturers',
      'custom machining',
      'contract manufacturing',
      'automated production'
    ],
    isCustom: false,
    domainBlacklist: []
  },
  {
    id: 'logistics',
    name: 'Logistics & Supply Chain',
    keywords: [
      'freight logistics provider',
      'supply chain company',
      '3PL services near me',
      'transportation logistics',
      'warehouse fulfillment service',
      'distribution center services'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.ups.*',
      '*.fedex.*'
    ]
  },
  {
    id: 'legal-saas',
    name: 'Legal Tech SaaS',
    keywords: [
      'legal software startup',
      'legal SaaS company',
      'contract automation platform',
      'compliance software',
      'case management software',
      'law practice management tools'
    ],
    isCustom: true,
    domainBlacklist: []
  },
];

/**
 * Contact page keywords for scraping
 */
export const CONTACT_KEYWORDS = [
  'contact',
  'about',
  'corporate',
  'investor',
  'team',
  'staff',
  'directory',
  'location',
  'office',
];