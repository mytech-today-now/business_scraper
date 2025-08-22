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
      'attorney office',
      'legal services',
      'lawyer near me',
      'corporate law firm',
      'family law attorney',
      'divorce lawyer',
      'criminal defense attorney',
      'business lawyer',
      'intellectual property attorney',
      'real estate lawyer',
      'personal injury attorney',
      'estate planning lawyer',
      'civil litigation attorney',
      'immigration lawyer',
      'bankruptcy attorney'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.justia.*',
      '*.findlaw.*',
      '*.avvo.*',
      '*.nolo.*',
      '*.superlawyers.*'
    ]
  },
  {
    id: 'accounting',
    name: 'Accounting & Tax Services',
    keywords: [
      'CPA firm near me',
      'accounting services',
      'tax preparation services',
      'bookkeeping services',
      'certified public accountant',
      'small business accountant',
      'tax advisor',
      'payroll services',
      'financial consulting',
      'business accounting firm',
      'tax return preparation',
      'QuickBooks accounting services',
      'audit services',
      'financial auditing firm'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.hrblock.*',
      '*.intuit.*',
      '*.turbotax.*',
      '*.libertytax.*'
    ]
  },
  {
    id: 'architecture',
    name: 'Architectural Services',
    keywords: [
      'architect near me',
      'architectural firm',
      'building design services',
      'residential architect',
      'commercial architecture firm',
      'architectural design services',
      'licensed architect',
      'sustainable design architect',
      'interior architecture',
      'landscape architect',
      'custom home architect',
      'building renovation architect',
      'urban design studio'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.archdaily.*',
      '*.houzz.*'
    ]
  },
  {
    id: 'medical-clinics',
    name: 'Medical Clinics',
    keywords: [
      'medical clinic near me',
      'primary care doctor',
      'family medical practice',
      'urgent care center',
      'walk-in clinic',
      'internal medicine clinic',
      'pediatric clinic',
      'family doctor',
      'healthcare provider',
      'medical center',
      'women\'s health clinic',
      'telehealth services',
      'medical practice'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.zocdoc.*',
      '*.healthgrades.*',
      '*.webmd.*',
      '*.doctolib.*'
    ]
  },
  {
    id: 'dental',
    name: 'Dental Offices',
    keywords: [
      'dentist near me',
      'dental office',
      'family dentist',
      'dental clinic',
      'cosmetic dentistry',
      'orthodontist near me',
      'dental implants',
      'emergency dental care',
      'pediatric dentist',
      'teeth whitening',
      'oral surgeon',
      'dental practice',
      'general dentistry'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.1-800-dentist.*',
      '*.zocdoc.*',
      '*.healthgrades.*'
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
      'property sales agency',
      'property management company',
      'luxury real estate agent'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.zillow.*',
      '*.realtor.*',
      '*.redfin.*',
      '*.trulia.*',
      '*.homes.*'
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
      'life insurance advisors',
      'business insurance consultant'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.statefarm.*',
      '*.progressive.*',
      '*.geico.*',
      '*.farmers.*',
      '*.nationwide.*',
      '*.travelers.*',
      '*.allstate.*',
      '*.esurance.*'
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
      'private wealth management',
      'financial consulting firm'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.fidelity.*',
      '*.vanguard.*',
      '*.charlesschwab.*',
      '*.merrilledge.*'
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
      'education-based nonprofits',
      'grant-funded organization'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.guidestar.*',
      '*.charitynavigator.*'
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
      'headhunting service',
      'staff augmentation company'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.indeed.*',
      '*.ziprecruiter.*',
      '*.monster.*',
      '*.glassdoor.*',
      '*.linkedin.*'
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
      'event production services',
      'nonprofit event organizer'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.theknot.*',
      '*.weddingwire.*',
      '*.eventbrite.*'
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
      'boutique hotel group',
      'hospitality consulting firms',
      'meeting and convention services'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.tripadvisor.*',
      '*.booking.*',
      '*.expedia.*',
      '*.hotels.*',
      '*.airbnb.*'
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
      'environmental engineering firm',
      'geotechnical services',
      'engineering project consultants'
    ],
    isCustom: false,
    domainBlacklist: []
  },
  {
    id: 'education',
    name: 'Private & Charter Schools',
    keywords: [
      'private school',
      'charter school',
      'independent school',
      'Montessori school',
      'Catholic school',
      'Christian school',
      'preparatory academy',
      'private academy'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.greatschools.*',
      '*.niche.*',
      '*.prepscholar.*',
      '*.schooldigger.*',
      '*.publicschoolreview.*',
      '*.usnews.*',
      '*.ed.gov',
      '*.state.*.us',
      '*.gov',
      '*.edu',
      '*.nces.ed.gov',
      '*.doe.*',
      '*.dph.*',
      '*.yelp.*',
      '*.yellowpages.*',
      '*.superpages.*',
      '*.whitepages.*'
    ]
  },
  {
    id: 'marketing-agency',
    name: 'Marketing & Creative Agencies',
    keywords: [
      'digital marketing agency',
      'marketing agency near me',
      'SEO company',
      'social media marketing',
      'advertising agency',
      'branding agency',
      'creative agency',
      'content marketing agency',
      'PPC advertising agency',
      'email marketing services',
      'web design agency',
      'graphic design services',
      'marketing consultants'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.fiverr.*',
      '*.upwork.*',
      '*.peopleperhour.*',
      '*.freelancer.*'
    ]
  },
  {
    id: 'ecommerce',
    name: 'E-commerce Businesses',
    keywords: [
      'online store',
      'e-commerce business',
      'online retail store',
      'dropshipping business',
      'online clothing store',
      'digital marketplace',
      'online shop',
      'e-commerce website',
      'online boutique',
      'internet retail',
      'web store',
      'online merchant',
      'direct to consumer brand',
      'online sales'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.amazon.*',
      '*.etsy.*',
      '*.ebay.*',
      '*.shopify.*'
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
      'automated production',
      'industrial equipment manufacturers'
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
      'distribution center services',
      'freight forwarding firm'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.ups.*',
      '*.fedex.*',
      '*.dhl.*'
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
      'law practice management tools',
      'legal workflow automation'
    ],
    isCustom: true,
    domainBlacklist: [
      '*.clio.*',
      '*.mycase.*',
      '*.practicepanther.*'
    ]
  },
  {
    id: 'pets',
    name: 'Pet Services',
    keywords: [
      'pet grooming near me',
      'dog groomer',
      'veterinary clinic',
      'animal hospital',
      'pet boarding near me',
      'dog daycare',
      'pet sitting services',
      'dog walker near me',
      'pet training services',
      'mobile pet grooming',
      'cat grooming',
      'pet spa',
      'dog training classes',
      'pet supplies store',
      'veterinarian near me'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.petco.*',
      '*.petsmart.*',
      '*.chewy.*'
    ]
  },
  {
    id: 'home-lifestyle-services',
    name: 'Home & Lifestyle Services',
    keywords: [
      'house cleaning service near me',
      'maid service',
      'lawn care service',
      'landscaping company near me',
      'handyman near me',
      'home repair contractor',
      'plumber near me',
      'electrician near me',
      'HVAC repair service',
      'carpet cleaning service',
      'window cleaning service',
      'gutter cleaning service',
      'pool maintenance service',
      'pest control service',
      'home security installation',
      'interior decorator near me',
      'personal chef service',
      'dog walker',
      'babysitter near me',
      'elderly care service',
      'home improvement contractor',
      'pressure washing service'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.angi.*',
      '*.homeadvisor.*',
      '*.thumbtack.*',
      '*.taskrabbit.*',
      '*.care.*',
      '*.sittercity.*',
      '*.rover.*',
      '*.wag.*',
      '*.handy.*',
      '*.porch.*',
      '*.houzz.*',
      '*.yelp.*',
      '*.google.*',
      '*.facebook.*'
    ]
  },
  {
    id: 'personal-health-wellness',
    name: 'Personal Health & Wellness',
    keywords: [
      'personal trainer near me',
      'yoga studio near me',
      'pilates classes near me',
      'massage therapist near me',
      'chiropractor near me',
      'acupuncture clinic',
      'physical therapy near me',
      'nutritionist near me',
      'weight loss clinic',
      'meditation center',
      'spa near me',
      'hair salon near me',
      'nail salon near me',
      'beauty salon',
      'barber shop near me',
      'tattoo shop near me',
      'piercing studio',
      'wellness center',
      'fitness gym near me',
      'crossfit gym',
      'martial arts classes',
      'dance studio near me',
      'life coach',
      'counseling services',
      'fitness center'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.classpass.*',
      '*.mindbody.*',
      '*.groupon.*',
      '*.livingwell.*',
      '*.webmd.*',
      '*.healthline.*',
      '*.mayoclinic.*',
      '*.psychology.*',
      '*.betterhelp.*',
      '*.talkspace.*',
      '*.zocdoc.*',
      '*.healthgrades.*',
      '*.vitals.*',
      '*.ratemds.*',
      '*.yelp.*',
      '*.google.*'
    ]
  },
  {
    id: 'entertainment-recreation',
    name: 'Entertainment & Recreation',
    keywords: [
      'movie theater near me',
      'bowling alley near me',
      'arcade near me',
      'mini golf near me',
      'escape room near me',
      'laser tag near me',
      'paintball near me',
      'go kart racing',
      'trampoline park near me',
      'amusement park',
      'water park',
      'ice skating rink',
      'roller skating rink',
      'rock climbing gym',
      'karaoke bar near me',
      'comedy club near me',
      'live music venue',
      'concert hall',
      'art gallery near me',
      'museum near me',
      'zoo near me',
      'aquarium',
      'theme restaurant',
      'sports bar near me',
      'pool hall near me',
      'casino near me',
      'bingo hall',
      'entertainment center'
    ],
    isCustom: false,
    domainBlacklist: [
      '*.fandango.*',
      '*.movietickets.*',
      '*.ticketmaster.*',
      '*.stubhub.*',
      '*.eventbrite.*',
      '*.groupon.*',
      '*.tripadvisor.*',
      '*.foursquare.*',
      '*.yelp.*',
      '*.google.*',
      '*.facebook.*',
      '*.timeout.*',
      '*.expedia.*',
      '*.booking.*',
      '*.opentable.*'
    ]
  },
];

/**
 * Contact page keywords for scraping
 */
export const CONTACT_KEYWORDS = [
  'contact',
  'about us',
  'corporate',
  'investor',
  'team',
  'staff',
  'directory',
  'location',
  'office',
];