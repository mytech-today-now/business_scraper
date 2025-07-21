import { IndustryCategory } from '@/types/business';

/**
 * Default industry categories with associated search keywords
 */
export const DEFAULT_INDUSTRIES: IndustryCategory[] = [
  {
    id: 'restaurants',
    name: 'Restaurants & Food Service',
    keywords: ['restaurant', 'cafe', 'food service', 'catering', 'dining'],
    isCustom: false,
  },
  {
    id: 'retail',
    name: 'Retail & Shopping',
    keywords: ['retail', 'store', 'shop', 'boutique', 'marketplace'],
    isCustom: false,
  },
  {
    id: 'healthcare',
    name: 'Healthcare & Medical',
    keywords: ['medical', 'healthcare', 'clinic', 'hospital', 'dental'],
    isCustom: false,
  },
  {
    id: 'professional',
    name: 'Professional Services',
    keywords: ['consulting', 'legal', 'accounting', 'financial', 'insurance'],
    isCustom: false,
  },
  {
    id: 'construction',
    name: 'Construction & Contractors',
    keywords: ['construction', 'contractor', 'builder', 'renovation', 'plumbing'],
    isCustom: false,
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