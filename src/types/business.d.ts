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
}

export interface ScrapingConfig {
  industries: string[];
  zipCode: string;
  searchRadius: number;
  searchDepth: number;
  pagesPerSite: number;
}

export interface IndustryCategory {
  id: string;
  name: string;
  keywords: string[];
  isCustom: boolean;
}