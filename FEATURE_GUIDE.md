# Business Scraper - Feature Guide

## 🎯 Smart Industry Expansion

### What It Does
Automatically converts industry categories into specific business types for targeted searching.

### How It Works
```
Input: "Professional Services"
Output: consulting, legal, accounting, financial, insurance

Input: "Healthcare & Medical"  
Output: medical, healthcare, clinic, hospital, dental
```

### Supported Industries
1. **Professional Services** → consulting, legal, accounting, financial, insurance
2. **Healthcare & Medical** → medical, healthcare, clinic, hospital, dental
3. **Restaurants & Food Service** → restaurant, cafe, food service, catering, dining
4. **Retail & Shopping** → retail, store, shop, boutique, marketplace
5. **Construction & Contractors** → construction, contractor, builder, renovation, plumbing
6. **Automotive** → automotive, car repair, auto service, mechanic, tire service
7. **Technology** → technology, IT services, software, computer repair, web design
8. **Beauty & Personal Care** → salon, spa, beauty, hair, nail salon
9. **Home Services** → cleaning, landscaping, pest control, home repair, HVAC
10. **Education** → school, tutoring, training, education, learning center
11. **Entertainment** → entertainment, event planning, photography, music, recreation

### Usage Tips
- Select industry from dropdown for automatic expansion
- Use comma-separated terms for custom searches: `plumber, electrician, carpenter`
- Use quoted phrases for exact matches: `"medical clinic", "dental office"`
- Case-insensitive matching works: `PROFESSIONAL SERVICES` = `professional services`

---

## 🏢 BBB Business Discovery

### What It Does
Scrapes Better Business Bureau profiles to extract real business websites instead of just BBB search URLs.

### How It Works
1. **Search BBB** for businesses matching your criteria
2. **Extract profiles** from BBB search results
3. **Visit each profile** to find "Visit Website" links
4. **Return real URLs** for actual business websites
5. **Filter by radius** using ZIP code geolocation

### Configuration Options
- **Search Type**: 
  - "BBB Accredited Only" - Only accredited businesses
  - "All Businesses" - All BBB-listed businesses
- **ZIP Radius**: 5-50 miles from center ZIP code
- **Rate Limiting**: Automatic 1-second delays between requests

### Anti-Bot Features
- Realistic browser fingerprinting
- Proper user agents and headers
- Rate limiting and retry logic
- Graceful error handling

### Fallback Behavior
If BBB scraping fails, returns alternative directory URLs:
- Yelp search URLs
- YellowPages search URLs  
- Google Maps search URLs

---

## 📐 ZIP Radius Validation

### What It Does
Accurately filters businesses within a specified radius using precise geolocation calculations.

### How It Works
1. **Extract ZIP codes** from business addresses
2. **Calculate distances** using Haversine formula
3. **Filter results** within specified radius
4. **Handle edge cases** gracefully

### Features
- **Precise Distance Calculation**: Uses latitude/longitude coordinates
- **ZIP Code Lookup**: API integration with fallback data
- **Address Parsing**: Extracts ZIP codes from various address formats
- **Error Handling**: Includes businesses if ZIP extraction fails

### Supported Formats
- Standard ZIP: `12345`
- ZIP+4: `12345-6789`
- Address parsing: `123 Main St, New York, NY 10001`

---

## 🔍 Multi-Strategy Search Engine

### What It Does
Combines multiple search approaches for comprehensive business discovery.

### Search Strategies
1. **DuckDuckGo SERP Scraping**: Extracts results from search engine pages
2. **BBB Business Discovery**: Real business websites from BBB profiles
3. **Instant Answer API**: Quick results for common queries
4. **Directory Fallbacks**: Yelp, YellowPages, Google Maps URLs

### Individual Criteria Processing
Each search term gets its own targeted search:
```
Input: "medical, legal, accounting"
Searches:
- "medical" in 90210
- "legal" in 90210  
- "accounting" in 90210
```

### Automatic Failover
If one search method fails, automatically tries the next:
```
DuckDuckGo SERP → BBB Discovery → Directory URLs
```

---

## 📊 Export System

### Supported Formats
- **CSV**: Universal spreadsheet format
- **XLSX**: Modern Excel format
- **XLS**: Legacy Excel format
- **ODS**: OpenDocument format
- **PDF**: Print-ready reports
- **JSON**: Structured data for APIs

### Export Features
- One-click export from results table
- Proper formatting and encoding
- Loading states and progress indication
- Error handling with user feedback

---

## 🎯 Usage Examples

### Example 1: Professional Services in NYC
```
1. Select "Professional Services" from industry dropdown
2. Enter ZIP code: 10001
3. Set radius: 25 miles
4. Choose "BBB Accredited Only"
5. Click search

Result: Individual searches for consulting, legal, accounting, 
financial, and insurance businesses within 25 miles of 10001
```

### Example 2: Custom Healthcare Search
```
1. Enter custom terms: "medical clinic", "dental office", "urgent care"
2. Enter ZIP code: 90210
3. Set radius: 15 miles
4. Choose "All Businesses"
5. Click search

Result: Exact phrase searches for each quoted term
```

### Example 3: Mixed Industry Search
```
1. Enter terms: restaurant, cafe, "fine dining"
2. Enter ZIP code: 60601
3. Set radius: 10 miles
4. Click search

Result: Individual searches for restaurant, cafe, and exact 
phrase "fine dining" within 10 miles of Chicago
```

---

## 🔧 Configuration Best Practices

### For Best Results
- **Use specific ZIP codes** rather than city names
- **Set appropriate radius** (5-15 miles for urban, 25-50 for rural)
- **Choose BBB settings** based on your quality requirements
- **Monitor search logs** to understand what's being searched

### Performance Optimization
- **Start with smaller radius** and expand if needed
- **Use fewer search terms** for faster processing
- **Enable demo mode** for testing configurations
- **Monitor rate limits** to avoid being blocked

### Troubleshooting
- **No results**: Try broader search terms or larger radius
- **Too many results**: Use more specific terms or smaller radius
- **BBB errors**: Check network connection and try again
- **Export issues**: Check browser download permissions

---

## 📈 Monitoring & Analytics

### Search Logs
Monitor the browser console to see:
- Individual search queries being executed
- BBB profile extraction progress
- ZIP radius filtering results
- Fallback strategy activation

### Performance Metrics
- Search completion time
- BBB scraping success rate
- ZIP radius filtering accuracy
- Export success rate

### Quality Indicators
- Percentage of real business websites vs directory URLs
- Geographic accuracy of results
- Industry relevance of discovered businesses
- Contact information extraction success rate
