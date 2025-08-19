# Business Scraper App

A comprehensive full-stack business web scraping application built with Next.js, React, TypeScript, and Puppeteer. This application enables intelligent business discovery and contact information extraction through advanced search strategies and real-time web scraping.

## 🚀 Features

### Core Functionality

- **🎯 Smart Industry Expansion**: Automatically expands industry categories into specific business types (e.g., "Professional Services" → consulting, legal, accounting, financial, insurance)
- **🌐 Multi-Strategy Search Engine**: DuckDuckGo SERP scraping, BBB business discovery, and instant answer API integration
- **📍 Intelligent Location Filtering**: ZIP code-based search with precise radius validation using geolocation services
- **🤖 Advanced Web Scraping**: Puppeteer-powered extraction with anti-bot countermeasures and rate limiting
- **📊 Multi-format Export**: Export data in CSV, XLSX, XLS, ODS, PDF, and JSON formats
- **📈 Real-time Progress Tracking**: Monitor scraping progress with detailed statistics and error reporting

### Advanced Search Capabilities

- **🔍 Individual Criteria Parsing**: Processes comma-separated and quoted search terms individually for higher precision
- **🏢 BBB Business Discovery**: Real-time scraping of Better Business Bureau for verified business websites
- **📐 ZIP Radius Validation**: Accurate distance calculation with fallback geolocation data
- **🔄 Fallback Search Strategies**: Multiple search providers with automatic failover
- **⚡ Optimized Query Processing**: Industry-specific templates and synonym expansion with targeted keyword searches
- **🔗 Azure AI Foundry Integration**: Modern "Grounding with Bing Custom Search" API support
- **🛡️ Enhanced Result Filtering**: Automatic rejection of government offices, educational databases, and directory listings
- **🚫 Advanced Domain Filtering**:
  - **Global Blacklist**: Filter out unwanted domains from all searches
  - **Per-Industry Blacklist**: Configure domain filtering specific to each industry category
  - **Government/Educational Site Detection**: Automatic filtering of *.gov, *.edu, and department sites
  - **Directory Site Filtering**: Blocks Yelp, Yellow Pages, and other listing sites for direct business results
  - **Wildcard Support**: Use patterns like `*.domain.com`, `domain.*`, `*keyword*`
  - **Theme-Aware Interface**: Text areas automatically adapt to light/dark mode

### Technical Features

- **📱 Responsive Design**: Works seamlessly on desktop and mobile devices
- **🌙 Dark Mode Support**: Toggle between light and dark themes
- **💾 Offline Capability**: IndexedDB storage for offline data persistence
- **🛡️ Comprehensive Error Handling**: Graceful degradation and detailed error logging
- **✅ Data Validation**: Input sanitization and business data integrity checks
- **🚀 Performance Optimized**: Lazy loading, caching, and efficient data processing

### Performance & Scalability

- **⚡ 3x Faster Processing**: Enhanced concurrent operations with 8 parallel jobs (up from 3)
- **🔄 Multi-Level Caching**: L1 (Memory), L2 (Redis), L3 (Disk) intelligent caching strategy
- **🌊 Real-Time Streaming**: Live search results via Server-Sent Events with progress tracking
- **💾 Memory-Efficient Exports**: Stream large datasets without memory constraints
- **🔧 Advanced Browser Pool**: 6 optimized browsers with health monitoring and auto-restart
- **📊 Performance Monitoring**: Real-time metrics for browser health, cache hit rates, and throughput
- **🎯 Intelligent Cache Warming**: Proactive cache population with popular queries and high-value data
- **⏱️ 50% Faster Response Times**: Optimized timeouts, retries, and resource management

### Advanced Anti-Detection & Security

- **🔄 Network Spoofing Service**: Comprehensive IP address and MAC address spoofing system
  - **IP Address Rotation**: Generates random IP addresses from realistic ranges (private and public)
  - **MAC Address Spoofing**: Creates authentic MAC addresses using known vendor prefixes (Dell, VMware, VirtualBox)
  - **Browser Fingerprint Spoofing**: Modifies WebGL, Canvas, and Audio Context fingerprints
  - **User Agent Rotation**: Cycles through realistic browser user agents and timezone settings
- **⚡ Advanced Rate Limiting Service**: Provider-specific intelligent rate limiting
  - **DuckDuckGo**: 1 req/min, 45s minimum delay, exponential backoff
  - **Google**: 5 req/min, 12s minimum delay
  - **Bing**: 10 req/min, 6s minimum delay
  - **BBB**: 3 req/min, 20s minimum delay
  - **Yelp**: 5 req/min, 12s minimum delay
  - **Request History Tracking**: Failure detection and sliding window rate limiting
- **🛡️ Enhanced Anti-Detection Measures**: Production-grade bot protection
  - **Request Interception**: Human-like delays and realistic browsing patterns
  - **Tracking Script Blocking**: Blocks Google Analytics, Facebook, and other tracking scripts
  - **Automation Property Removal**: Removes browser automation indicators
  - **Enhanced Stealth Mode**: Advanced Puppeteer stealth configuration

### Production Infrastructure

- **🐳 Docker Deployment**: Complete containerized production environment
- **🗄️ PostgreSQL Database**: Persistent data storage with encrypted connections
- **🔴 Redis Cache**: Session management and performance optimization
- **📊 Health Monitoring**: Comprehensive system health checks and logging
- **🔒 Security Features**: Rate limiting, security headers, and encrypted communications

## 🏗️ Architecture

The application follows an **Adapted MVC (Model-View-Controller)** pattern with modern Next.js architecture:

### Model Layer (`src/model/`)

- **clientSearchEngine.ts**: Multi-strategy search orchestration with industry expansion
- **clientScraperService.ts**: Client-side scraping coordination and API management
- **scraperService.ts**: Core web scraping functionality using Puppeteer
- **searchEngine.ts**: Advanced search engine with optimization and validation
- **queryOptimizer.ts**: Industry-specific query templates and synonym expansion
- **storage.ts**: IndexedDB operations for data persistence

### API Layer (`src/app/api/`)

- **search/route.ts**: Search API with BBB discovery and DuckDuckGo SERP scraping
- **scrape/route.ts**: Web scraping API endpoints
- **stream-search/route.ts**: Real-time streaming search with Server-Sent Events
- **stream-export/route.ts**: Memory-efficient streaming export for large datasets
- **data-management/route.ts**: Data validation and management operations
- **config/route.ts**: Configuration management and health checks
- **auth/route.ts**: Session management and authentication

### View Layer (`src/view/`)

- **App.tsx**: Main application component with export functionality
- **ApiConfigurationPage.tsx**: Comprehensive API and BBB configuration interface
- **CategorySelector.tsx**: Industry category selection with smart expansion
- **ResultsTable.tsx**: Interactive data table with sorting and filtering
- **UI Components**: Reusable UI components (Button, Input, Card, etc.)

### Controller Layer (`src/controller/`)

- **ConfigContext.tsx**: Global configuration state management
- **useScraperController.ts**: Advanced scraping workflow orchestration

### Services & Libraries (`src/lib/`)

- **bbbScrapingService.ts**: Dedicated BBB scraping with Puppeteer and rate limiting
- **zipCodeService.ts**: Geolocation services with distance calculation
- **enhancedScrapingEngine.ts**: Advanced scraping with job queues and retry logic
- **dataValidationPipeline.ts**: Comprehensive business data validation
- **industry-config.ts**: Industry category definitions and keyword mappings
- **networkSpoofingService.ts**: Network spoofing and anti-detection system
- **rateLimitingService.ts**: Provider-specific intelligent rate limiting
- **antiBotBypass.ts**: Enhanced anti-bot countermeasures
- **browserPool.ts**: Browser instance management with spoofing integration

### Database & Cache Layer

- **PostgreSQL Database**: Production-grade persistent storage
  - Business data storage and retrieval
  - Configuration management
  - Search history and analytics
- **Redis Cache**: High-performance caching and session management
  - Search result caching
  - Rate limiting state management
  - Session storage and user preferences

### Security & Monitoring Services

- **Health Monitoring**: Comprehensive system health checks
- **Security Headers**: CSP, HSTS, and other security configurations
- **Rate Limiting**: Global and provider-specific request throttling
- **Logging System**: Structured logging with request correlation IDs

### Utilities (`src/utils/`)

- **logger.ts**: Structured logging system with multiple levels
- **formatters.ts**: Data formatting utilities for export
- **exportService.ts**: Multi-format data export (CSV, XLSX, PDF, JSON)
- **validation.ts**: Input validation and sanitization
- **secureStorage.ts**: Encrypted credential storage

## 📋 Prerequisites

### Development Environment
- Node.js 18+
- npm or yarn
- Modern web browser with JavaScript enabled

### Production Environment
- Docker and Docker Compose
- PostgreSQL 16+ (for production deployment)
- Redis 7+ (for caching and session management)
- 2GB+ RAM recommended for production deployment

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd business-scraper-app
   ```

2. **Install dependencies**
   ```bash
   npm install
   # or
   yarn install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env.local
   ```
   
   Edit `.env.local` and configure the following optional API keys:
   ```env
   # Optional: For enhanced geocoding
   GOOGLE_MAPS_API_KEY=your_google_maps_api_key
   OPENCAGE_API_KEY=your_opencage_api_key

   # Optional: For enhanced search capabilities
   GOOGLE_SEARCH_API_KEY=your_google_search_api_key
   GOOGLE_SEARCH_ENGINE_ID=your_google_search_engine_id

   # Azure AI Foundry - Grounding with Bing Custom Search (NEW - replaces deprecated Bing API)
   AZURE_AI_FOUNDRY_API_KEY=your_azure_ai_foundry_api_key
   AZURE_AI_FOUNDRY_ENDPOINT=https://businessscraper.cognitiveservices.azure.com/
   AZURE_AI_FOUNDRY_REGION=eastus

   # Network Spoofing & Anti-Detection (v1.4.0+)
   ENABLE_NETWORK_SPOOFING=true
   ENABLE_IP_SPOOFING=true
   ENABLE_MAC_ADDRESS_SPOOFING=true
   ENABLE_FINGERPRINT_SPOOFING=true
   REQUEST_DELAY_MIN=2000
   REQUEST_DELAY_MAX=8000

   # Production Database & Cache (for Docker deployment)
   DATABASE_URL=postgresql://username:password@localhost:5432/business_scraper
   REDIS_URL=redis://localhost:6379
   ENABLE_REAL_SCRAPING=true

   # Legacy APIs
   YANDEX_SEARCH_API_KEY=your_yandex_search_api_key
   ```

   > **⚠️ Important**: The Bing Search API is being discontinued in August 2025. Use Azure AI Foundry instead. See [AZURE_AI_FOUNDRY_MIGRATION.md](./AZURE_AI_FOUNDRY_MIGRATION.md) for migration instructions.

4. **Run the development server**
   ```bash
   npm run dev
   # or
   yarn dev
   ```

5. **Open your browser**
   Navigate to [http://localhost:3000](http://localhost:3000)

## 🎯 Usage

### 1. Configuration

1. **API Configuration**: Navigate to the API Configuration page to set up:
   - **BBB Search Settings**: Choose "Accredited Only" vs "All Businesses"
   - **ZIP Radius**: Set search radius from 5-50 miles
   - **Search Parameters**: Configure SERP pages and max results
   - **API Credentials**: Configure Google Custom Search and Azure AI Foundry APIs

2. **Industry Selection**:
   - Choose from predefined categories (automatically expands to specific business types)
   - Example: "Professional Services" → consulting, legal, accounting, financial, insurance
   - Add custom industries with comma-separated keywords
   - Use quoted phrases for exact matches: "medical clinic", "dental office"

3. **Location Setup**: Enter ZIP code for precise geolocation-based filtering

### 2. Advanced Search Process

1. **Smart Industry Expansion**: System automatically converts industry categories into specific search terms
2. **Multi-Strategy Search**: Combines DuckDuckGo SERP scraping with BBB business discovery
3. **Individual Criteria Processing**: Each keyword gets its own targeted search
4. **Real-time Progress**: Monitor individual searches and BBB profile extractions
5. **Fallback Handling**: Automatic failover to alternative search methods

### 3. BBB Business Discovery

1. **Automated BBB Scraping**: Uses Puppeteer to extract real business websites from BBB profiles
2. **Anti-Bot Countermeasures**: Realistic browser fingerprinting and rate limiting
3. **Website Extraction**: Finds "Visit Website" links from BBB business profiles
4. **ZIP Radius Filtering**: Validates business locations against specified radius
5. **Graceful Fallbacks**: Returns directory search URLs if BBB scraping fails

### 4. Data Management

1. **View Results**: Browse scraped data in the interactive table with real business websites
2. **Edit Data**: Click on cells to edit business information
3. **Filter & Sort**: Use built-in filtering and sorting options
4. **Export Data**: Download results in your preferred format with one-click export

### 4. Data Export Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| CSV | Comma-separated values | Universal spreadsheet import |
| XLSX | Modern Excel format | Advanced Excel features |
| XLS | Legacy Excel format | Older Excel versions |
| ODS | OpenDocument format | LibreOffice/OpenOffice |
| PDF | Print-ready document | Reports and presentations |
| JSON | Structured data | API integration |

## 🧪 Testing

Run the test suite:
```bash
npm test
# or
yarn test
```

Run tests in watch mode:
```bash
npm run test:watch
# or
yarn test:watch
```

Generate coverage report:
```bash
npm run test:coverage
# or
yarn test:coverage
```

## 📚 API Documentation

Generate API documentation:
```bash
npm run docs
# or
yarn docs
```

The documentation will be generated in the `docs/` directory.

## 🔧 Configuration Options

### BBB Search Configuration

- **Search Type**: Choose between "BBB Accredited Only" or "All Businesses"
- **ZIP Radius**: 5-50 miles from center ZIP code with precise geolocation validation
- **Rate Limiting**: Automatic 1-second delays between BBB requests
- **Retry Logic**: Up to 3 attempts with exponential backoff
- **Browser Settings**: Stealth mode with realistic user agents and headers

### Search Engine Configuration

- **SERP Pages**: 1-5 pages of search results to process
- **Max Results**: 10-100 maximum results per search
- **Search Strategies**: DuckDuckGo SERP, BBB Discovery, Instant Answer API
- **Fallback Behavior**: Automatic failover between search providers
- **Industry Expansion**: Smart conversion of categories to specific keywords

### Scraping Configuration

- **Search Depth**: 1-5 levels deep per website
- **Pages per Site**: 1-20 pages maximum per website
- **Timeout**: Configurable request timeout (default: 30 seconds)
- **Concurrent Processing**: Parallel processing with configurable batch sizes
- **Memory Management**: Automatic cleanup and resource optimization

### Network Spoofing & Anti-Detection

- **IP Address Spoofing**: Random IP generation from realistic ranges
- **MAC Address Spoofing**: Authentic MAC addresses from known vendors (Dell, VMware, VirtualBox)
- **Browser Fingerprint Spoofing**: WebGL, Canvas, and Audio Context modification
- **User Agent Rotation**: Realistic browser user agents and timezone settings
- **Request Interception**: Human-like delays and browsing patterns
- **Tracking Script Blocking**: Blocks Google Analytics, Facebook, and other trackers

### Advanced Rate Limiting

- **Provider-Specific Limits**: Intelligent rate limiting per search provider
  - **DuckDuckGo**: 1 request/minute, 45-second minimum delay
  - **Google**: 5 requests/minute, 12-second minimum delay
  - **Bing**: 10 requests/minute, 6-second minimum delay
  - **BBB**: 3 requests/minute, 20-second minimum delay
  - **Yelp**: 5 requests/minute, 12-second minimum delay
- **Failure Detection**: Request history tracking with exponential backoff
- **Sliding Window**: Time-based rate limiting with automatic recovery

### Performance Tuning

- **Cache Settings**: Search result and geolocation caching with Redis
- **Rate Limiting**: Respectful delays to prevent server overload
- **Resource Management**: Browser instance pooling and cleanup
- **Error Recovery**: Graceful degradation and automatic retries
- **Memory Optimization**: Efficient resource management and cleanup

## 🛡️ Security & Privacy

### Data Protection
- **Local Storage**: Data stored locally in IndexedDB and PostgreSQL (production)
- **Encrypted Connections**: Database connections use encryption in production
- **Input Sanitization**: Prevents XSS attacks and injection vulnerabilities
- **CSP Headers**: Content Security Policy provides additional protection
- **Secure Credentials**: API keys and passwords stored in environment variables

### Advanced Security Features
- **Network Spoofing**: IP and MAC address spoofing for enhanced privacy
- **Browser Fingerprint Protection**: Prevents browser fingerprinting detection
- **Request Anonymization**: Removes automation indicators and tracking scripts
- **Rate Limiting**: Global and provider-specific request throttling
- **Security Headers**: HSTS, CSP, and other security configurations

### Ethical Scraping
- **Respectful Rate Limiting**: Provider-specific delays to prevent server overload
- **Robots.txt Compliance**: Respects robots.txt when appropriate
- **User-Agent Identification**: Provides realistic user-agent identification
- **Exponential Backoff**: Intelligent retry logic with increasing delays
- **Resource Management**: Efficient browser pooling and cleanup

## 🚀 Deployment

### Development Deployment

#### Build for Production
```bash
npm run build
# or
yarn build
```

#### Start Production Server
```bash
npm start
# or
yarn start
```

### Production Deployment (Docker)

#### Prerequisites
- Docker and Docker Compose installed
- 2GB+ RAM available
- Ports 3000, 5432, 6379 available

#### Quick Start
```bash
# Clone and navigate to repository
git clone <repository-url>
cd business-scraper-app

# Start production environment
docker-compose up -d

# Monitor deployment
docker-compose logs -f

# Health check
curl http://localhost:3000/api/health
```

#### Production Environment Setup
```bash
# Create production environment file
cp .env.example .env.production

# Configure production variables
# Edit .env.production with:
# - DATABASE_URL=postgresql://postgres:your_password@business-scraper-db:5432/business_scraper
# - REDIS_URL=redis://business-scraper-redis:6379
# - ENABLE_REAL_SCRAPING=true
# - Network spoofing configuration

# Deploy with production config
docker-compose --env-file .env.production up -d
```

#### Container Management
```bash
# View container status
docker-compose ps

# View logs
docker-compose logs business-scraper-app
docker-compose logs business-scraper-db
docker-compose logs business-scraper-redis

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Rebuild and deploy
docker-compose build --no-cache
docker-compose up -d
```

### Cloud Deployment

#### Deploy to Vercel
```bash
npx vercel
```

#### Deploy to Netlify
```bash
npm run build
# Upload the 'out' directory to Netlify
```

> **Note**: For production workloads, Docker deployment is recommended for full database and caching capabilities.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow TypeScript best practices
- Write comprehensive tests for new features
- Update documentation for API changes
- Use conventional commit messages
- Ensure all tests pass before submitting

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Common Issues

**Issue**: Scraping fails with timeout errors
**Solution**: Increase timeout values in configuration or check network connectivity

**Issue**: No businesses found
**Solution**: Try broader search terms or increase search radius

**Issue**: Export fails
**Solution**: Check browser permissions for file downloads

### Getting Help
- Check the [Issues](../../issues) page for known problems
- Create a new issue with detailed error information
- Include browser console logs and configuration details

## 📚 Documentation

### Quick Links
- **[Current Status](CURRENT_STATUS.md)** - Complete overview of implemented features and current capabilities
- **[Version History](VERSIONS)** - Comprehensive version history and compatibility documentation
- **[Production Deployment Summary](docs/PRODUCTION_DEPLOYMENT_SUMMARY.md)** - Docker deployment guide and production environment setup
- **[Network Spoofing Implementation](docs/NETWORK_SPOOFING_IMPLEMENTATION.md)** - Advanced anti-detection and network spoofing system
- **[Feature Guide](FEATURE_GUIDE.md)** - Detailed guide to smart industry expansion, BBB discovery, and advanced search features
- **[Chamber of Commerce Processing](CHAMBER_OF_COMMERCE_PROCESSING.md)** - Automatic processing of chamberofcommerce.com URLs with deep scraping
- **[Yelp RESTful Scraping](YELP_RESTFUL_SCRAPING.md)** - RESTful Yelp processing with deep website analysis
- **[Yelp Directory URL Fix](YELP_DIRECTORY_URL_FIX.md)** - Fix for directory URL skipping warnings
- **[Per-Industry Blacklist](PER_INDUSTRY_BLACKLIST.md)** - Complete guide to the new per-industry domain filtering system
- **[Domain Blacklist Format](DOMAIN_BLACKLIST_FORMAT.md)** - Legacy global domain blacklist import/export format
- **[Changelog](CHANGELOG.md)** - Detailed history of changes and improvements
- **[Configuration Guide](CONFIGURATION.md)** - Comprehensive configuration options and best practices
- **[API Documentation](API_DOCUMENTATION.md)** - Complete API reference and integration guide

### Recent Major Updates (v1.5.1)
- 🔍 **Enhanced Search Quality**: Fixed Private & Charter Schools search returning irrelevant government office results
- 🎯 **Improved Industry Targeting**: Refined keywords and search strategy for better result accuracy
- 🚫 **Advanced Filtering**: Comprehensive domain blacklist including government, educational, and directory sites
- 📍 **Better Location Accuracy**: Enhanced ZIP radius filtering for more relevant local results

### Performance Optimizations (v1.5.0)
- 🚀 **Comprehensive Performance Optimizations**: 3x faster concurrent processing with enhanced throughput
- ⚡ **Multi-Level Smart Caching**: L1/L2/L3 caching strategy with intelligent cache warming
- 🌊 **Real-Time Streaming**: Live search results and progress updates via Server-Sent Events
- 💾 **Memory-Efficient Exports**: Streaming CSV/JSON export for large datasets
- 🔧 **Advanced Browser Pool**: 2x more browser capacity with health monitoring and auto-optimization
- 📊 **Performance Monitoring**: Real-time metrics for browser health, cache statistics, and streaming performance
- 🆕 **New API Endpoints**: `/api/stream-search` and `/api/stream-export` for real-time operations

### Previous Updates (v1.4.1)
- ✅ **Complete Production Rebuild**: Full application rebuild and redeployment with latest optimizations
- ✅ **Docker Production Environment**: Containerized deployment with PostgreSQL and Redis
- ✅ **Enhanced Monitoring**: Comprehensive health checks and system monitoring
- ✅ **Production Configuration**: Real web scraping enabled with secure environment setup

### Major Updates (v1.4.0)
- ✅ **Network Spoofing Service**: Comprehensive IP address and MAC address spoofing system
- ✅ **Advanced Rate Limiting**: Provider-specific intelligent rate limiting with exponential backoff
- ✅ **Enhanced Anti-Detection**: Request interception, tracking script blocking, automation property removal
- ✅ **DuckDuckGo Rate Limiting Fix**: Resolved 429 errors with 45-second delays and improved success rate to 85%
- ✅ **Browser Fingerprint Spoofing**: WebGL, Canvas, and Audio Context fingerprint modification
- ✅ **Production Infrastructure**: Docker deployment with PostgreSQL database and Redis cache

### Previous Updates (v1.3.0)
- ✅ **Chamber of Commerce Processing (COCP)**: Automatic detection and processing of chamberofcommerce.com URLs
- ✅ **Yelp RESTful Scraping**: Refactored Yelp processing with RESTful URLs and deep website analysis
- ✅ **Directory URL Fix**: Eliminated warnings by preventing directory search URLs from being treated as business websites
- ✅ **Enhanced Deep Scraping**: Up to 20 pages per business website with comprehensive contact extraction

### Previous Updates (v1.2.0)
- ✅ **Per-Industry Domain Blacklists**: Configure domain filtering specific to each industry category
- ✅ **Enhanced Wildcard Support**: Use patterns like `*.domain.com`, `domain.*`, `*keyword*` for precise filtering
- ✅ **Theme-Aware Interface**: Text areas automatically adapt to light/dark mode with proper contrast
- ✅ **Improved Export/Import**: Complete industry configuration management with backward compatibility
- ✅ **Expanded Editor Interface**: Dual text areas for keywords and domain blacklist editing

### Previous Updates (v1.1.0)
- ✅ **Smart Industry Expansion**: Automatic conversion of industry categories to specific business types
- ✅ **Advanced BBB Discovery**: Real-time scraping of BBB profiles for actual business websites
- ✅ **Precise ZIP Radius Validation**: Accurate geolocation-based filtering with distance calculations
- ✅ **Multi-Strategy Search Engine**: Combined DuckDuckGo SERP + BBB discovery with automatic failover
- ✅ **Enhanced Error Handling**: Comprehensive fallback strategies and graceful degradation

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

## 🔐 Security

This repository implements comprehensive security measures to protect sensitive information:

### 🛡️ Sensitive File Protection
- **Automatic Exclusion**: `.gitignore` configured to exclude files with API keys and credentials
- **Safe Templates**: Use `.example` files for configuration templates
- **Environment Variables**: Store secrets in environment variables, never in code

### 📋 Protected Patterns
The following file patterns are automatically excluded from version control:
- `REAL_SCRAPING_GUIDE.md` - Contains actual API keys
- `*api-credentials*.txt` - API credential backup files
- `*-with-keys.md` - Documentation with real keys
- `*SECRET*.md`, `*PRIVATE*.md` - Sensitive documentation

### 📚 Security Documentation
- **[SECURITY_SENSITIVE_FILES.md](SECURITY_SENSITIVE_FILES.md)** - Comprehensive security guide
- **[REAL_SCRAPING_GUIDE.example.md](REAL_SCRAPING_GUIDE.example.md)** - Safe configuration template

> ⚠️ **Important**: Never commit files containing real API keys or credentials. Always use example templates and environment variables.

## 🙏 Acknowledgments

- [Puppeteer](https://pptr.dev/) for web scraping capabilities
- [Next.js](https://nextjs.org/) for the React framework
- [Tailwind CSS](https://tailwindcss.com/) for styling
- [Lucide React](https://lucide.dev/) for icons
- [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) for client-side storage

---

**Built with ❤️ using modern web technologies**
