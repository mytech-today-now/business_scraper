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

- **🔍 Individual Criteria Parsing**: Processes comma-separated and quoted search terms individually
- **🏢 BBB Business Discovery**: Real-time scraping of Better Business Bureau for verified business websites
- **📐 ZIP Radius Validation**: Accurate distance calculation with fallback geolocation data
- **🔄 Fallback Search Strategies**: Multiple search providers with automatic failover
- **⚡ Optimized Query Processing**: Industry-specific templates and synonym expansion
- **🔗 Azure AI Foundry Integration**: Modern "Grounding with Bing Custom Search" API support
- **🚫 Domain Blacklist**: Filter out unwanted domains from search results

### Technical Features

- **📱 Responsive Design**: Works seamlessly on desktop and mobile devices
- **🌙 Dark Mode Support**: Toggle between light and dark themes
- **💾 Offline Capability**: IndexedDB storage for offline data persistence
- **🛡️ Comprehensive Error Handling**: Graceful degradation and detailed error logging
- **✅ Data Validation**: Input sanitization and business data integrity checks
- **🚀 Performance Optimized**: Lazy loading, caching, and efficient data processing

## 🏗️ Architecture

The application follows an **Adapted MVC (Model-View-Controller)** pattern with modern Next.js architecture:

### Model Layer (`src/model/`)

- **clientSearchEngine.ts**: Multi-strategy search orchestration with industry expansion
- **clientScraperService.ts**: Client-side scraping coordination and demo mode handling
- **scraperService.ts**: Core web scraping functionality using Puppeteer
- **searchEngine.ts**: Advanced search engine with optimization and validation
- **queryOptimizer.ts**: Industry-specific query templates and synonym expansion
- **storage.ts**: IndexedDB operations for data persistence

### API Layer (`src/app/api/`)

- **search/route.ts**: Search API with BBB discovery and DuckDuckGo SERP scraping
- **scrape/route.ts**: Web scraping API endpoints
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

### Utilities (`src/utils/`)

- **logger.ts**: Structured logging system with multiple levels
- **formatters.ts**: Data formatting utilities for export
- **exportService.ts**: Multi-format data export (CSV, XLSX, PDF, JSON)
- **validation.ts**: Input validation and sanitization
- **secureStorage.ts**: Encrypted credential storage

## 📋 Prerequisites

- Node.js 18+ 
- npm or yarn
- Modern web browser with JavaScript enabled

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
   - **Demo Mode**: Toggle between real scraping and demo data

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

### Performance Tuning

- **Cache Settings**: Search result and geolocation caching
- **Rate Limiting**: Respectful delays to prevent server overload
- **Resource Management**: Browser instance pooling and cleanup
- **Error Recovery**: Graceful degradation and automatic retries

## 🛡️ Security & Privacy

### Data Protection
- All data is stored locally in IndexedDB
- No data is transmitted to external servers (except for geocoding APIs)
- Input sanitization prevents XSS attacks
- CSP headers provide additional security

### Ethical Scraping
- Respects robots.txt when appropriate
- Implements rate limiting to avoid overwhelming servers
- Provides user-agent identification
- Includes retry logic with exponential backoff

## 🚀 Deployment

### Build for Production
```bash
npm run build
# or
yarn build
```

### Start Production Server
```bash
npm start
# or
yarn start
```

### Deploy to Vercel
```bash
npx vercel
```

### Deploy to Netlify
```bash
npm run build
# Upload the 'out' directory to Netlify
```

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
- **[Feature Guide](FEATURE_GUIDE.md)** - Detailed guide to smart industry expansion, BBB discovery, and advanced search features
- **[Changelog](CHANGELOG.md)** - Detailed history of changes and improvements
- **[Configuration Guide](CONFIGURATION.md)** - Comprehensive configuration options and best practices
- **[API Documentation](API_DOCUMENTATION.md)** - Complete API reference and integration guide

### Recent Major Updates (v1.1.0)
- ✅ **Smart Industry Expansion**: Automatic conversion of industry categories to specific business types
- ✅ **Advanced BBB Discovery**: Real-time scraping of BBB profiles for actual business websites
- ✅ **Precise ZIP Radius Validation**: Accurate geolocation-based filtering with distance calculations
- ✅ **Multi-Strategy Search Engine**: Combined DuckDuckGo SERP + BBB discovery with automatic failover
- ✅ **Enhanced Error Handling**: Comprehensive fallback strategies and graceful degradation

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

## 🙏 Acknowledgments

- [Puppeteer](https://pptr.dev/) for web scraping capabilities
- [Next.js](https://nextjs.org/) for the React framework
- [Tailwind CSS](https://tailwindcss.com/) for styling
- [Lucide React](https://lucide.dev/) for icons
- [IndexedDB](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API) for client-side storage

---

**Built with ❤️ using modern web technologies**
