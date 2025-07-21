# Business Scraper App

A comprehensive full-stack business web scraping application built with Next.js, React, TypeScript, and Puppeteer. This application allows users to search for and scrape business contact information by industry and location.

## 🚀 Features

### Core Functionality
- **Industry-based Search**: Select from predefined industries or add custom categories
- **Location-based Filtering**: Search businesses within a specified radius of a ZIP code
- **Intelligent Web Scraping**: Automated extraction of business contact information
- **Multi-format Export**: Export data in CSV, XLSX, XLS, ODS, PDF, and JSON formats
- **Real-time Progress Tracking**: Monitor scraping progress with detailed statistics

### Technical Features
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Dark Mode Support**: Toggle between light and dark themes
- **Offline Capability**: IndexedDB storage for offline data persistence
- **Error Handling**: Comprehensive error logging and user feedback
- **Data Validation**: Input validation and data integrity checks
- **Performance Optimized**: Lazy loading, caching, and efficient data processing

## 🏗️ Architecture

The application follows an **Adapted MVC (Model-View-Controller)** pattern:

### Model Layer (`src/model/`)
- **scraperService.ts**: Core web scraping functionality using Puppeteer
- **geocoder.ts**: Address geocoding with multiple provider fallbacks
- **searchEngine.ts**: Search engine integration for finding business websites
- **storage.ts**: IndexedDB operations for data persistence

### View Layer (`src/view/`)
- **App.tsx**: Main application component
- **CategorySelector.tsx**: Industry category selection interface
- **ResultsTable.tsx**: Data display and management table
- **UI Components**: Reusable UI components (Button, Input, Card, etc.)

### Controller Layer (`src/controller/`)
- **ConfigContext.tsx**: Global configuration state management
- **useScraperController.ts**: Scraping workflow orchestration

### Utilities (`src/utils/`)
- **logger.ts**: Structured logging system
- **formatters.ts**: Data formatting utilities
- **exportService.ts**: Multi-format data export
- **validation.ts**: Data validation and sanitization

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
   BING_SEARCH_API_KEY=your_bing_search_api_key
   YANDEX_SEARCH_API_KEY=your_yandex_search_api_key
   ```

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
1. **Select Industries**: Choose from predefined categories or add custom industries
2. **Set Location**: Enter a ZIP code and search radius
3. **Configure Scraping**: Set search depth and pages per site limits

### 2. Scraping Process
1. Click "Start Scraping" to begin the automated process
2. Monitor real-time progress and statistics
3. View errors and warnings in the dedicated panel
4. Stop the process at any time if needed

### 3. Data Management
1. **View Results**: Browse scraped data in the interactive table
2. **Edit Data**: Click on cells to edit business information
3. **Filter & Sort**: Use built-in filtering and sorting options
4. **Export Data**: Download results in your preferred format

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

### Scraping Configuration
- **Search Radius**: 1-100 miles from ZIP code center
- **Search Depth**: 1-5 levels deep per website
- **Pages per Site**: 1-20 pages maximum per website
- **Timeout**: Request timeout in milliseconds
- **Retry Logic**: Exponential backoff for failed requests

### Performance Tuning
- **Concurrent Requests**: Adjust batch size for parallel processing
- **Cache Settings**: Configure caching duration and size limits
- **Rate Limiting**: Set delays between requests to avoid blocking

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
