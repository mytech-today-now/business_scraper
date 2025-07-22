# Business Scraper MVP Implementation Guide - Single User Application
## Step-by-Step Development Prompts for Augment

### PHASE 1: INFRASTRUCTURE SETUP (Weeks 1-2)

#### Step 1.1: Database Schema Design

Create a simplified PostgreSQL database schema for the single-user business scraper application with the following tables:
- campaigns (id, name, industry, location, status, created_at, parameters)
- businesses (id, campaign_id, name, email, phone, website, address, confidence_score, scraped_at)
- scraping_sessions (id, campaign_id, status, started_at, completed_at, total_urls, successful_scrapes, errors)
- app_settings (id, key, value, updated_at) - for storing API keys and configuration

Include proper indexes, foreign key constraints, and data types. Add migration scripts using a tool like Prisma or raw SQL.
Note: No user management tables needed since this is a single-user application.


#### Step 1.2: Application Security and Access Control

Implement basic security measures for the single-user application:
- Simple password protection for the application (optional)
- API endpoint protection with basic authentication
- CSRF protection for forms
- Input validation and sanitization
- Rate limiting for scraping operations
- Secure storage of API keys in environment variables or encrypted settings

Note: No complex user management needed - focus on protecting the application from unauthorized access and ensuring data security.


#### Step 1.3: Environment Configuration Management

Create a simplified environment configuration system for single-user deployment:
- Basic config files for development and production
- Secure API key management using environment variables
- Database connection configuration
- Optional Redis configuration for caching (can use in-memory cache for simplicity)
- External service configurations (search APIs)
- Logging level configuration
- Simple feature toggles for development

Implement a config validation system to ensure all required variables are present.


#### Step 1.4: Simple Deployment Setup

Create a simple deployment configuration for the single-user application:
- Basic Dockerfile for the Next.js application
- Docker Compose file for local development (app, database)
- Simple production deployment configuration
- Health check endpoints
- Data persistence setup
- Environment variable configuration
- Basic backup and restore procedures

Include documentation for easy local setup and deployment. Focus on simplicity over complex orchestration.


### PHASE 2: SEARCH ENGINE INTEGRATION (Weeks 3-4)

#### Step 2.1: Google Custom Search API Integration

Implement Google Custom Search API integration for business discovery:
- Create Google Custom Search Engine configuration
- Implement search query optimization for business results
- Add location-based search parameters
- Implement result filtering to exclude directories and social media
- Add pagination support for large result sets
- Implement caching to reduce API calls
- Add error handling and retry logic
- Create rate limiting to respect API quotas

Include comprehensive logging and monitoring for search performance.


#### Step 2.2: Bing Search API Implementation

Create Bing Search API integration as a fallback search provider:
- Implement Bing Web Search API client
- Create query formatting specific to Bing's requirements
- Add result parsing and normalization
- Implement fallback logic when Google API fails
- Add cost optimization features
- Create unified search result interface
- Implement A/B testing between search providers

Ensure seamless switching between search providers based on availability and cost.


#### Step 2.3: Search Result Validation and Scoring

Develop a search result validation and scoring system:
- Create algorithms to identify legitimate business websites
- Implement domain authority checking
- Add website accessibility validation
- Create relevance scoring based on query match
- Implement duplicate URL detection
- Add geographic relevance scoring
- Create business type classification
- Implement result ranking algorithms

Include machine learning preparation for future improvements.


#### Step 2.4: Search Query Optimization Engine

Build an intelligent search query optimization system:
- Create industry-specific search term templates
- Implement location normalization (ZIP codes, cities, states)
- Add synonym expansion for better coverage
- Create negative keyword filtering
- Implement query performance analytics
- Add search term suggestion features
- Create custom search operators
- Implement query cost optimization

Include analytics to track query performance and success rates.


### PHASE 3: ENHANCED SCRAPING ENGINE (Weeks 5-6)

#### Step 3.1: Puppeteer/Playwright Scraping Infrastructure

Implement a robust web scraping engine using Puppeteer:
- Create browser pool management for concurrent scraping
- Implement JavaScript rendering for dynamic content
- Add mobile and desktop user agent rotation
- Create screenshot capture for debugging
- Implement proxy rotation support
- Add memory and CPU optimization
- Create browser crash recovery
- Implement headless and headed mode switching

Include comprehensive error handling and resource cleanup.


#### Step 3.2: Advanced Contact Information Extraction

Develop sophisticated contact information extraction algorithms:
- Create regex patterns for email detection with validation
- Implement phone number extraction with international formatting
- Add address parsing with geocoding integration
- Create business name extraction from page titles and headers
- Implement social media profile detection
- Add business hours extraction
- Create contact form detection
- Implement structured data (Schema.org) parsing

Include confidence scoring for each extracted piece of information.


#### Step 3.3: Anti-Bot Detection Bypass

Implement anti-bot detection bypass mechanisms:
- Create realistic browser fingerprinting
- Implement human-like mouse movements and scrolling
- Add random delays between actions
- Create CAPTCHA detection and handling
- Implement IP rotation and proxy management
- Add cookie and session management
- Create request header randomization
- Implement behavioral pattern mimicking

Include monitoring to detect when anti-bot measures are triggered.


#### Step 3.4: Scraping Performance Optimization

Optimize scraping performance and reliability:
- Implement concurrent scraping with queue management
- Create intelligent retry logic with exponential backoff
- Add timeout management for hanging requests
- Implement resource usage monitoring
- Create scraping speed optimization
- Add bandwidth usage optimization
- Implement cache-aware scraping
- Create performance benchmarking tools

Include real-time performance monitoring and alerting.


### PHASE 4: DATA MANAGEMENT (Weeks 7-8)

#### Step 4.1: Data Validation and Cleaning Pipeline

Create a comprehensive data validation and cleaning system:
- Implement email validation with deliverability checking
- Add phone number formatting and validation
- Create address standardization and geocoding
- Implement business name normalization
- Add data quality scoring algorithms
- Create confidence level assignment
- Implement data enrichment from external sources
- Add data completeness scoring

Include automated data quality reporting and alerts.


#### Step 4.2: Advanced Duplicate Detection System

Develop sophisticated duplicate detection algorithms:
- Create fuzzy matching for business names
- Implement address similarity detection
- Add phone number normalization and matching
- Create email domain clustering
- Implement website URL normalization
- Add geographic proximity clustering
- Create machine learning-based duplicate detection
- Implement manual review workflow for uncertain matches

Include duplicate merge and resolution workflows.


#### Step 4.3: Data Export and Integration System

Build comprehensive data export and integration capabilities:
- Create CSV export with customizable fields
- Implement Excel export with formatting
- Add JSON/XML API endpoints
- Create real-time data streaming
- Implement webhook notifications
- Add scheduled export functionality
- Create data transformation pipelines
- Implement third-party integration templates

Include export history tracking and download management.


#### Step 4.4: Data Retention and Archival

Implement data lifecycle management:
- Create configurable data retention policies
- Implement automated data archival
- Add data deletion workflows
- Create backup and recovery systems
- Implement audit trail logging
- Add compliance reporting features
- Create data anonymization tools
- Implement GDPR compliance features

Include data governance and compliance monitoring.


### PHASE 5: USER INTERFACE ENHANCEMENT (Weeks 9-10)

#### Step 5.1: Campaign Management Dashboard

Create a comprehensive campaign management interface:
- Build intuitive campaign creation wizard
- Implement real-time progress tracking with WebSockets
- Add campaign scheduling and automation
- Create campaign templates for different industries
- Implement campaign cloning and modification
- Add campaign performance analytics
- Create campaign sharing and collaboration features
- Implement campaign history and versioning

Include responsive design for mobile and tablet access.


#### Step 5.2: Advanced Results Dashboard

Develop a sophisticated results viewing and management system:
- Create interactive data tables with sorting and filtering
- Implement advanced search and query capabilities
- Add data visualization charts and graphs
- Create export selection and customization
- Implement bulk actions for result management
- Add result annotation and tagging
- Create result quality indicators
- Implement result comparison tools

Include keyboard shortcuts and power user features.


#### Step 5.3: Real-time Monitoring Interface

Build real-time monitoring and alerting dashboard:
- Create live scraping progress indicators
- Implement error tracking and reporting
- Add performance metrics visualization
- Create system health monitoring
- Implement alert configuration and management
- Add log viewing and filtering
- Create debugging tools and diagnostics
- Implement capacity planning indicators

Include mobile-responsive monitoring for on-the-go access.


#### Step 5.4: User Experience Optimization

Optimize the overall user experience:
- Implement progressive loading and skeleton screens
- Add contextual help and onboarding tours
- Create keyboard navigation and accessibility features
- Implement dark/light theme switching
- Add user preference management
- Create intuitive error handling and recovery
- Implement undo/redo functionality
- Add search and navigation optimization

Include user feedback collection and analysis tools.


### PHASE 6: TESTING AND DEPLOYMENT (Weeks 11-12)

#### Step 6.1: Comprehensive Testing Suite

Implement a complete testing infrastructure:
- Create unit tests for all core functions with 90%+ coverage
- Implement integration tests for API endpoints
- Add end-to-end tests for critical user workflows
- Create performance tests for scraping and database operations
- Implement security testing and vulnerability scanning
- Add load testing for concurrent user scenarios
- Create data integrity tests
- Implement automated regression testing

Include continuous integration pipeline with automated test execution.


#### Step 6.2: Security Review and Basic Hardening

Conduct basic security review for single-user application:
- Implement input validation and sanitization
- Add SQL injection prevention
- Create XSS protection mechanisms
- Implement CSRF protection
- Add basic rate limiting
- Secure API key storage
- Implement data encryption for sensitive data
- Add security headers and HTTPS enforcement

Include basic security testing and vulnerability scanning.


#### Step 6.3: Performance Optimization

Optimize application performance for single-user usage:
- Implement database query optimization and indexing
- Add simple caching for frequently accessed data (in-memory or file-based)
- Implement lazy loading and code splitting
- Add database connection pooling
- Create memory usage optimization
- Implement API response compression
- Add basic performance monitoring

Include performance benchmarking for typical single-user workloads.


#### Step 6.4: Simple Deployment Pipeline

Create a simple deployment pipeline for single-user application:
- Basic automated testing and deployment
- Simple deployment strategy (direct deployment)
- Database migration automation
- Basic rollback procedures
- Simple monitoring and logging
- Basic backup procedures
- Single-instance deployment configuration

Include simple deployment documentation and maintenance procedures.


### POST-MVP PHASE 1: IMMEDIATE ENHANCEMENTS (Weeks 13-16)

#### Step 7.1: Advanced Data Enrichment

Implement sophisticated data enrichment capabilities:
- Integrate with business information APIs (Clearbit, FullContact)
- Add social media profile discovery and linking
- Implement company size and revenue estimation
- Create industry classification and NAICS code assignment
- Add competitor analysis and market positioning
- Implement technology stack detection
- Create business relationship mapping
- Add news and event monitoring

Include enrichment quality scoring and validation.


#### Step 7.2: Analytics and Reporting Dashboard

Build comprehensive analytics and reporting system:
- Create campaign performance analytics
- Implement data quality trend analysis
- Add cost-per-lead calculations
- Create geographic distribution analysis
- Implement industry trend reporting
- Add user behavior analytics
- Create ROI tracking and reporting
- Implement custom report builder

Include scheduled reporting and alert notifications.


#### Step 7.3: API Development for Third-party Integrations

Develop comprehensive API for external integrations:
- Create RESTful API with OpenAPI documentation
- Implement GraphQL endpoint for flexible queries
- Add webhook system for real-time notifications
- Create SDK development for popular languages
- Implement API versioning and backward compatibility
- Add rate limiting and usage analytics
- Create API key management and authentication
- Implement real-time data streaming endpoints

Include comprehensive API documentation and examples.


#### Step 7.4: Team Collaboration Features

Implement team collaboration and sharing capabilities:
- Create team workspace management
- Implement role-based access control
- Add campaign sharing and collaboration
- Create comment and annotation systems
- Implement approval workflows
- Add team performance analytics
- Create resource sharing and templates
- Implement team communication features

Include team management and billing features.


## IMPLEMENTATION NOTES

### Development Best Practices
- Use TypeScript for type safety across the entire application
- Implement comprehensive error handling and logging
- Follow security best practices for data handling
- Use database transactions for data consistency
- Implement proper caching strategies
- Follow RESTful API design principles
- Use environment-specific configurations
- Implement proper testing at all levels

### Monitoring and Observability
- Implement structured logging with correlation IDs
- Add performance monitoring and alerting
- Create health check endpoints
- Implement error tracking and reporting
- Add user behavior analytics
- Create system metrics dashboards
- Implement capacity planning tools
- Add security monitoring and alerting

### Scalability Considerations
- Design for horizontal scaling from the start
- Implement database sharding strategies
- Use message queues for async processing
- Implement caching at multiple levels
- Design stateless application architecture
- Use microservices where appropriate
- Implement auto-scaling capabilities
- Plan for multi-region deployment
