# User Guide

![Version](https://img.shields.io/badge/version-3.10.1-blue.svg)
![User Guide](https://img.shields.io/badge/guide-comprehensive-green.svg)

## 📋 Overview

Welcome to the Business Scraper Application v3.6.0! This comprehensive user
guide will help you master all features of the application, from basic business
searches to advanced CRM export functionality.

## 🚀 Getting Started

### **System Requirements**

- **Browser**: Chrome 90+, Firefox 88+, Safari 14+, or Edge 90+
- **Internet Connection**: Stable broadband connection
- **JavaScript**: Must be enabled
- **Local Storage**: 50MB+ available space

### **First Time Setup**

1. **Access the Application**: Navigate to the application URL
2. **Configure API Settings**: Go to API Configuration page
3. **Test Search Functionality**: Perform a basic search
4. **Explore Features**: Familiarize yourself with the interface

## 🔍 Basic Business Search

### **Performing Your First Search**

1. **Enter Search Query**
   - Type your industry or business type (e.g., "restaurants", "dentists", "auto
     repair")
   - Use specific terms for better results

2. **Specify Location**
   - Enter ZIP code (e.g., "90210")
   - Or city and state (e.g., "Beverly Hills, CA")
   - Or full address for precise targeting

3. **Set Search Parameters**
   - **Radius**: Choose search radius (5-50 miles)
   - **Limit**: Set maximum results (10-500 businesses)
   - **Filters**: Apply additional filters if needed

4. **Start Search**
   - Click "Search Businesses" button
   - Monitor real-time progress
   - Results appear as they're discovered

### **Understanding Search Results**

#### **Result Columns**

- **Business Name**: Company or business name
- **Website**: Business website URL (clickable)
- **Phone**: Contact phone number
- **Email**: Contact email address
- **Address**: Full business address
- **Industry**: Categorized industry type
- **Confidence**: Data quality score (0-100%)
- **Source**: Where the data was found

#### **Result Actions**

- **Visit Website**: Click website URL to open in new tab
- **Copy Information**: Click to copy phone, email, or address
- **View Details**: Hover for additional information
- **Select for Export**: Use checkboxes to select specific businesses

## 🔧 Advanced Search Features

### **Search Engine Management**

#### **Available Search Engines**

- **Google Custom Search**: High-quality results with advanced filtering
- **Azure AI Search**: AI-powered business discovery
- **DuckDuckGo**: Privacy-focused search results
- **Yelp Integration**: Restaurant and service business data
- **BBB Integration**: Better Business Bureau verified businesses

#### **Engine Configuration**

1. **Navigate to API Configuration**
2. **Enable/Disable Engines**: Toggle individual search engines
3. **Set Priorities**: Arrange engines by preference
4. **Test Engines**: Verify each engine is working correctly

### **Advanced Filtering Options**

#### **Industry Filters**

- **Specific Industries**: Filter by exact industry categories
- **Industry Groups**: Use broader category filters
- **Custom Keywords**: Add specific search terms

#### **Quality Filters**

- **Has Website**: Only businesses with websites
- **Has Phone**: Only businesses with phone numbers
- **Has Email**: Only businesses with email addresses
- **Minimum Confidence**: Set minimum data quality threshold

#### **Geographic Filters**

- **Radius Control**: Precise distance-based filtering
- **ZIP Code Validation**: Ensure accurate location targeting
- **Multi-location Search**: Search multiple areas simultaneously

## 📊 Data Management

### **Viewing and Organizing Results**

#### **Table Features**

- **Sorting**: Click column headers to sort data
- **Filtering**: Use search box to filter visible results
- **Pagination**: Navigate through large result sets
- **Selection**: Select individual or all businesses

#### **Performance Modes**

- **Normal Mode**: Full features for datasets under 1,000 results
- **Performance Mode**: Optimized for 1,000-2,500 results
- **Pagination Mode**: Efficient handling of 2,500+ results
- **Virtual Scrolling**: Smooth performance with 10,000+ results

### **Data Quality and Validation**

#### **Confidence Scores**

- **90-100%**: Highly reliable data from verified sources
- **70-89%**: Good quality data with minor uncertainties
- **50-69%**: Moderate quality data requiring verification
- **Below 50%**: Lower quality data, use with caution

#### **Data Sources**

- **Direct Website**: Information scraped from business websites
- **Directory Listings**: Data from business directories
- **Search Results**: Information from search engine results
- **BBB Verified**: Better Business Bureau verified information

## 🔗 CRM Export Templates

### **Overview of CRM Integration**

The CRM Export Templates feature allows you to export business data in formats
optimized for major CRM platforms including Salesforce, HubSpot, and Pipedrive.

### **Using CRM Export Templates**

#### **Step 1: Access CRM Export**

1. **Complete a Search**: Generate business results first
2. **Open Export Menu**: Click "Export" dropdown in results table
3. **Select CRM Templates**: Click "🚀 CRM Templates" option

#### **Step 2: Choose Platform**

1. **Salesforce**: For Salesforce CRM users
   - Lead templates for individual contacts
   - Account/Contact templates for B2B data
2. **HubSpot**: For HubSpot CRM users
   - Contact templates with lifecycle stages
   - Company templates for organization data
3. **Pipedrive**: For Pipedrive CRM users
   - Organization/Person templates
   - Deal templates with pipeline stages

#### **Step 3: Select Template**

1. **Browse Available Templates**: View platform-specific options
2. **Read Template Descriptions**: Understand field mappings
3. **Choose Appropriate Template**: Select based on your CRM workflow

#### **Step 4: Preview and Validate**

1. **Preview Data**: See how your data will be transformed
2. **Review Validation**: Check for errors and warnings
3. **Fix Issues**: Address any validation problems
4. **Confirm Export**: Proceed when validation passes

#### **Step 5: Download Export**

1. **Generate Export**: System processes your data
2. **Monitor Progress**: Track export progress for large datasets
3. **Download File**: Save the CRM-ready file
4. **Import to CRM**: Use the file in your CRM system

### **CRM Template Features**

#### **Field Mapping**

- **Automatic Mapping**: Business data automatically mapped to CRM fields
- **Data Transformation**: Phone numbers, emails, and dates properly formatted
- **Industry Mapping**: Business categories mapped to CRM industry values
- **Default Values**: Missing data filled with appropriate defaults

#### **Validation and Quality**

- **Required Field Validation**: Ensures all required CRM fields are populated
- **Format Validation**: Validates email addresses, phone numbers, dates
- **Length Validation**: Checks field length limits for target CRM
- **Custom Validation**: Platform-specific validation rules

#### **Export Formats**

- **CSV**: Standard comma-separated values for most CRMs
- **JSON**: Structured data format for API imports
- **XML**: Extensible markup language for advanced integrations

## 📤 Data Export Options

### **Standard Export Formats**

#### **CSV Export**

- **Use Case**: Spreadsheet analysis, basic CRM imports
- **Features**: Headers, custom delimiters, encoding options
- **Best For**: General data analysis and simple imports

#### **Excel Export (XLSX)**

- **Use Case**: Advanced spreadsheet analysis, presentations
- **Features**: Multiple sheets, formatting, formulas
- **Best For**: Business reports and detailed analysis

#### **PDF Export**

- **Use Case**: Reports, presentations, documentation
- **Features**: Professional formatting, charts, summaries
- **Best For**: Sharing results with stakeholders

#### **JSON Export**

- **Use Case**: API integrations, custom applications
- **Features**: Structured data, nested objects, metadata
- **Best For**: Technical integrations and data processing

### **Export Customization**

#### **Field Selection**

- **Choose Columns**: Select specific data fields to export
- **Custom Order**: Arrange columns in preferred order
- **Calculated Fields**: Add computed values and summaries

#### **Filtering Options**

- **Quality Filters**: Export only high-confidence data
- **Industry Filters**: Export specific business categories
- **Geographic Filters**: Export businesses from specific areas

#### **Format Options**

- **Headers**: Include/exclude column headers
- **Encoding**: Choose character encoding (UTF-8, ASCII)
- **Delimiters**: Custom separators for CSV files

## ⚙️ Configuration and Settings

### **API Configuration**

#### **Search Engine Setup**

1. **Google Custom Search**
   - Obtain API key from Google Cloud Console
   - Create Custom Search Engine ID
   - Configure search parameters

2. **Azure AI Search**
   - Set up Azure AI Foundry account
   - Configure Bing Custom Search
   - Set API endpoints and keys

3. **Other Engines**
   - Configure DuckDuckGo settings
   - Set up Yelp API access
   - Configure BBB integration

#### **Performance Settings**

- **Timeout Values**: Adjust request timeouts
- **Retry Logic**: Configure retry attempts
- **Rate Limiting**: Set request rate limits
- **Caching**: Configure result caching

### **User Preferences**

#### **Interface Settings**

- **Theme**: Light/dark mode selection
- **Language**: Interface language preferences
- **Timezone**: Local timezone configuration
- **Date Format**: Date display preferences

#### **Default Search Settings**

- **Default Radius**: Preferred search radius
- **Default Limit**: Preferred result limit
- **Default Engines**: Preferred search engines
- **Auto-filters**: Automatic filter applications

## 🔧 Troubleshooting

### **Common Issues and Solutions**

#### **No Search Results**

- **Check Location**: Verify ZIP code or city name
- **Expand Radius**: Increase search radius
- **Try Different Terms**: Use alternative search keywords
- **Check Engine Status**: Verify search engines are enabled

#### **Slow Performance**

- **Reduce Result Limit**: Lower maximum results
- **Enable Performance Mode**: Use optimized display mode
- **Clear Browser Cache**: Clear browser data
- **Check Internet Connection**: Verify stable connection

#### **Export Issues**

- **Check File Size**: Large exports may take time
- **Verify Data Selection**: Ensure businesses are selected
- **Try Different Format**: Use alternative export format
- **Clear Browser Downloads**: Remove old download files

### **Getting Help**

#### **Documentation Resources**

- **[API Documentation](API_DOCUMENTATION.md)**: Technical API reference
- **[CRM Export Guide](CRM_EXPORT_GUIDE.md)**: Detailed CRM export instructions
- **[Troubleshooting Guide](TROUBLESHOOTING.md)**: Comprehensive problem-solving
  guide

#### **Support Channels**

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check comprehensive guides
- **Community**: Development team discussions

## 🎯 Best Practices

### **Effective Searching**

- **Use Specific Terms**: "Italian restaurants" vs "restaurants"
- **Optimize Location**: Use ZIP codes for precision
- **Adjust Radius**: Start small, expand if needed
- **Quality Over Quantity**: Prefer high-confidence results

### **Data Management**

- **Regular Exports**: Export data regularly to avoid loss
- **Validate Before Export**: Use preview functionality
- **Organize Results**: Use meaningful export filenames
- **Backup Important Data**: Keep copies of valuable datasets

### **CRM Integration**

- **Test Templates**: Use sample data to test CRM imports
- **Validate Mappings**: Ensure field mappings are correct
- **Clean Data First**: Address validation errors before export
- **Import Gradually**: Start with small batches in CRM

### **Performance Optimization**

- **Use Appropriate Limits**: Don't request more data than needed
- **Enable Performance Modes**: Use optimized display for large datasets
- **Close Unused Tabs**: Free up browser memory
- **Regular Maintenance**: Clear cache and temporary files

## 📈 Advanced Features

### **Batch Processing**

- **Multiple Searches**: Queue multiple search operations
- **Bulk Export**: Export multiple result sets
- **Scheduled Operations**: Set up recurring searches
- **Progress Monitoring**: Track long-running operations

### **Data Analysis**

- **Quality Metrics**: Analyze data quality statistics
- **Geographic Distribution**: View results by location
- **Industry Analysis**: Analyze business category distribution
- **Trend Analysis**: Track search result patterns

### **Integration Options**

- **API Access**: Programmatic access to functionality
- **Webhook Support**: Real-time notifications
- **Custom Exports**: Tailored export formats
- **Third-party Integrations**: Connect with other tools

This user guide provides comprehensive coverage of all application features. For
additional help, refer to the specific documentation guides or contact support
through the available channels.
