# API Configuration Guide

## Overview

The Business Scraper application supports multiple search APIs for enhanced functionality. However, these APIs require valid credentials to function properly. This guide explains how to configure them.

## Current Status

**All external API keys are currently DISABLED** to prevent errors with placeholder/test credentials.

## Supported APIs

### 1. Google Custom Search API
- **Purpose**: Enhanced web search capabilities
- **Configuration**: 
  - `GOOGLE_SEARCH_API_KEY` - Your Google Custom Search API key
  - `GOOGLE_SEARCH_ENGINE_ID` - Your Custom Search Engine ID
- **How to get**: Visit [Google Custom Search API](https://developers.google.com/custom-search/v1/introduction)

### 2. Azure AI Foundry (Bing Custom Search)
- **Purpose**: Alternative search engine with Bing results
- **Configuration**:
  - `AZURE_AI_FOUNDRY_API_KEY` - Your Azure AI Foundry API key
  - `AZURE_AI_FOUNDRY_ENDPOINT` - Your Azure endpoint URL
  - `AZURE_AI_FOUNDRY_REGION` - Azure region (e.g., eastus)
- **How to get**: Visit [Azure AI Foundry](https://azure.microsoft.com/en-us/products/ai-foundry/)

### 3. Google Maps API
- **Purpose**: Enhanced geocoding and location services
- **Configuration**: `GOOGLE_MAPS_API_KEY`
- **How to get**: Visit [Google Maps Platform](https://developers.google.com/maps)

### 4. OpenCage Geocoding API
- **Purpose**: Alternative geocoding service
- **Configuration**: `OPENCAGE_API_KEY`
- **How to get**: Visit [OpenCage Geocoding API](https://opencagedata.com/)

## Fallback Behavior

When API keys are not configured, the application automatically falls back to:
- **DuckDuckGo Search** (free, no API key required)
- **Built-in geocoding** (basic functionality)

This ensures the application continues to work without external API dependencies.

## How to Enable APIs

1. **Obtain valid API keys** from the respective providers
2. **Update the `.env` file** with your real API keys:
   ```bash
   # Uncomment and replace with real keys
   GOOGLE_SEARCH_API_KEY=your_real_google_search_api_key_here
   GOOGLE_SEARCH_ENGINE_ID=your_real_search_engine_id_here
   AZURE_AI_FOUNDRY_API_KEY=your_real_azure_api_key_here
   AZURE_AI_FOUNDRY_ENDPOINT=https://your-real-endpoint.cognitiveservices.azure.com/
   GOOGLE_MAPS_API_KEY=your_real_google_maps_api_key_here
   ```
3. **Restart the application** to apply the changes

## Testing API Configuration

The application includes an **API Configuration** page where you can:
- Enter your API credentials
- Test each API connection
- View detailed error messages if configuration fails
- See which APIs are available and working

Access this via the "API Configuration" button in the application header.

## Security Notes

- **Never commit real API keys** to version control
- **Use environment variables** for production deployments
- **Rotate API keys regularly** for security
- **Monitor API usage** to avoid unexpected charges

## Troubleshooting

### Common Issues:
1. **400 Bad Request**: Usually indicates invalid API key or malformed request
2. **404 Not Found**: Usually indicates incorrect endpoint URL
3. **403 Forbidden**: Usually indicates API key lacks required permissions
4. **429 Too Many Requests**: API rate limit exceeded

### Solutions:
1. Verify API keys are correct and active
2. Check endpoint URLs for typos
3. Ensure API keys have required permissions
4. Monitor API usage and implement rate limiting

## Cost Considerations

Most APIs have free tiers but may charge for usage beyond limits:
- **Google Custom Search**: 100 queries/day free, then $5 per 1000 queries
- **Azure AI Foundry**: Varies by service tier
- **Google Maps**: $200 monthly credit, then pay-per-use
- **OpenCage**: 2500 queries/day free, then paid plans

## Current Configuration

As of the latest update, all external APIs are disabled to prevent errors. The application runs successfully using free fallback services (DuckDuckGo search and basic geocoding).
