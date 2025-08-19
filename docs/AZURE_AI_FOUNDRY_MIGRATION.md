# Azure AI Foundry Migration Guide

## 🚨 Important: Bing Search API Deprecation

Microsoft is discontinuing the Bing Search API in **August 2025**. This application has been updated to support the new **"Grounding with Bing Custom Search"** service through Azure AI Foundry.

## What's Changing

### Old Service (Deprecated)
- **Service**: Bing Search API v7
- **Endpoint**: `https://api.bing.microsoft.com/v7.0/search`
- **Status**: ⚠️ **Discontinued August 2025**

### New Service (Current)
- **Service**: Azure AI Foundry - "Grounding with Bing Custom Search"
- **Endpoint**: `https://[your-resource-name].cognitiveservices.azure.com/`
- **Status**: ✅ **Active and Supported**

## Migration Steps

### 1. Create Azure AI Foundry Resource

1. Go to the [Azure Portal](https://portal.azure.com)
2. Search for "Grounding with Bing Custom Search"
3. Create a new resource with these settings:
   - **Resource Name**: `businessscraper` (or your preferred name)
   - **Region**: `eastus` (or your preferred region)
   - **Pricing Tier**: Select based on your usage needs

### 2. Get Your Credentials

After creating the resource, you'll receive:

```
KEY 1: ••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••
KEY 2: ••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••
Location/Region: eastus
Endpoint: https://businessscraper.cognitiveservices.azure.com/
```

### 3. Update Application Configuration

#### Option A: Using the Configuration UI (Recommended)
1. Open the application
2. Go to **Settings** → **API Configuration**
3. Find the **Azure AI Foundry** section
4. Enter your credentials:
   - **API Key**: Use either Key 1 or Key 2
   - **Endpoint URL**: Your full endpoint URL
   - **Region**: Your selected region

#### Option B: Using Environment Variables
Update your `.env.local` file:

```bash
# Azure AI Foundry - Grounding with Bing Custom Search
AZURE_AI_FOUNDRY_API_KEY=your_key_1_or_key_2_here
AZURE_AI_FOUNDRY_ENDPOINT=https://businessscraper.cognitiveservices.azure.com/
AZURE_AI_FOUNDRY_REGION=eastus

# Remove or comment out old Bing API key
# BING_SEARCH_API_KEY=old_bing_key
```

### 4. Test the Configuration

1. In the application, go to **Settings** → **API Configuration**
2. Click the **Test** button next to Azure AI Foundry
3. Verify you see a green checkmark indicating successful connection

## Key Differences

### API Changes
- **Method**: Changed from GET to POST requests
- **Endpoint**: New Azure AI Foundry endpoint structure
- **Authentication**: Still uses `Ocp-Apim-Subscription-Key` header
- **Response Format**: Compatible with existing Bing Search response format

### Features Maintained
- ✅ Same search quality and results
- ✅ All existing search filters and parameters
- ✅ Domain blacklist functionality
- ✅ Enhanced contact extraction
- ✅ Business-focused result filtering

### New Benefits
- 🔄 **Future-proof**: Supported long-term by Microsoft
- 🚀 **Enhanced Performance**: Improved search capabilities
- 🔒 **Better Security**: Modern Azure security features
- 📊 **Advanced Analytics**: Better usage tracking and monitoring

## Troubleshooting

### Common Issues

#### 1. "Azure AI Foundry credentials not configured"
- **Solution**: Ensure you've entered the API key and endpoint in the configuration

#### 2. "Azure AI Foundry API error: 401"
- **Solution**: Check that your API key is correct and hasn't expired

#### 3. "Azure AI Foundry API error: 403"
- **Solution**: Verify your Azure subscription is active and the resource is properly configured

#### 4. "No search results returned"
- **Solution**: Check that your endpoint URL is correct and includes the full domain

### Getting Help

1. **Check Configuration**: Verify all credentials are entered correctly
2. **Test Connection**: Use the built-in test feature in the configuration UI
3. **Check Azure Portal**: Ensure your resource is active and properly configured
4. **Review Logs**: Check the browser console for detailed error messages

## Pricing Information

The new Azure AI Foundry service has different pricing than the old Bing Search API. Check the [Azure Pricing Calculator](https://azure.microsoft.com/pricing/calculator/) for current rates.

## Timeline

- **Now**: New Azure AI Foundry integration available
- **August 2025**: Bing Search API discontinued
- **Recommendation**: Migrate as soon as possible to ensure uninterrupted service

## Support

For technical issues with the migration:
1. Check this guide first
2. Review the application logs
3. Verify your Azure resource configuration
4. Contact your Azure support team for Azure-specific issues

---

**Note**: This migration maintains full backward compatibility. Your existing search configurations, domain blacklists, and other settings will continue to work without changes.
