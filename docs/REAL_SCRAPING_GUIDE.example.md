# 🌐 Real Web Scraping Configuration Guide (Example)

**Status:** 📋 **EXAMPLE TEMPLATE**  
**Updated:** August 15, 2025

> ⚠️ **SECURITY WARNING**: This is an example template. Never commit files with real API keys to version control!

## 🎯 Configuration Summary

This guide shows how to configure your Business Scraper application for **real web scraping**.

### ✅ Required Changes

1. **Environment Configuration**
   - `NODE_ENV=production` ✅
   - `ENABLE_REAL_SCRAPING=true` ✅

2. **API Keys to Configure** (Replace with your actual keys)
   - ✅ **Google Maps API**: `YOUR_GOOGLE_MAPS_API_KEY_HERE`
   - ✅ **Google Custom Search**: `YOUR_GOOGLE_CUSTOM_SEARCH_API_KEY_HERE`
   - ✅ **Search Engine ID**: `YOUR_SEARCH_ENGINE_ID_HERE`
   - ✅ **Azure AI Foundry**: `YOUR_AZURE_AI_FOUNDRY_KEY_HERE`

3. **Docker Configuration Updates**
   - Environment variables passed to container ✅
   - Production mode enforced ✅
   - Real scraping mode enabled ✅

## 🔐 Security Best Practices

### 🚨 NEVER commit files containing:
- Real API keys
- Production credentials
- Live authentication tokens
- Database connection strings with passwords
- Any sensitive configuration data

### ✅ Safe practices:
- Use environment variables for all secrets
- Create `.example` versions of configuration files
- Add sensitive files to `.gitignore`
- Use separate configuration files for different environments

## 🧪 How to Test Real Scraping

### Method 1: Web Interface
1. Open http://localhost/ in your browser
2. Log in with your configured credentials
3. Enter a real industry (e.g., "restaurants")
4. Enter a real ZIP code (e.g., "10001")
5. Click "Start Scraping"
6. **Real scraping indicators:**
   - Longer processing times (real web requests)
   - Actual business websites found
   - Real contact information extracted
   - No "demo" or "example" URLs

### Method 2: API Testing
```bash
# Test search functionality
curl -X POST http://localhost/api/scrape \
  -H "Content-Type: application/json" \
  -d '{
    "action": "search",
    "query": "restaurants",
    "zipCode": "10001",
    "radius": 5
  }'
```

## 📋 Configuration Checklist

- [ ] Copy this file to `REAL_SCRAPING_GUIDE.md` (add to .gitignore)
- [ ] Replace all placeholder API keys with real values
- [ ] Configure environment variables
- [ ] Test with real data
- [ ] Verify scraping results
- [ ] Document any custom configurations

## 🔧 Troubleshooting

### Common Issues:
1. **API Rate Limits**: Implement proper delays between requests
2. **Invalid API Keys**: Verify keys are active and have proper permissions
3. **Network Timeouts**: Increase timeout values for real web requests
4. **CAPTCHA Challenges**: Implement CAPTCHA solving or use residential proxies

### Performance Optimization:
- Use connection pooling
- Implement request caching
- Add retry logic with exponential backoff
- Monitor API usage and costs

## 📚 Additional Resources

- [Google Custom Search API Documentation](https://developers.google.com/custom-search/v1/introduction)
- [Google Maps API Documentation](https://developers.google.com/maps/documentation)
- [Azure AI Foundry Documentation](https://docs.microsoft.com/en-us/azure/cognitive-services/)
- [Web Scraping Best Practices](https://scrapfly.io/web-scraping/best-practices)

---

**Remember**: Always follow website terms of service and implement respectful scraping practices!
