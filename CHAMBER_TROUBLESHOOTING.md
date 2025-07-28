# Chamber of Commerce Processing Troubleshooting

## Issue Description
The Chamber of Commerce processing functionality is failing with 500 Internal Server Error when trying to process `chamberofcommerce.com` URLs.

## Recent Fixes Applied

### 1. Enhanced Error Handling
- Added retry logic for browser initialization
- Improved error messages and logging
- Added fallback mechanisms for failed processing

### 2. Browser Configuration Improvements
- Increased timeouts for browser operations
- Added platform-specific configurations (Windows/Linux)
- Added memory management options
- Enhanced Puppeteer launch arguments

### 3. API Response Improvements
- Better error status codes (400 for invalid URLs, 504 for timeouts)
- More detailed error messages
- Added service status information

### 4. Health Check Endpoint
- Created `/api/health/chamber` endpoint for diagnostics
- Browser version checking
- Service status monitoring

## Testing the Fix

### 1. Run the Diagnostic Script
```bash
node scripts/test-chamber-processing.js
```

### 2. Manual Health Check
```bash
curl http://localhost:3000/api/health/chamber
```

### 3. Test Chamber Processing
```bash
curl -X POST http://localhost:3000/api/search \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "chamber-of-commerce",
    "url": "https://www.chamberofcommerce.com/business-directory/illinois/barrington/pet-groomer/2005503583-the-grooming-lodge",
    "maxResults": 5,
    "maxPagesPerSite": 20
  }'
```

## Common Issues and Solutions

### 1. Puppeteer Installation Issues
**Problem**: Browser fails to initialize
**Solution**: 
```bash
npm install puppeteer --force
# or
npx puppeteer browsers install chrome
```

### 2. Memory Issues
**Problem**: Browser crashes or timeouts
**Solution**: 
- Increase Node.js memory limit: `node --max-old-space-size=4096`
- Restart the development server
- Close other memory-intensive applications

### 3. Network Connectivity
**Problem**: Cannot reach Chamber of Commerce website
**Solution**:
- Check internet connection
- Verify firewall settings
- Test URL accessibility in browser

### 4. Windows-Specific Issues
**Problem**: Browser fails on Windows
**Solution**:
- Ensure Windows Defender isn't blocking Puppeteer
- Run as administrator if needed
- Check antivirus software settings

## Monitoring and Logs

### Check Server Logs
Look for these log entries:
- `COCPScraping` - Chamber service logs
- `Search API` - API endpoint logs
- `Health Check` - Health check logs

### Key Error Patterns
- `Browser initialization failed` - Puppeteer setup issue
- `timeout` - Network or page loading issue
- `ECONNREFUSED` - Database connection issue (separate from Chamber processing)

## Fallback Behavior

If Chamber processing fails, the system now:
1. Returns a fallback result with the original Chamber URL
2. Logs detailed error information
3. Allows users to manually visit the Chamber page
4. Continues processing other search results

## Performance Optimization

### Current Settings
- Browser timeout: 60 seconds
- Page navigation timeout: 45 seconds
- Selector wait timeout: 20 seconds
- Rate limiting: 2 seconds between requests
- Max retries: 3 attempts

### Tuning Recommendations
- Reduce timeouts for faster failure detection
- Increase retries for unreliable networks
- Adjust rate limiting based on Chamber website response

## Next Steps

1. **Monitor the fix**: Check if the 500 errors are resolved
2. **Performance testing**: Test with multiple concurrent requests
3. **Error tracking**: Monitor error rates and patterns
4. **Optimization**: Fine-tune timeouts and retry logic based on real usage

## Contact

If issues persist:
1. Check the diagnostic script output
2. Review server logs for detailed error messages
3. Test the health check endpoint
4. Consider temporarily disabling Chamber processing if critical
