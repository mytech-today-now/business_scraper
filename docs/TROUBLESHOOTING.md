# Troubleshooting Guide

![Version](https://img.shields.io/badge/version-3.10.1-blue.svg)
![Support](https://img.shields.io/badge/support-comprehensive-green.svg)

## 📋 Overview

This comprehensive troubleshooting guide covers common issues, solutions, and
debugging procedures for the Business Scraper Application v3.6.0. Use this guide
to quickly resolve problems and maintain optimal application performance.

## 🔍 Quick Diagnosis

### **Application Won't Start**

#### Symptoms

- Application fails to start
- Port already in use errors
- Module not found errors

#### Solutions

```bash
# Check if port 3000 is in use
lsof -i :3000

# Kill process using port 3000
kill -9 $(lsof -t -i:3000)

# Clear npm cache and reinstall
npm cache clean --force
rm -rf node_modules package-lock.json
npm install

# Start with different port
PORT=3001 npm run dev
```

### **Search Not Returning Results**

#### Symptoms

- Empty search results
- "No businesses found" messages
- Search timeouts

#### Solutions

```bash
# Check search engine configuration
curl http://localhost:3000/api/config

# Test with basic search
curl -X POST http://localhost:3000/api/search \
  -H "Content-Type: application/json" \
  -d '{"query": "restaurants", "location": "90210", "limit": 5}'

# Check search engine status
# Navigate to API Configuration page in the application
```

### **CRM Export Failures**

#### Symptoms

- Export button not working
- Validation errors during export
- Empty export files

#### Solutions

```bash
# Validate CRM template
curl -X POST http://localhost:3000/api/crm/validate \
  -H "Content-Type: application/json" \
  -d '{"templateId": "salesforce-lead-basic", "businessIds": ["test-id"]}'

# Check available templates
curl http://localhost:3000/api/crm/templates

# Clear browser cache and localStorage
# Open browser dev tools > Application > Storage > Clear All
```

## 🚨 Common Error Messages

### **"Module not found" Errors**

#### Error Message

```
Error: Cannot find module 'package-name'
```

#### Cause

Missing dependencies or corrupted node_modules

#### Solution

```bash
# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# For specific missing packages
npm install package-name

# Check for peer dependency issues
npm ls
```

### **"Port 3000 is already in use"**

#### Error Message

```
Error: listen EADDRINUSE: address already in use :::3000
```

#### Cause

Another process is using port 3000

#### Solution

```bash
# Find process using port 3000
lsof -i :3000

# Kill the process
kill -9 PID_NUMBER

# Or use different port
PORT=3001 npm run dev
```

### **"Database connection failed"**

#### Error Message

```
Error: Connection to database failed
```

#### Cause

Database not running or misconfigured

#### Solution

```bash
# Check PostgreSQL status
pg_ctl status

# Start PostgreSQL
pg_ctl start

# Check connection string in .env
cat .env | grep DATABASE_URL

# Test database connection
psql $DATABASE_URL -c "SELECT 1;"
```

### **"Search engine API key invalid"**

#### Error Message

```
Error: Invalid API key for search engine
```

#### Cause

Missing or incorrect API keys

#### Solution

```bash
# Check environment variables
cat .env | grep API_KEY

# Verify API keys in configuration
# Navigate to API Configuration page
# Test each search engine individually
```

## 🔧 Performance Issues

### **Slow Search Performance**

#### Symptoms

- Search takes longer than 30 seconds
- Browser becomes unresponsive
- High CPU usage

#### Diagnosis

```bash
# Check system resources
top
htop

# Monitor application logs
tail -f logs/application.log

# Check database performance
psql $DATABASE_URL -c "SELECT * FROM pg_stat_activity;"
```

#### Solutions

```bash
# Reduce search limit
# Use smaller radius
# Enable performance mode in settings

# Clear browser cache
# Restart application
# Check available memory
free -h
```

### **Memory Issues**

#### Symptoms

- Application crashes with out of memory errors
- Slow performance with large datasets
- Browser tabs become unresponsive

#### Solutions

```bash
# Increase Node.js memory limit
NODE_OPTIONS="--max-old-space-size=4096" npm start

# Enable garbage collection logging
NODE_OPTIONS="--gc-global" npm start

# Monitor memory usage
node --inspect app.js
# Open chrome://inspect in Chrome
```

### **Database Performance**

#### Symptoms

- Slow query execution
- Database timeouts
- High disk usage

#### Diagnosis

```sql
-- Check slow queries
SELECT query, mean_time, calls
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;

-- Check database size
SELECT pg_size_pretty(pg_database_size('business_scraper'));

-- Check table sizes
SELECT schemaname,tablename,attname,n_distinct,correlation
FROM pg_stats
WHERE tablename = 'businesses';
```

#### Solutions

```sql
-- Analyze tables
ANALYZE businesses;

-- Reindex tables
REINDEX TABLE businesses;

-- Update statistics
VACUUM ANALYZE;
```

## 🌐 Network and Connectivity Issues

### **Scraping Timeouts**

#### Symptoms

- Frequent timeout errors
- Incomplete scraping results
- "Request failed" messages

#### Solutions

```bash
# Increase timeout settings
# Check network connectivity
ping google.com

# Test with curl
curl -I https://example.com

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY
```

### **CORS Errors**

#### Symptoms

- Browser console shows CORS errors
- API requests blocked
- Cross-origin request failures

#### Solutions

```javascript
// Check CORS configuration in next.config.js
// Verify API endpoint URLs
// Check browser network tab for failed requests

// Temporary workaround for development
// Disable browser security (NOT for production)
// chrome --disable-web-security --user-data-dir=/tmp/chrome
```

### **SSL/TLS Issues**

#### Symptoms

- Certificate errors
- HTTPS connection failures
- "Insecure connection" warnings

#### Solutions

```bash
# Check certificate validity
openssl s_client -connect domain.com:443

# Update certificates
# Check system time
date

# Verify SSL configuration
curl -I https://your-domain.com
```

## 🔐 Authentication and Security Issues

### **Session Expired Errors**

#### Symptoms

- Frequent login prompts
- "Session expired" messages
- Authentication failures

#### Solutions

```bash
# Clear browser cookies and localStorage
# Check session configuration
# Verify system time is correct

# Check session storage
# Browser Dev Tools > Application > Cookies
```

### **Permission Denied Errors**

#### Symptoms

- File access errors
- Database permission errors
- API access denied

#### Solutions

```bash
# Check file permissions
ls -la

# Fix file permissions
chmod 755 directory
chmod 644 file

# Check database permissions
psql $DATABASE_URL -c "\du"

# Verify user roles and permissions
```

## 📱 Browser-Specific Issues

### **Chrome Issues**

#### Common Problems

- Memory leaks with large datasets
- Extension conflicts
- Cache issues

#### Solutions

```bash
# Clear Chrome cache
# Disable extensions
# Use incognito mode for testing
# Check Chrome console for errors
```

### **Firefox Issues**

#### Common Problems

- JavaScript performance
- Local storage limits
- CORS handling differences

#### Solutions

```bash
# Clear Firefox cache
# Check about:config settings
# Disable tracking protection for localhost
# Use Firefox developer tools
```

### **Safari Issues**

#### Common Problems

- Local storage restrictions
- WebSocket connection issues
- Date/time formatting differences

#### Solutions

```bash
# Enable developer tools
# Check Safari preferences
# Clear website data
# Test in other browsers
```

## 🔄 Data and Export Issues

### **Export File Corruption**

#### Symptoms

- Downloaded files won't open
- Incomplete export data
- Encoding issues

#### Solutions

```bash
# Check file size
ls -la downloads/

# Verify file format
file export.csv

# Check encoding
file -i export.csv

# Re-export with different format
# Try different browser
```

### **Data Validation Errors**

#### Symptoms

- CRM import failures
- Invalid data format errors
- Missing required fields

#### Solutions

```bash
# Use CRM template validation
# Check field mappings
# Verify data completeness

# Test with sample data
# Review validation errors in preview
```

## 🛠️ Development and Debugging

### **Enable Debug Mode**

```bash
# Set debug environment
DEBUG=* npm run dev

# Enable verbose logging
LOG_LEVEL=debug npm start

# Check application logs
tail -f logs/debug.log
```

### **Browser Developer Tools**

```javascript
// Check console for errors
console.log('Debug information')

// Monitor network requests
// Network tab in dev tools

// Check local storage
localStorage.getItem('key')

// Monitor memory usage
performance.memory
```

### **Database Debugging**

```sql
-- Enable query logging
SET log_statement = 'all';

-- Check current connections
SELECT * FROM pg_stat_activity;

-- Monitor query performance
SELECT query, total_time, calls
FROM pg_stat_statements
ORDER BY total_time DESC;
```

## 📞 Getting Help

### **Before Contacting Support**

1. **Check this troubleshooting guide**
2. **Review application logs**
3. **Test in different browser**
4. **Verify system requirements**
5. **Check network connectivity**

### **Information to Provide**

- **Application version**: Check VERSION file
- **Operating system**: Windows/macOS/Linux version
- **Browser**: Name and version
- **Error messages**: Exact error text
- **Steps to reproduce**: Detailed reproduction steps
- **Screenshots**: If applicable

### **Support Channels**

- **GitHub Issues**: For bugs and feature requests
- **Documentation**: Check docs/ directory
- **Community**: Development team discussions

### **Log Collection**

```bash
# Collect application logs
tar -czf logs.tar.gz logs/

# Export browser console
# Right-click in console > Save as...

# System information
uname -a > system-info.txt
npm list > package-info.txt
```

## 🔄 Recovery Procedures

### **Application Reset**

```bash
# Complete application reset
npm run reset

# Clear all data
rm -rf data/ logs/
npm run setup

# Restore from backup
cp backup/data/* data/
```

### **Database Recovery**

```sql
-- Backup current database
pg_dump business_scraper > backup.sql

-- Restore from backup
psql business_scraper < backup.sql

-- Reset to initial state
DROP DATABASE business_scraper;
CREATE DATABASE business_scraper;
npm run migrate
```

### **Configuration Reset**

```bash
# Reset to default configuration
cp .env.example .env
npm run config:reset

# Clear browser data
# Clear localStorage and cookies
# Reset API settings to defaults
```

## 📊 Monitoring and Maintenance

### **Health Checks**

```bash
# Application health
curl http://localhost:3000/api/health

# Database health
psql $DATABASE_URL -c "SELECT 1;"

# System resources
df -h
free -h
```

### **Regular Maintenance**

```bash
# Update dependencies
npm update

# Clean logs
find logs/ -name "*.log" -mtime +7 -delete

# Optimize database
psql $DATABASE_URL -c "VACUUM ANALYZE;"

# Clear temporary files
rm -rf tmp/*
```

This troubleshooting guide is regularly updated. For the latest version, check
the documentation repository.
