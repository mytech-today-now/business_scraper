#!/bin/bash

# Production Health Check Script for Business Scraper Application
# This script monitors the health of all production services

echo "=== Business Scraper Production Health Check ==="
echo "Timestamp: $(date)"
echo ""

# Check Docker containers
echo "🐳 Docker Container Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep business-scraper

echo ""

# Check application health endpoint
echo "🏥 Application Health Check:"
HEALTH_RESPONSE=$(curl -s http://localhost:3000/api/health)
if [ $? -eq 0 ]; then
    echo "✅ Application is responding"
    echo "Raw Health Response: $HEALTH_RESPONSE"
else
    echo "❌ Application health check failed"
fi

echo ""

# Check database connectivity
echo "🗄️ Database Connectivity:"
if docker exec business-scraper-db pg_isready -U postgres -d business_scraper > /dev/null 2>&1; then
    echo "✅ PostgreSQL database is ready"
else
    echo "❌ PostgreSQL database connection failed"
fi

echo ""

# Check Redis connectivity
echo "🔴 Redis Connectivity:"
if docker exec business-scraper-redis redis-cli ping > /dev/null 2>&1; then
    echo "✅ Redis cache is responding"
else
    echo "❌ Redis connection failed"
fi

echo ""

# Check disk usage
echo "💾 Disk Usage:"
df -h / | tail -1 | awk '{print "Root filesystem: " $5 " used (" $3 "/" $2 ")"}'

echo ""

# Check memory usage (Windows compatible)
echo "🧠 System Memory:"
echo "Memory information available via Docker stats"

echo ""

# Check application logs for errors
echo "📋 Recent Application Logs (last 5 lines):"
docker logs business-scraper-app --tail 5 2>/dev/null || echo "Could not retrieve application logs"

echo ""
echo "=== Health Check Complete ==="
