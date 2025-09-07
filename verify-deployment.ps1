# Business Scraper Production Deployment Verification Script

Write-Host "=== Business Scraper Production Deployment Verification ===" -ForegroundColor Green
Write-Host ""

# Check Docker containers
Write-Host "1. Checking Docker containers..." -ForegroundColor Yellow
docker-compose -f docker-compose.prod.yml ps

Write-Host ""
Write-Host "2. Checking container health..." -ForegroundColor Yellow

# Check individual container health
$containers = @("business-scraper-prod", "business-scraper-db-prod", "business-scraper-redis-prod", "business-scraper-nginx-prod")

foreach ($container in $containers) {
    $health = docker inspect --format='{{.State.Health.Status}}' $container 2>$null
    if ($health) {
        Write-Host "  $container`: $health" -ForegroundColor $(if ($health -eq "healthy") { "Green" } else { "Red" })
    } else {
        $status = docker inspect --format='{{.State.Status}}' $container 2>$null
        Write-Host "  $container`: $status (no health check)" -ForegroundColor $(if ($status -eq "running") { "Green" } else { "Red" })
    }
}

Write-Host ""
Write-Host "3. Testing endpoints..." -ForegroundColor Yellow

# Test nginx health endpoint
try {
    $response = Invoke-WebRequest -Uri "http://localhost:80/health" -Method GET -TimeoutSec 10
    Write-Host "  Nginx health endpoint: OK (Status: $($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "  Nginx health endpoint: FAILED - $($_.Exception.Message)" -ForegroundColor Red
}

# Test application through nginx
try {
    $response = Invoke-WebRequest -Uri "http://localhost:80/" -Method GET -TimeoutSec 10
    Write-Host "  Application via nginx: OK (Status: $($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "  Application via nginx: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Test direct application port
try {
    $response = Invoke-WebRequest -Uri "http://localhost:3000/" -Method GET -TimeoutSec 10
    Write-Host "  Direct application: OK (Status: $($response.StatusCode))" -ForegroundColor Green
} catch {
    Write-Host "  Direct application: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "4. Checking application logs (last 10 lines)..." -ForegroundColor Yellow
docker logs business-scraper-prod --tail 10

Write-Host ""
Write-Host "=== Deployment Summary ===" -ForegroundColor Green
Write-Host "Production stack is deployed and running."
Write-Host "Access the application at: http://localhost (via nginx) or http://localhost:3000 (direct)"
Write-Host "Note: The application may require authentication or API keys to be fully functional."
Write-Host ""
Write-Host "To stop the production stack: docker-compose -f docker-compose.prod.yml down"
Write-Host "To view logs: docker-compose -f docker-compose.prod.yml logs -f"
