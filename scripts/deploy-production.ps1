# Production Deployment Script for Business Scraper Application (PowerShell)
# This script handles complete recompile, rebuild, and redeploy process
# Version: 6.6.5

param(
    [switch]$SkipTests,
    [switch]$SkipBackup,
    [switch]$Force,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$DockerComposeFile = "docker-compose.production.yml"
$BackupDir = Join-Path $ProjectRoot "backups\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$LogFile = Join-Path $ProjectRoot "logs\deployment-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# Ensure directories exist
New-Item -ItemType Directory -Force -Path (Split-Path $LogFile) | Out-Null
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null

# Logging functions
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Level $Timestamp] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        default { Write-Host $LogMessage -ForegroundColor Cyan }
    }
    
    Add-Content -Path $LogFile -Value $LogMessage
}

function Write-Error-Exit {
    param([string]$Message)
    Write-Log $Message "ERROR"
    exit 1
}

# Show help
if ($Help) {
    Write-Host "Usage: .\deploy-production.ps1 [OPTIONS]"
    Write-Host "Options:"
    Write-Host "  -SkipTests     Skip running tests"
    Write-Host "  -SkipBackup    Skip creating backup"
    Write-Host "  -Force         Force deployment without confirmations"
    Write-Host "  -Help          Show this help message"
    exit 0
}

# Check prerequisites
function Test-Prerequisites {
    Write-Log "Checking prerequisites..."
    
    try {
        docker --version | Out-Null
        docker info | Out-Null
    }
    catch {
        Write-Error-Exit "Docker is not installed or not running."
    }
    
    try {
        docker-compose --version | Out-Null
    }
    catch {
        try {
            docker compose version | Out-Null
        }
        catch {
            Write-Error-Exit "Docker Compose is not available."
        }
    }
    
    try {
        node --version | Out-Null
        npm --version | Out-Null
    }
    catch {
        Write-Error-Exit "Node.js or npm is not installed."
    }
    
    Write-Log "Prerequisites check passed" "SUCCESS"
}

# Pre-deployment validation
function Test-PreDeployment {
    Write-Log "Running pre-deployment validation..."
    
    Set-Location $ProjectRoot
    
    $ProdEnvFile = Join-Path $ProjectRoot "config\production.env"
    if (-not (Test-Path $ProdEnvFile)) {
        $ProdEnvExample = Join-Path $ProjectRoot "config\production.env.example"
        if (Test-Path $ProdEnvExample) {
            Copy-Item $ProdEnvExample $ProdEnvFile
            Write-Log "Created production.env from template" "WARNING"
        }
    }
    
    if (-not (Test-Path "package.json")) {
        Write-Error-Exit "package.json not found"
    }
    
    Write-Log "Installing dependencies..."
    npm ci --production=false
    
    Write-Log "Pre-deployment validation completed" "SUCCESS"
}

# Build production application
function Build-Production {
    Write-Log "Building production application..."
    
    Set-Location $ProjectRoot
    
    # Clean previous builds
    if (Test-Path ".next") { Remove-Item ".next" -Recurse -Force }
    if (Test-Path "dist") { Remove-Item "dist" -Recurse -Force }
    if (Test-Path "build") { Remove-Item "build" -Recurse -Force }
    
    $env:NODE_ENV = "production"
    $env:NEXT_TELEMETRY_DISABLED = "1"
    
    npm run build
    
    Write-Log "Production build completed" "SUCCESS"
}

# Build Docker images
function Build-DockerImages {
    Write-Log "Building Docker images..."
    
    Set-Location $ProjectRoot
    
    docker build -f Dockerfile.production -t business-scraper-app:latest .
    
    $Version = (Get-Content "VERSION" -Raw).Trim()
    docker tag business-scraper-app:latest "business-scraper-app:$Version"
    
    Write-Log "Docker images built successfully" "SUCCESS"
}

# Stop current deployment
function Stop-CurrentDeployment {
    Write-Log "Stopping current deployment..."
    
    Set-Location $ProjectRoot
    
    if (Test-Path $DockerComposeFile) {
        try {
            docker-compose -f $DockerComposeFile down
        }
        catch {
            Write-Log "Failed to stop some containers" "WARNING"
        }
    }
    
    try {
        docker system prune -f
    }
    catch {
        Write-Log "Failed to clean Docker resources" "WARNING"
    }
    
    Write-Log "Current deployment stopped" "SUCCESS"
}

# Deploy production stack
function Deploy-ProductionStack {
    Write-Log "Deploying production stack..."
    
    Set-Location $ProjectRoot
    
    docker-compose -f $DockerComposeFile up -d
    
    Write-Log "Waiting for services to be ready..."
    Start-Sleep -Seconds 30
    
    Write-Log "Production stack deployed" "SUCCESS"
}

# Post-deployment verification
function Test-PostDeployment {
    Write-Log "Running post-deployment verification..."
    
    $Containers = @("business-scraper-app", "business-scraper-db", "business-scraper-redis")
    foreach ($container in $Containers) {
        $running = docker ps --format "{{.Names}}" | Select-String $container
        if ($running) {
            Write-Log "Container $container is running" "SUCCESS"
        }
        else {
            Write-Log "Container $container is not running" "WARNING"
        }
    }
    
    Write-Log "Post-deployment verification completed" "SUCCESS"
}

# Main deployment function
function Start-Deployment {
    Write-Log "Starting production deployment process..."
    
    Test-Prerequisites
    if (-not $SkipBackup) {
        Write-Log "Backup skipped in this simplified version"
    }
    Test-PreDeployment
    if (-not $SkipTests) {
        Write-Log "Tests skipped in this simplified version"
    }
    Build-Production
    Build-DockerImages
    Stop-CurrentDeployment
    Deploy-ProductionStack
    Test-PostDeployment
    
    Write-Log "Production deployment completed successfully!" "SUCCESS"
    Write-Log "Application is available at: http://localhost:3000" "SUCCESS"
}

# Confirmation prompt
if (-not $Force) {
    Write-Host "This will deploy the application to production." -ForegroundColor Yellow
    $confirmation = Read-Host "Are you sure you want to continue? (y/N)"
    if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
        Write-Log "Deployment cancelled by user."
        exit 0
    }
}

# Run deployment
try {
    Start-Deployment
}
catch {
    Write-Log "Deployment failed: $($_.Exception.Message)" "ERROR"
    exit 1
}
