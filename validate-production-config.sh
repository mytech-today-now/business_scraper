#!/bin/bash

# Production Configuration Validation Script
# Validates Docker production environment setup

echo "🐳 Docker Production Configuration Validation"
echo "=============================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASSED=0
FAILED=0
WARNINGS=0

# Function to check file existence
check_file() {
    if [ -f "$1" ]; then
        echo -e "  ${GREEN}✅ $1${NC}"
        ((PASSED++))
    else
        echo -e "  ${RED}❌ $1 - Missing${NC}"
        ((FAILED++))
    fi
}

# Function to check environment variable
check_env_var() {
    local var_name="$1"
    local expected="$2"
    local critical="$3"
    
    if grep -q "^${var_name}=" .env; then
        local value=$(grep "^${var_name}=" .env | cut -d'=' -f2-)
        if [ -n "$expected" ] && [ "$value" != "$expected" ]; then
            if [ "$critical" = "true" ]; then
                echo -e "  ${RED}❌ ${var_name}=${value} - Expected: ${expected}${NC}"
                ((FAILED++))
            else
                echo -e "  ${YELLOW}⚠️  ${var_name}=${value} - Recommended: ${expected}${NC}"
                ((WARNINGS++))
            fi
        else
            echo -e "  ${GREEN}✅ ${var_name}=${value}${NC}"
            ((PASSED++))
        fi
    else
        if [ "$critical" = "true" ]; then
            echo -e "  ${RED}❌ ${var_name} - Missing (Critical)${NC}"
            ((FAILED++))
        else
            echo -e "  ${YELLOW}⚠️  ${var_name} - Missing (Optional)${NC}"
            ((WARNINGS++))
        fi
    fi
}

# Check required files
echo -e "\n${BLUE}📁 Checking required files...${NC}"
check_file ".env"
check_file ".env.docker.production.template"
check_file "docker-compose.production.yml"
check_file "Dockerfile.production"

# Check Docker-specific environment variables
if [ -f ".env" ]; then
    echo -e "\n${BLUE}🔧 Validating .env configuration...${NC}"
    check_env_var "NODE_ENV" "production" "true"
    check_env_var "HOSTNAME" "0.0.0.0" "true"
    check_env_var "DB_HOST" "postgres" "true"
    check_env_var "REDIS_HOST" "redis" "true"
    check_env_var "DOCKER_DEPLOYMENT" "true" "false"
    check_env_var "RESTART_POLICY" "unless-stopped" "false"
    
    # Check for placeholder values
    echo -e "\n${BLUE}🔐 Checking for placeholder values...${NC}"
    if grep -q "YOUR_PRODUCTION_" .env; then
        echo -e "  ${YELLOW}⚠️  Found placeholder values that need to be replaced:${NC}"
        grep "YOUR_PRODUCTION_" .env | while read line; do
            echo -e "    ${YELLOW}• $line${NC}"
        done
        ((WARNINGS++))
    else
        echo -e "  ${GREEN}✅ No placeholder values found${NC}"
        ((PASSED++))
    fi
    
    # Check for yourdomain.com placeholders
    if grep -q "yourdomain.com" .env; then
        echo -e "  ${YELLOW}⚠️  Found domain placeholders that need to be replaced:${NC}"
        grep "yourdomain.com" .env | while read line; do
            echo -e "    ${YELLOW}• $line${NC}"
        done
        ((WARNINGS++))
    fi
fi

# Summary
echo -e "\n${BLUE}📊 Validation Summary${NC}"
echo "==================="
echo -e "${GREEN}✅ Passed: $PASSED${NC}"
echo -e "${YELLOW}⚠️  Warnings: $WARNINGS${NC}"
echo -e "${RED}❌ Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 Basic validation passed!${NC}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠️  Please address warnings before production deployment.${NC}"
    else
        echo -e "${GREEN}Ready for production deployment.${NC}"
    fi
    exit 0
else
    echo -e "\n${RED}❌ Validation failed!${NC}"
    echo -e "${RED}Please address critical issues before deployment.${NC}"
    exit 1
fi
