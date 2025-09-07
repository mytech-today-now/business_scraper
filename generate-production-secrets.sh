#!/bin/bash

# Production Secrets Generator
# Generates secure secrets for Docker production deployment

echo "🔐 Production Secrets Generator"
echo "==============================="

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to generate secure random string
generate_random() {
    local length=${1:-32}
    openssl rand -hex $length | head -c $((length * 2))
}

# Function to generate secure password
generate_password() {
    local length=${1:-24}
    openssl rand -base64 $length | tr -d "=+/" | cut -c1-$length
}

# Function to generate JWT secret
generate_jwt_secret() {
    openssl rand -base64 64 | tr -d "=+/" | cut -c1-64
}

echo -e "\n${BLUE}🔑 Generated Production Secrets:${NC}"
echo "=================================="

echo -e "\n${YELLOW}# Database Secrets${NC}"
echo "DB_PASSWORD=$(generate_password 32)"
echo "POSTGRES_PASSWORD=$(generate_password 32)"

echo -e "\n${YELLOW}# Redis Secrets${NC}"
echo "REDIS_PASSWORD=$(generate_password 24)"

echo -e "\n${YELLOW}# Admin Credentials${NC}"
echo "ADMIN_PASSWORD=$(generate_password 20)"

echo -e "\n${YELLOW}# Encryption & JWT Secrets${NC}"
echo "ENCRYPTION_KEY=$(generate_random 32)"
echo "JWT_SECRET=$(generate_jwt_secret)"
echo "SESSION_SECRET=$(generate_random 32)"

echo -e "\n${YELLOW}# Monitoring Secrets${NC}"
echo "GRAFANA_PASSWORD=$(generate_password 16)"

echo -e "\n${YELLOW}# CSP Nonce${NC}"
echo "NEXT_PUBLIC_CSP_NONCE=$(generate_random 16)"

echo -e "\n${GREEN}✅ Secrets generated successfully!${NC}"
echo -e "\n${YELLOW}⚠️  IMPORTANT SECURITY NOTES:${NC}"
echo "• Copy these values to your .env file"
echo "• Never commit these secrets to version control"
echo "• Store them securely (password manager, vault, etc.)"
echo "• Use Docker secrets for additional security in production"
echo "• Regenerate secrets periodically for security"

echo -e "\n${BLUE}📋 Next Steps:${NC}"
echo "1. Copy the generated secrets above"
echo "2. Update your .env file with these values"
echo "3. Replace API keys with your production keys"
echo "4. Update domain URLs with your production domain"
echo "5. Run validation: ./validate-production-config.sh"
echo "6. Deploy: docker-compose -f docker-compose.production.yml up -d"
