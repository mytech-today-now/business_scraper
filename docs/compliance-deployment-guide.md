# Enterprise Compliance Framework - Deployment Guide

This guide provides step-by-step instructions for deploying the Business Scraper
application with full enterprise compliance features including SOC 2 Type II,
GDPR, and CCPA compliance.

## 📋 **Prerequisites**

### System Requirements

- **Node.js**: v18.0.0 or higher
- **PostgreSQL**: v14.0 or higher
- **Redis**: v6.0 or higher (optional, for session management)
- **SSL Certificate**: Required for production deployment
- **Email Service**: SMTP, SendGrid, or AWS SES for compliance notifications

### Security Requirements

- **Encryption Keys**: 256-bit AES encryption keys
- **SSL/TLS**: Valid SSL certificates for HTTPS
- **Firewall**: Properly configured network security
- **Backup Strategy**: Automated database backups
- **Monitoring**: Application and security monitoring

## 🔧 **Step 1: Environment Configuration**

### 1.1 Copy Environment Template

```bash
cp .env.example .env
```

### 1.2 Generate Security Keys

```bash
# Generate encryption keys
npm run secrets:generate

# Generate production secrets
npm run secrets:prod
```

### 1.3 Configure Core Settings

Edit `.env` with your production values:

```bash
# Application
NODE_ENV=production
NEXT_PUBLIC_APP_URL=https://yourdomain.com
PORT=3000

# Database
DATABASE_URL=postgresql://username:password@host:5432/database

# Security
ENCRYPTION_MASTER_KEY=your_64_character_hex_key
NEXTAUTH_SECRET=your_nextauth_secret
JWT_SECRET=your_jwt_secret
```

### 1.4 Configure Compliance Settings

```bash
# GDPR
GDPR_ENABLED=true
GDPR_DPO_EMAIL=dpo@yourcompany.com
GDPR_COMPANY_NAME=Your Company Name

# CCPA
CCPA_ENABLED=true
CCPA_CONTACT_EMAIL=privacy@yourcompany.com

# SOC 2
SOC2_ENABLED=true
SOC2_AUDIT_FIRM=Your Audit Firm
```

## 🗄️ **Step 2: Database Setup**

### 2.1 Create Database

```sql
-- Connect to PostgreSQL as superuser
CREATE DATABASE business_scraper_prod;
CREATE USER business_scraper_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE business_scraper_prod TO business_scraper_user;
```

### 2.2 Run Database Migrations

```bash
# Run compliance schema migration
npm run db:migrate

# Verify migration status
npm run db:status
```

### 2.3 Initialize Compliance Data

```bash
# Set up default retention policies and compliance settings
npm run compliance:setup
```

## 📧 **Step 3: Email Service Configuration**

### Option A: SMTP Configuration

```bash
EMAIL_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
```

### Option B: SendGrid Configuration

```bash
EMAIL_PROVIDER=sendgrid
SENDGRID_API_KEY=your_sendgrid_api_key
```

### Option C: AWS SES Configuration

```bash
EMAIL_PROVIDER=aws-ses
AWS_SES_ACCESS_KEY_ID=your_access_key
AWS_SES_SECRET_ACCESS_KEY=your_secret_key
AWS_SES_REGION=us-east-1
```

## 🔐 **Step 4: SSL/TLS Configuration**

### 4.1 Obtain SSL Certificate

```bash
# Using Let's Encrypt (recommended)
sudo certbot certonly --standalone -d yourdomain.com

# Or upload your certificate files
SSL_CERT_PATH=/path/to/cert.pem
SSL_KEY_PATH=/path/to/private.key
```

### 4.2 Configure HTTPS

```bash
SSL_ENABLED=true
SECURITY_HEADERS_ENABLED=true
HSTS_MAX_AGE=31536000
```

## 🚀 **Step 5: Application Deployment**

### 5.1 Install Dependencies

```bash
npm ci --production
```

### 5.2 Build Application

```bash
npm run build
```

### 5.3 Run Compliance Tests

```bash
# Test all compliance features
npm run compliance:test

# Test specific compliance areas
npm run compliance:gdpr-test
npm run compliance:ccpa-test
npm run compliance:soc2-test
```

### 5.4 Validate Configuration

```bash
# Validate compliance configuration
npm run compliance:validate

# Validate environment configuration
npm run config:validate
```

### 5.5 Start Application

```bash
# Production start
npm start

# Or with PM2 (recommended)
pm2 start ecosystem.config.js --env production
```

## 📊 **Step 6: Monitoring & Alerting**

### 6.1 Configure Health Checks

```bash
# Health check endpoint
HEALTH_CHECK_ENDPOINT=/health
HEALTH_CHECK_TOKEN=your_secure_token
```

### 6.2 Set Up Monitoring

```bash
# Sentry for error tracking
SENTRY_DSN=your_sentry_dsn

# DataDog for metrics
DATADOG_API_KEY=your_datadog_key
```

### 6.3 Configure Compliance Alerts

```bash
# Critical event alerts
CRITICAL_EVENT_ALERTS=true
ALERT_WEBHOOK_URL=https://your-monitoring.com/webhook
ALERT_EMAIL=security@yourcompany.com

# Data breach detection
BREACH_DETECTION_ENABLED=true
BREACH_NOTIFICATION_EMAIL=security@yourcompany.com
```

## 🔄 **Step 7: Backup & Recovery**

### 7.1 Database Backup

```bash
# Configure automated backups
BACKUP_ENABLED=true
BACKUP_SCHEDULE=0 2 * * *
BACKUP_RETENTION_DAYS=30
```

### 7.2 Encryption Key Backup

```bash
# Securely backup encryption keys
# Store in secure key management system
# Never store in version control
```

## ✅ **Step 8: Post-Deployment Verification**

### 8.1 Compliance Checklist

```bash
# Run compliance audit
npm run compliance:audit

# Generate compliance report
npm run compliance:report
```

### 8.2 Security Verification

- [ ] HTTPS is working correctly
- [ ] Security headers are present
- [ ] Encryption is functioning
- [ ] Audit logging is active
- [ ] Consent management is working
- [ ] Data retention policies are active
- [ ] Email notifications are working
- [ ] Backup systems are operational

### 8.3 Functional Testing

- [ ] User registration and login
- [ ] Consent banner functionality
- [ ] Privacy dashboard access
- [ ] DSAR request processing
- [ ] CCPA opt-out functionality
- [ ] Data export features
- [ ] Scraping operations with compliance

## 🔧 **Step 9: Ongoing Maintenance**

### 9.1 Regular Tasks

```bash
# Weekly compliance audit
npm run compliance:audit

# Monthly compliance report
npm run compliance:report

# Quarterly security assessment
npm run security-test-prod
```

### 9.2 Key Rotation

- Rotate encryption keys annually
- Update SSL certificates before expiration
- Review and update access credentials

### 9.3 Compliance Updates

- Monitor regulatory changes
- Update privacy policies as needed
- Review and update retention policies
- Conduct annual compliance training

## 🚨 **Troubleshooting**

### Common Issues

#### Database Connection Issues

```bash
# Check database connectivity
npm run db:status

# Reset database if needed
npm run db:reset
```

#### Encryption Issues

```bash
# Verify encryption key format
node -e "console.log(process.env.ENCRYPTION_MASTER_KEY?.length)"
# Should output: 64
```

#### Email Service Issues

```bash
# Test email configuration
node scripts/test-email.js
```

#### SSL Certificate Issues

```bash
# Check certificate validity
openssl x509 -in cert.pem -text -noout
```

## 📞 **Support & Resources**

### Documentation

- [Compliance Framework Overview](./compliance-implementation-summary.md)
- [API Documentation](./api-documentation.md)
- [Security Guidelines](./security-guidelines.md)

### Emergency Contacts

- **Security Team**: security@yourcompany.com
- **Compliance Officer**: compliance@yourcompany.com
- **Technical Support**: support@yourcompany.com

### Compliance Resources

- [GDPR Compliance Guide](https://gdpr.eu/)
- [CCPA Compliance Guide](https://oag.ca.gov/privacy/ccpa)
- [SOC 2 Framework](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html)

---

**⚠️ Important Security Notes:**

1. Never commit `.env` files to version control
2. Use strong, unique passwords for all services
3. Regularly update dependencies and security patches
4. Monitor logs for suspicious activity
5. Conduct regular security assessments
6. Maintain incident response procedures
7. Keep compliance documentation up to date
