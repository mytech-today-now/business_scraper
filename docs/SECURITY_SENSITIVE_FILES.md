# 🔐 Security Guide: Handling Sensitive Files

## 🚨 Critical Security Notice

This repository is configured to **automatically exclude sensitive files** containing API keys, credentials, and other confidential information from version control.

## 📋 Protected File Patterns

The `.gitignore` file automatically excludes:

### 🔑 API Keys & Credentials
- `REAL_SCRAPING_GUIDE.md` - Contains actual API keys
- `*api-credentials*.txt` - API credential backup files
- `*-with-keys.md` - Documentation with real keys
- `*production-config*.md` - Production configuration files

### 🗂️ Sensitive Documentation
- `*SECRET*.md` - Secret documentation
- `*PRIVATE*.md` - Private documentation
- `*CREDENTIAL*.md` - Credential files
- `*-sensitive.md` - Sensitive configuration files

### 💾 Backup & Temporary Files
- `*.backup` - Backup files
- `*-backup.*` - Backup files with extensions
- `*.tmp` - Temporary files
- `/tmp/` - Temporary directories

### 🚀 Deployment & Infrastructure
- `deploy-*.sh` - Deployment scripts with credentials
- `terraform.tfvars` - Terraform variables with secrets
- `*-secret.yaml` - Kubernetes secrets

## ✅ Safe Practices

### 1. Use Example Templates
Instead of committing sensitive files, create `.example` versions:

```
REAL_SCRAPING_GUIDE.md          ❌ (contains real API keys)
REAL_SCRAPING_GUIDE.example.md  ✅ (safe template)

api-credentials.txt             ❌ (contains real credentials)
api-credentials.example.txt     ✅ (safe template)
```

### 2. Environment Variables
Store sensitive data in environment variables:

```bash
# .env (excluded from git)
GOOGLE_MAPS_API_KEY=your_real_key_here
GOOGLE_SEARCH_API_KEY=your_real_key_here
AZURE_AI_KEY=your_real_key_here
```

### 3. Configuration Files
Use separate configuration files for different environments:

```
config/
├── development.env.example     ✅ (safe template)
├── production.env.example      ✅ (safe template)
├── development.env             ❌ (excluded from git)
└── production.env              ❌ (excluded from git)
```

## 🛠️ Developer Workflow

### Setting Up Local Development

1. **Copy example files:**
   ```bash
   cp REAL_SCRAPING_GUIDE.example.md REAL_SCRAPING_GUIDE.md
   cp config/development.env.example config/development.env
   ```

2. **Add your real API keys:**
   ```bash
   # Edit the copied files with your actual credentials
   nano REAL_SCRAPING_GUIDE.md
   nano config/development.env
   ```

3. **Verify files are ignored:**
   ```bash
   git status
   # Should not show your sensitive files
   ```

### Before Committing

Always check that sensitive files are not being committed:

```bash
# Check what files will be committed
git status

# Verify no sensitive patterns are included
git ls-files | grep -E "(key|secret|credential|production)"
```

## 🚨 Emergency Response

### If Sensitive Data is Accidentally Committed

1. **Immediately rotate all exposed credentials**
2. **Remove from git history:**
   ```bash
   git filter-branch --force --index-filter \
     'git rm --cached --ignore-unmatch SENSITIVE_FILE.md' \
     --prune-empty --tag-name-filter cat -- --all
   ```
3. **Force push to remote:**
   ```bash
   git push origin --force --all
   ```
4. **Update .gitignore to prevent future incidents**

## 📚 File Categories

### ✅ Safe to Commit
- `*.example.*` - Example/template files
- `README.md` - Documentation without secrets
- `SECURITY.md` - Security documentation
- Source code without hardcoded secrets

### ❌ Never Commit
- Files with real API keys
- Production configuration files
- Database connection strings with passwords
- Private keys and certificates
- User credentials or authentication tokens

## 🔍 Monitoring

### Regular Security Audits
1. Review `.gitignore` patterns monthly
2. Scan repository for accidentally committed secrets
3. Verify all team members follow security practices
4. Update patterns as new sensitive file types are identified

### Tools for Secret Detection
- `git-secrets` - Prevents committing secrets
- `truffleHog` - Searches for secrets in git history
- `detect-secrets` - Baseline secret detection

## 📞 Contact

If you discover sensitive information in the repository:
1. **Do not** create a public issue
2. Contact the security team immediately
3. Follow the emergency response procedures above

---

**Remember**: Security is everyone's responsibility. When in doubt, don't commit!
