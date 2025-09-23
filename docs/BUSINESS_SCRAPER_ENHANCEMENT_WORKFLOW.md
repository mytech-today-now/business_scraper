# Business Scraper Enhancement Workflow

This document describes the adapted enhancement workflow specifically designed for the business_scraper project structure and testing framework.

## Overview

The Business Scraper Enhancement Workflow is a comprehensive automation system that:

1. **Plans and implements enhancements** across all affected areas
2. **Detects affected files** using git diff and heuristic analysis
3. **Updates project documentation** automatically with enhancement notes
4. **Creates GitHub issues** with detailed tracking and progress updates
5. **Runs comprehensive test suites** tailored to the project structure
6. **Provides detailed reporting** with test results and recommendations

## Project Structure Integration

The workflow is specifically adapted for the business_scraper project structure:

```
business_scraper/
├── src/
│   ├── view/components/     # React components (tested with component tests)
│   ├── lib/                 # Services and utilities (unit tests)
│   ├── app/api/            # API endpoints (integration tests)
│   ├── model/              # Data models (unit tests)
│   ├── controller/         # Controllers (unit tests)
│   ├── hooks/              # React hooks (unit tests)
│   └── tests/              # Test suites (unit, integration, e2e)
├── docs/                   # Documentation (auto-updated)
├── scripts/                # Enhancement scripts
└── .github/workflows/      # GitHub Actions workflows
```

## Usage Methods

### 1. GitHub Actions Workflow (Recommended)

#### Manual Trigger
1. Go to your repository's Actions tab
2. Select "Business Scraper Enhancement Workflow"
3. Click "Run workflow"
4. Fill in the required inputs:
   - **Enhancement**: Description of the enhancement to implement
   - **Assignees**: GitHub usernames (comma-separated)
   - **Labels**: Issue labels (comma-separated)
   - **Pull Request URL**: Optional PR link

#### Example Inputs
```
Enhancement: Improve search streaming performance and error handling
Assignees: mytech-today-now
Labels: enhancement,performance,critical
Pull Request URL: https://github.com/mytech-today-now/business_scraper/pull/123
```

### 2. Local Script Execution

#### Basic Usage
```bash
# Run enhancement with description
node scripts/business-scraper-enhancement.js --enhancement "Fix memory leaks in search engine"

# Dry run (no actual changes)
node scripts/business-scraper-enhancement.js --enhancement "Add new API endpoint" --dry-run

# Verbose logging
node scripts/business-scraper-enhancement.js --enhancement "Improve error handling" --verbose
```

#### Advanced Usage
```bash
# Copy and configure environment
cp config/enhancement-workflow.env.example config/enhancement-workflow.env
# Edit config/enhancement-workflow.env with your settings

# Run with custom configuration
node scripts/business-scraper-enhancement.js --enhancement "Performance optimization"
```

## Test Strategy Integration

The workflow integrates with the project's comprehensive testing framework:

### Test Categories
1. **Unit Tests** (`npm run test:unit`)
   - Components: `src/view/components/**/*.{ts,tsx}`
   - Services: `src/lib/**/*.ts`
   - Models: `src/model/**/*.ts`
   - Controllers: `src/controller/**/*.ts`

2. **Integration Tests** (`npm run test:integration`)
   - API endpoints: `src/app/api/**/*.ts`
   - Service integrations
   - Database interactions

3. **End-to-End Tests** (`npm run test:e2e`)
   - User workflows with Playwright
   - Complete application flows

4. **Security Tests** (`npm run test:security`)
   - Vulnerability scanning
   - Authentication testing
   - Input validation

5. **Performance Tests** (`npm run test:performance`)
   - Load testing
   - Memory usage monitoring
   - Response time validation

6. **Accessibility Tests** (`npm run test:accessibility`)
   - WCAG compliance
   - Screen reader compatibility

### Coverage Requirements
- **Global Coverage**: 95% (branches, functions, lines, statements)
- **Per-Directory Thresholds**:
  - `src/model/`: 95%
  - `src/controller/`: 95%
  - `src/view/`: 90% (UI components)
  - `src/utils/`: 98%
  - `src/lib/`: 95%

## Documentation Auto-Update

The workflow automatically updates these documentation files:

### HTML Documentation
- `docs/UX-ToDo.html`
- `docs/Remaining-Work.html`
- `docs/MVP2.html`
- `docs/MVP.html`
- `docs/MVP_REFACTOR_SUMMARY.html`
- `docs/MVP_IMPLEMENTATION_GUIDE.html`
- `docs/API_DOCUMENTATION.html`
- `docs/FEATURE_GUIDE.html`

### Markdown Documentation
- `docs/TESTING.md`
- `README.md`
- `CHANGELOG.md`

### Enhancement Notes
The workflow injects enhancement notes into documentation:

```html
<!-- Enhancement Update: 2025-09-16T12:00:00Z -->
<div class="enhancement-note">
  <h4>🔄 Enhancement Applied</h4>
  <p><strong>Description:</strong> Improve search streaming performance</p>
  <p><strong>Date:</strong> 2025-09-16T12:00:00Z</p>
  <p><strong>Affected Files:</strong></p>
  <ul>
    <li><code>src/hooks/useSearchStreaming.ts</code></li>
    <li><code>src/lib/searchEngine.ts</code></li>
  </ul>
  <p><em>Please review related sections and verify functionality.</em></p>
</div>
```

## GitHub Issue Integration

### Automatic Issue Creation
The workflow creates detailed GitHub issues with:

- **Enhancement summary** and implementation plan
- **Project structure context** and testing strategy
- **Expected outcomes** and success criteria
- **Automatic progress tracking** with checkboxes

### Issue Updates
- **Test results** for each affected file
- **Documentation update status**
- **Comprehensive test suite results**
- **Workflow execution summary**

### Issue Closure
Issues are automatically closed upon successful completion with:
- **Summary of completed work**
- **Links to updated documentation**
- **Test result verification**
- **Next steps recommendations**

## Configuration Options

### Environment Variables
Copy `config/enhancement-workflow.env.example` to `config/enhancement-workflow.env` and customize:

```bash
# GitHub Configuration
GITHUB_TOKEN=your_github_token_here
GITHUB_REPOSITORY=mytech-today-now/business_scraper

# Testing Configuration
TEST_TIMEOUT=60000
COVERAGE_THRESHOLD=95
MAX_WORKERS=2

# Enhancement Settings
AUTO_CREATE_ISSUE=true
AUTO_UPDATE_DOCS=true
AUTO_RUN_TESTS=true
CREATE_BACKUPS=true
```

### Workflow Customization
- **Test commands**: Customize for your specific test setup
- **File patterns**: Define which files to monitor for changes
- **Documentation files**: Specify which docs to auto-update
- **Quality gates**: Set coverage and complexity thresholds

## Output and Artifacts

### Generated Files
- **Test results**: `test-results/enhancement/`
- **Documentation backups**: `backups/docs-{timestamp}/`
- **Enhancement report**: `test-results/enhancement/enhancement-report.md`
- **Workflow logs**: `logs/enhancement.log`

### GitHub Artifacts
- Enhancement planning files
- Test execution logs
- Documentation backups
- Affected files list

## Best Practices

### Enhancement Descriptions
- Be specific and actionable
- Include context about the problem being solved
- Mention expected impact on users or system

### Testing Strategy
- Run dry-run mode first to validate the workflow
- Review test results before merging changes
- Ensure all quality gates pass

### Documentation Maintenance
- Review auto-generated enhancement notes
- Update relevant sections manually if needed
- Keep documentation current with actual implementation

### Issue Management
- Use descriptive labels for better organization
- Assign appropriate team members
- Link related PRs and issues

## Troubleshooting

### Common Issues
1. **Test failures**: Review test logs in `test-results/enhancement/`
2. **Documentation update failures**: Check file permissions and backup directory
3. **GitHub API errors**: Verify token permissions and rate limits
4. **File detection issues**: Ensure git repository is properly configured

### Debug Mode
```bash
# Enable verbose logging
node scripts/business-scraper-enhancement.js --enhancement "Debug test" --verbose

# Dry run for testing
node scripts/business-scraper-enhancement.js --enhancement "Debug test" --dry-run
```

### Support
- Check the enhancement logs in `logs/enhancement.log`
- Review GitHub Actions workflow logs
- Examine test result files for specific failures
- Verify configuration in `config/enhancement-workflow.env`

## Integration with Existing Workflows

This enhancement workflow integrates seamlessly with:

- **Existing CI/CD pipelines** (GitHub Actions)
- **Current testing framework** (Jest + Playwright)
- **Documentation system** (HTML + Markdown)
- **Issue tracking** (GitHub Issues)
- **Code review process** (Pull Requests)

The workflow respects existing project conventions and enhances them with automated enhancement tracking and comprehensive testing validation.
