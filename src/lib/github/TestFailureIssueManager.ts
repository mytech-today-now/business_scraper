/**
 * GitHub Issue Manager for Test Failures
 * Automatically creates, tracks, and manages GitHub issues for test failures
 */

import { Octokit } from '@octokit/rest'
import { TestResult, TestError, GitHubIssueReference, ErrorSeverity } from '../../types/TestReporting'

export interface GitHubConfig {
  token: string
  owner: string
  repo: string
  apiUrl?: string
}

export interface IssueCreationOptions {
  autoAssign?: boolean
  defaultAssignees?: string[]
  labelPrefix?: string
  escalationThreshold?: number
  dryRun?: boolean
}

export class TestFailureIssueManager {
  private octokit: Octokit
  private config: GitHubConfig
  private options: IssueCreationOptions
  private issueCache: Map<string, GitHubIssueReference> = new Map()

  constructor(config: GitHubConfig, options: IssueCreationOptions = {}) {
    this.config = config
    this.options = {
      autoAssign: true,
      defaultAssignees: ['mytech-today-now'],
      labelPrefix: 'test-failure',
      escalationThreshold: 3,
      dryRun: false,
      ...options
    }

    this.octokit = new Octokit({
      auth: config.token,
      baseUrl: config.apiUrl || 'https://api.github.com'
    })
  }

  /**
   * Process test failure and create/update GitHub issue
   */
  async processTestFailure(testResult: TestResult): Promise<GitHubIssueReference | null> {
    if (testResult.status !== 'failed' || !testResult.error) {
      return null
    }

    const issueKey = this.generateIssueKey(testResult)
    
    // Check if issue already exists
    const existingIssue = await this.findExistingIssue(testResult)
    
    if (existingIssue) {
      return await this.updateExistingIssue(existingIssue, testResult)
    } else {
      return await this.createNewIssue(testResult)
    }
  }

  /**
   * Create new GitHub issue for test failure
   */
  private async createNewIssue(testResult: TestResult): Promise<GitHubIssueReference> {
    const title = this.generateIssueTitle(testResult)
    const body = this.generateIssueBody(testResult)
    const labels = this.generateIssueLabels(testResult)
    const assignees = this.getAssignees(testResult)

    if (this.options.dryRun) {
      console.log('[DRY RUN] Would create GitHub issue:', { title, labels, assignees })
      return {
        status: 'pending',
        createdAt: new Date().toISOString()
      }
    }

    try {
      const response = await this.octokit.rest.issues.create({
        owner: this.config.owner,
        repo: this.config.repo,
        title,
        body,
        labels,
        assignees
      })

      const issueRef: GitHubIssueReference = {
        issueNumber: response.data.number,
        issueUrl: response.data.html_url,
        status: 'open',
        createdAt: response.data.created_at,
        assignees,
        labels
      }

      // Cache the issue
      const issueKey = this.generateIssueKey(testResult)
      this.issueCache.set(issueKey, issueRef)

      return issueRef
    } catch (error) {
      console.error('Failed to create GitHub issue:', error)
      throw new Error(`GitHub issue creation failed: ${error.message}`)
    }
  }

  /**
   * Update existing GitHub issue with new failure information
   */
  private async updateExistingIssue(
    existingIssue: GitHubIssueReference, 
    testResult: TestResult
  ): Promise<GitHubIssueReference> {
    if (!existingIssue.issueNumber || this.options.dryRun) {
      return existingIssue
    }

    try {
      const comment = this.generateFailureComment(testResult)
      
      await this.octokit.rest.issues.createComment({
        owner: this.config.owner,
        repo: this.config.repo,
        issue_number: existingIssue.issueNumber,
        body: comment
      })

      // Check if escalation is needed
      if (testResult.retryCount >= (this.options.escalationThreshold || 3)) {
        await this.escalateIssue(existingIssue.issueNumber, testResult)
      }

      return existingIssue
    } catch (error) {
      console.error('Failed to update GitHub issue:', error)
      return existingIssue
    }
  }

  /**
   * Find existing issue for the same test failure
   */
  private async findExistingIssue(testResult: TestResult): Promise<GitHubIssueReference | null> {
    const issueKey = this.generateIssueKey(testResult)
    
    // Check cache first
    if (this.issueCache.has(issueKey)) {
      return this.issueCache.get(issueKey)!
    }

    try {
      const searchQuery = `repo:${this.config.owner}/${this.config.repo} is:issue is:open "${testResult.metadata.testName}" label:${this.options.labelPrefix}`
      
      const response = await this.octokit.rest.search.issuesAndPullRequests({
        q: searchQuery,
        per_page: 1
      })

      if (response.data.items.length > 0) {
        const issue = response.data.items[0]
        const issueRef: GitHubIssueReference = {
          issueNumber: issue.number,
          issueUrl: issue.html_url,
          status: 'open',
          createdAt: issue.created_at,
          assignees: issue.assignees?.map(a => a.login) || [],
          labels: issue.labels.map(l => typeof l === 'string' ? l : l.name || '')
        }
        
        this.issueCache.set(issueKey, issueRef)
        return issueRef
      }
    } catch (error) {
      console.error('Failed to search for existing issues:', error)
    }

    return null
  }

  /**
   * Escalate issue for critical or repeated failures
   */
  private async escalateIssue(issueNumber: number, testResult: TestResult): Promise<void> {
    try {
      // Add escalation labels
      await this.octokit.rest.issues.addLabels({
        owner: this.config.owner,
        repo: this.config.repo,
        issue_number: issueNumber,
        labels: ['escalated', 'needs-immediate-attention']
      })

      // Add escalation comment
      const escalationComment = `🚨 **ESCALATED**: This test has failed ${testResult.retryCount} times consecutively.

**Severity**: ${testResult.error?.severity || 'Unknown'}
**Last Failure**: ${new Date().toISOString()}

This issue requires immediate attention from the development team.`

      await this.octokit.rest.issues.createComment({
        owner: this.config.owner,
        repo: this.config.repo,
        issue_number: issueNumber,
        body: escalationComment
      })
    } catch (error) {
      console.error('Failed to escalate issue:', error)
    }
  }

  /**
   * Close issue when test is fixed
   */
  async closeIssueForFixedTest(testResult: TestResult, resolution: string): Promise<void> {
    const existingIssue = await this.findExistingIssue(testResult)
    
    if (!existingIssue?.issueNumber || this.options.dryRun) {
      return
    }

    try {
      // Add resolution comment
      const resolutionComment = `✅ **RESOLVED**: Test is now passing.

**Resolution**: ${resolution}
**Fixed at**: ${new Date().toISOString()}

Closing this issue as the test failure has been resolved.`

      await this.octokit.rest.issues.createComment({
        owner: this.config.owner,
        repo: this.config.repo,
        issue_number: existingIssue.issueNumber,
        body: resolutionComment
      })

      // Close the issue
      await this.octokit.rest.issues.update({
        owner: this.config.owner,
        repo: this.config.repo,
        issue_number: existingIssue.issueNumber,
        state: 'closed'
      })

      // Update cache
      const issueKey = this.generateIssueKey(testResult)
      const updatedIssue = { ...existingIssue, status: 'closed' as const }
      this.issueCache.set(issueKey, updatedIssue)
    } catch (error) {
      console.error('Failed to close GitHub issue:', error)
    }
  }

  /**
   * Generate unique key for test failure
   */
  private generateIssueKey(testResult: TestResult): string {
    return `${testResult.metadata.suite}::${testResult.metadata.testName}::${testResult.error?.type || 'unknown'}`
  }

  /**
   * Generate issue title
   */
  private generateIssueTitle(testResult: TestResult): string {
    const severity = testResult.error?.severity || 'medium'
    const category = testResult.metadata.category
    return `[${severity.toUpperCase()}] Test Failure: ${testResult.metadata.testName} (${category})`
  }

  /**
   * Generate comprehensive issue body
   */
  private generateIssueBody(testResult: TestResult): string {
    const error = testResult.error!
    
    return `# Test Failure Report

## Test Information
- **Test Name**: ${testResult.metadata.testName}
- **Test Suite**: ${testResult.metadata.suite}
- **File Path**: ${testResult.metadata.filePath}
- **Category**: ${testResult.metadata.category}
- **Priority**: ${testResult.metadata.priority}

## Failure Details
- **Error Type**: ${error.type}
- **Severity**: ${error.severity}
- **Category**: ${error.category}
- **Retry Count**: ${testResult.retryCount}

## Error Message
\`\`\`
${error.message}
\`\`\`

${error.stack ? `## Stack Trace
\`\`\`
${error.stack}
\`\`\`
` : ''}

## Performance Impact
- **Duration**: ${testResult.performance.duration}ms
- **Memory Usage**: ${(testResult.performance.memoryUsage.heapUsed / 1024 / 1024).toFixed(2)}MB

## Reproduction Steps
${error.reproductionSteps ? error.reproductionSteps.map((step, i) => `${i + 1}. ${step}`).join('\n') : '1. Run the test suite\n2. Observe the failure'}

## Expected vs Actual Behavior
**Expected**: ${error.expectedBehavior || 'Test should pass without errors'}
**Actual**: ${error.actualBehavior || 'Test failed with the error above'}

## Environment
- **Node Version**: ${process.version}
- **Platform**: ${process.platform}
- **Timestamp**: ${new Date().toISOString()}

## Resolution Checklist
- [ ] Identify root cause of the failure
- [ ] Implement fix for the issue
- [ ] Add additional tests to prevent regression
- [ ] Update documentation if needed
- [ ] Verify fix in CI/CD pipeline
- [ ] Close this issue with resolution details

---
*This issue was automatically created by the Enhanced Test Reporting System*`
  }

  /**
   * Generate failure comment for existing issues
   */
  private generateFailureComment(testResult: TestResult): string {
    return `## Additional Failure - ${new Date().toISOString()}

**Retry Count**: ${testResult.retryCount}
**Duration**: ${testResult.performance.duration}ms
**Memory Usage**: ${(testResult.performance.memoryUsage.heapUsed / 1024 / 1024).toFixed(2)}MB

**Error Message**:
\`\`\`
${testResult.error?.message || 'Unknown error'}
\`\`\`

This test continues to fail. Please prioritize investigation and resolution.`
  }

  /**
   * Generate appropriate labels for the issue
   */
  private generateIssueLabels(testResult: TestResult): string[] {
    const labels = [this.options.labelPrefix!, 'bug']
    
    // Add severity label
    if (testResult.error?.severity) {
      labels.push(`severity-${testResult.error.severity}`)
    }
    
    // Add category label
    labels.push(`category-${testResult.metadata.category}`)
    
    // Add priority label
    labels.push(`priority-${testResult.metadata.priority}`)
    
    // Add special labels for critical issues
    if (testResult.error?.severity === ErrorSeverity.CRITICAL) {
      labels.push('critical', 'needs-immediate-attention')
    }
    
    return labels
  }

  /**
   * Get assignees for the issue
   */
  private getAssignees(testResult: TestResult): string[] {
    const assignees = [...(this.options.defaultAssignees || [])]
    
    // Add test author if available
    if (testResult.metadata.author) {
      assignees.push(testResult.metadata.author)
    }
    
    return [...new Set(assignees)] // Remove duplicates
  }
}
