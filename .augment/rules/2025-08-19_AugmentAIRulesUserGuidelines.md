---
type: "always_apply"
description: "Example description"
---
# Augment AI Rules & User Guidelines – General Application Development

This document defines the standards, workflows, and guidelines for any computer application development project, regardless of the technology stack (web, mobile, desktop, backend services, embedded systems, etc.).  
The purpose of these guidelines is to enforce **consistency, maintainability, security, and professionalism** across all projects supported by Augment AI.  

---

## CORE DEVELOPMENT RULES

### 1. Architecture & Code Organization  
**RULE: Follow Clear Layered Architecture with Explicit Separation of Concerns**  

Applications should be structured in a way that promotes modularity and reusability.  
Each layer should have a **well-defined responsibility** and should not bleed into other concerns.  

- **Data/Logic Layer (Models):**  
  Responsible for business logic, data validation, and communication with storage systems or APIs.  
  Example: Database ORM models, API request/response handling.  

- **Presentation Layer (Views):**  
  Handles user interface (UI), display logic, or output formatting. This applies whether it is a GUI, web page, CLI output, or API response serializer.  

- **Control Layer (Controllers/Managers):**  
  Manages state transitions, application workflows, request/response lifecycles, or hardware orchestration.  

- **Services:**  
  Reusable modules that encapsulate external interactions or business workflows. Example: authentication service, payment gateway, or file storage service.  

- **Utilities:**  
  Pure helper functions that operate independently of application state. Examples: string formatters, date/time converters, number parsers.  

- **Types/Interfaces (if supported):**  
  Schema definitions or type annotations that improve clarity and reduce errors in data handling.  

**ENFORCE:** Maintain strict boundaries between these layers. For example, a controller must not directly query the database—it should delegate to a data service.  

---

### 2. File Naming & Structure Conventions  
**RULE: Adopt Consistent & Descriptive Naming Patterns Across All Files**  

- **Services:** Use `camelCase` and append `Service` (e.g., `scraperService`, `paymentService`).  
- **Components/UI Modules:** Use `PascalCase` (e.g., `LoginForm`, `UserDashboard`).  
- **Utilities:** Use `camelCase` (e.g., `apiErrorHandler`, `dateFormatter`).  
- **Data Models/Types:** Use `PascalCase` with descriptive meaning (e.g., `UserProfile`, `TransactionRecord`).  
- **Tests:** Mirror source filenames with `.test` or `.spec` suffixes.  

**ENFORCE:** File names must reveal intent. A file named `helper.js` or `misc.ts` is not acceptable.  

---

### 3. Language & Framework Standards  
**RULE: Enforce Strict Language and Framework Configurations**  

- Enable strict type-checking modes where available (e.g., `strict` mode in TypeScript, compiler warnings in C/C++).  
- Explicitly declare function return types. Avoid implicit typing.  
- Prohibit untyped or weakly typed constructs (e.g., `any` in TypeScript, raw `void*` in C).  
- Always implement structured and contextual error handling.  
- Validate runtime inputs and outputs with schemas (e.g., Zod, JSON Schema, or equivalent).  

---

## TESTING REQUIREMENTS

### 4. Test Coverage Standards  
**RULE: Maintain at Least 85% Comprehensive Test Coverage Across All Test Categories**  

Software quality is directly proportional to the rigor of its testing. Testing is **non-negotiable** in every project. Coverage must span multiple layers of the application and ensure resilience under both expected and unexpected scenarios.  

The **12 primary categories of testing** that must be considered are:  

1. **Unit Tests**  
   - Validate correctness of individual functions, classes, and methods in isolation.  
   - Example: Ensure a `calculateTax()` function computes the correct value given known inputs.  

2. **Integration Tests**  
   - Validate that multiple modules or services interact correctly.  
   - Example: Ensure the payment service correctly triggers order creation in the database.  

3. **End-to-End (E2E) Tests**  
   - Simulate user behavior or complete system flows.  
   - Example: Simulate a full checkout process from login → cart → payment → confirmation.  

4. **System Tests**  
   - Validate the entire application in its target environment.  
   - Example: Confirm that the full system runs correctly on a test server or device.  

5. **Regression Tests**  
   - Ensure new changes do not break existing functionality.  
   - Example: Running the previous test suite after adding a new feature.  

6. **Acceptance Tests (UAT)**  
   - Validate that requirements from stakeholders are met.  
   - Example: Confirm that the order processing flow meets business requirements.  

7. **Performance Tests**  
   - Measure application responsiveness, throughput, and latency under normal conditions.  
   - Example: Confirm an API responds in <200ms under nominal load.  

8. **Load & Stress Tests**  
   - Validate system behavior under peak or extreme usage.  
   - Example: Test database under 10x expected concurrent users.  

9. **Security Tests**  
   - Identify vulnerabilities, insecure configurations, and input validation flaws.  
   - Example: Test for SQL injection, XSS, CSRF, or privilege escalation.  

10. **Compatibility Tests**  
   - Ensure correct behavior across platforms, devices, or environments.  
   - Example: Confirm a desktop app runs identically on Windows, macOS, and Linux.  

11. **Accessibility Tests**  
   - Ensure compliance with accessibility standards (e.g., WCAG, ADA).  
   - Example: Verify that UI components are screen-reader compatible.  

12. **Exploratory & Ad-hoc Tests**  
   - Manual, creative testing by developers or QA to uncover unexpected issues.  
   - Example: A tester deliberately enters strange edge-case inputs to provoke unusual behavior.  

**ENFORCE:**  
- No new functionality should be merged without appropriate tests.  
- Critical workflows must have **E2E + Regression + Security coverage** at minimum.  
- Automated tests should run as part of the CI/CD pipeline.  

---

### 5. Test Organization  
**RULE: Tests Must Mirror Project Structure and Remain Readable**  

- Unit tests: `tests/unit/`  
- Integration tests: `tests/integration/`  
- End-to-End tests: `tests/e2e/`  
- Shared test utilities: `tests/utils/`  
- Fixtures & mock data: `tests/fixtures/`  

**PATTERN:** For every source file/module, there should be a corresponding test file located in the test directory structure.  

---

## DOCUMENTATION STANDARDS

### 6. Automatic Documentation Updates  
**RULE: Documentation Must Be Updated with Every Change**  

- **VERSION file:** Increment the application version and include release notes.  
- **CHANGELOG.md:** Describe changes in detail (files affected, features added/removed, bugs fixed).  
- **README.md / User Docs:** Update instructions, usage examples, and new features.  
- **API Docs:** Maintain accurate inline documentation for all public functions and interfaces.  

---

### 7. Version Management  
**RULE: Follow Semantic Versioning (MAJOR.MINOR.PATCH)**  

- **MAJOR:** Incompatible API changes or breaking features.  
- **MINOR:** Backward-compatible feature additions.  
- **PATCH:** Backward-compatible bug fixes.  

---

### 8. Code/Process Documentation  
**RULE: Maintain Comprehensive Inline and External Documentation**  

- Document all **public functions, classes, APIs, and complex logic**.  
- Use comments to describe **why** a solution exists, not just **what** it does.  
- Provide examples for critical configurations and workflows.  

---

## SECURITY & PRIVACY RULES

### 9. Sensitive Data Protection  
**RULE: Never Expose or Commit Secrets**  

- Use secure credential storage (environment variables, secret managers).  
- Provide `.env.example` templates for developers.  
- Never commit `.env` or sensitive files to version control.  

---

### 10. Input Validation & Sanitization  
**RULE: Validate and Sanitize All External Inputs**  

- Validate request payloads, file uploads, and query parameters.  
- Sanitize user-provided text to prevent injection attacks.  
- Use parameterized queries for all database operations.  

---

### 11. Error Handling  
**RULE: Secure, Structured, and User-Friendly Error Management**  

- Never expose stack traces or sensitive data to end-users.  
- Use structured logging for errors.  
- Provide descriptive, actionable error messages where appropriate.  
- Implement graceful fallback strategies.  

---

## PERFORMANCE & OPTIMIZATION

### 12. Resource Management  
**RULE: Monitor and Efficiently Manage Resources**  

- Release unused resources (file handles, network connections).  
- Apply caching and pooling strategies where appropriate.  
- Continuously monitor memory, CPU, and network usage.  

---

### 13. Fair Use & Rate Limiting  
**RULE: Respect External Services and APIs**  

- Implement configurable rate limits.  
- Use retries with exponential backoff.  
- Respect published usage policies such as API quotas or robots.txt.  

---

## VERSION CONTROL & COLLABORATION

### 14. Commit Message Standards  
**RULE: Follow Conventional Commit Conventions**  

Format: `type(scope): description`  
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`  

---

### 15. Branch Management  
**RULE: Follow a Structured Branching Strategy**  

- `main`: Production-ready branch.  
- `develop`: Consolidated development branch.  
- `feature/*`: For new features.  
- `hotfix/*`: Emergency production fixes.  
- `release/*`: Release preparation.  

---

### 16. Pre-commit Validation  
**RULE: Require Automated Quality Checks**  

- Linting for code quality and style consistency.  
- Type-checking where supported.  
- Automated tests must pass.  
- Security scans for dependency vulnerabilities.  

---

## DEVELOPMENT WORKFLOW

### 17. Feature Development Process  
**WORKFLOW:**  
1. Create a feature branch from `develop`.  
2. Implement the feature and write appropriate tests.  
3. Update documentation.  
4. Run quality checks.  
5. Open a pull request with a clear description.  
6. Obtain mandatory code review.  
7. Merge to `develop`.  
8. Deploy to staging.  
9. Merge to `main` for production release.  

---

### 18. Code Review Requirements  
**RULE: Code Reviews Are Mandatory for All Merges**  

Reviewers must check for:  
- Functional correctness.  
- Security vulnerabilities.  
- Test coverage adequacy.  
- Documentation accuracy.  
- Architectural and stylistic consistency.  

---

## ENVIRONMENT & DEPENDENCIES

### 19. Environment Configuration  
**RULE: Environments Must Be Isolated and Clearly Defined**  

- Provide separate configurations for development, testing, and production.  
- Allow local overrides for developers without committing them.  
- Validate all configuration schemas.  

---

### 20. Dependency Management  
**RULE: Secure and Maintainable Dependency Practices**  

- Audit dependencies regularly.  
- Pin dependency versions to prevent unexpected changes.  
- Use trusted package sources.  
- Automate dependency update checks.  

---

## MONITORING & MAINTENANCE

### 21. Health Monitoring  
**RULE: Implement Automated Monitoring**  

- Provide application health endpoints.  
- Monitor database and external API connectivity.  
- Track performance metrics.  
- Implement real-time alerting.  

---

### 22. Logging Standards  
**RULE: Use Structured Logging Across the Application**  

- Log with appropriate levels (`error`, `warn`, `info`, `debug`).  
- Include correlation IDs for tracking distributed requests.  
- Log security-related events explicitly.  
- Use structured/JSON logging for production systems.  

---

## DEPLOYMENT & PRODUCTION

### 23. Production Readiness  
**RULE: All Code Must Pass a Deployment Checklist**  

- All tests passing.  
- Security scans completed.  
- Performance benchmarks validated.  
- Documentation fully updated.  
- Monitoring configured and operational.  

---

### 24. Rollback Procedures  
**RULE: Always Deploy Safely and Prepare for Rollback**  

- Maintain rollback mechanisms.  
- Use staged or blue-green deployments.  
- Monitor key performance metrics after release.  
- Maintain incident response runbooks.  

---

## USAGE GUIDELINES FOR AUGMENT AI

### When Making Changes:  
- Always run quality checks (lint/tests/type-check).  
- Update documentation immediately.  
- Follow naming and structural conventions.  
- Write tests to maintain required coverage.  
- Use clear, conventional commit messages.  

### Before Submitting:  
- Verify all tests pass successfully.  
- Confirm no sensitive data is present in commits.  
- Update semantic version numbers as required.  
- Review documentation for completeness.  
- Validate the feature in a staging environment.  

### For All Projects:  
- Adapt architecture patterns to the project’s domain.  
- Maintain strict security and testing standards.  
- Follow consistent documentation practices.  
- Implement structured error handling and logging.  

