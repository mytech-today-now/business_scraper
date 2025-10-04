---
type: "always_apply"
description: "Example description"
---

# Augment AI Rules & User Guidelines – General Application Development

This document defines the standards, workflows, and guidelines for any computer
application development project, regardless of the technology stack (web,
mobile, desktop, backend services, embedded systems, etc.).  
The purpose of these guidelines is to enforce **consistency, maintainability,
security, and professionalism** across all projects supported by Augment AI.

---

## CORE DEVELOPMENT RULES

### 1. Architecture & Code Organization

**RULE: Follow Clear Layered Architecture with Explicit Separation of Concerns**

Applications should be structured in a way that promotes modularity and
reusability.  
Each layer should have a **well-defined responsibility** and should not bleed
into other concerns.

- **Data/Logic Layer (Models):**  
  Responsible for business logic, data validation, and communication with
  storage systems or APIs.  
  Example: Database ORM models, API request/response handling.

- **Presentation Layer (Views):**  
  Handles user interface (UI), display logic, or output formatting. This applies
  whether it is a GUI, web page, CLI output, or API response serializer.

- **Control Layer (Controllers/Managers):**  
  Manages state transitions, application workflows, request/response lifecycles,
  or hardware orchestration.

- **Services:**  
  Reusable modules that encapsulate external interactions or business workflows.
  Example: authentication service, payment gateway, or file storage service.

- **Utilities:**  
  Pure helper functions that operate independently of application state.
  Examples: string formatters, date/time converters, number parsers.

- **Types/Interfaces (if supported):**  
  Schema definitions or type annotations that improve clarity and reduce errors
  in data handling.

**ENFORCE:** Maintain strict boundaries between these layers. For example, a
controller must not directly query the database—it should delegate to a data
service.

---

### 2. File Naming & Structure Conventions

**RULE: Adopt Consistent & Descriptive Naming Patterns Across All Files**

- **Services:** Use `camelCase` and append `Service` (e.g., `scraperService`,
  `paymentService`).
- **Components/UI Modules:** Use `PascalCase` (e.g., `LoginForm`,
  `UserDashboard`).
- **Utilities:** Use `camelCase` (e.g., `apiErrorHandler`, `dateFormatter`).
- **Data Models/Types:** Use `PascalCase` with descriptive meaning (e.g.,
  `UserProfile`, `TransactionRecord`).
- **Tests:** Mirror source filenames with `.test` or `.spec` suffixes.

**ENFORCE:** File names must reveal intent. A file named `helper.js` or
`misc.ts` is not acceptable.

---

### 3. Language & Framework Standards

**RULE: Enforce Strict Language and Framework Configurations**

- Enable strict type-checking modes where available (e.g., `strict` mode in
  TypeScript, compiler warnings in C/C++).
- Explicitly declare function return types. Avoid implicit typing.
- Prohibit untyped or weakly typed constructs (e.g., `any` in TypeScript, raw
  `void*` in C).
- Always implement structured and contextual error handling.
- Validate runtime inputs and outputs with schemas (e.g., Zod, JSON Schema, or
  equivalent).
  
#### JavaScript/TypeScript Coding Style Rules

- Always declare variables using `let` or `const` instead of `var` to ensure block scoping and avoid hoisting issues.
- **Prefer `const` over `let` for variables that won't be reassigned**: Use `const` by default to enforce immutability and prevent accidental reassignments, reducing bugs in larger codebases.
- **Use arrow functions for non-method callbacks**: Arrow functions (`() => {}`) provide concise syntax and lexical `this` binding, avoiding common `this` pitfalls in callbacks.
- **Destructure objects and arrays in function parameters and assignments**: Destructuring (`const { prop } = obj`) improves readability and reduces repetitive property access.
- **Use template literals for string interpolation**: Prefer backticks (`` `Hello ${name}` ``) over concatenation for cleaner, more readable multi-variable strings.
- **Always use strict equality (`===`) instead of loose (`==`)**: Strict comparison avoids type coercion surprises, ensuring predictable behavior.
- **Favor `async/await` over raw Promise chains**: `async/await` makes asynchronous code read like synchronous code, improving flow and error handling.
- **Wrap asynchronous operations in try/catch blocks**: Explicit error handling with `try/catch` prevents unhandled promise rejections and simplifies debugging.
- **Use ES6 modules with `import`/`export` instead of CommonJS**: Modern modules promote tree-shaking and better dependency management in bundlers like Webpack.
- **Prefer the spread operator (`...`) over `Function.prototype.apply()`**: Spread syntax (`func(...args)`) is more intuitive and performant for argument passing.
- **Use optional chaining (`?.`) for safe property access**: Avoids runtime errors when accessing nested properties that might be null/undefined (e.g., `obj?.prop?.nested`).
- **Employ nullish coalescing (`??`) for default values**: Provides a concise way to fallback for `null` or `undefined` without treating falsy values like `0` or `''` as defaults.
- **Avoid declaring variables in the global scope**: Scope variables to modules or blocks to prevent pollution and naming conflicts.
- **Use descriptive, camelCase names for variables and functions**: Follow conventions like `userProfile` instead of `up` for self-documenting code.
- **Limit functions to 20-30 lines maximum**: Shorter functions are easier to test, read, and maintain; refactor larger ones into smaller helpers.
- **Prefer array methods like `map`, `filter`, and `reduce` over imperative loops**: Functional approaches (`arr.map(x => x * 2)`) are more declarative and composable.
- **Use `for...of` loops for iterables instead of `for...in`**: `for...of` iterates values directly, avoiding prototype pollution issues with `for...in`.
- **Treat function arguments as immutable; avoid direct mutation**: Return new objects/arrays instead of modifying inputs to promote pure functions and predictability.
- **In TypeScript, define interfaces for object shapes**: Use `interface User { name: string; }` to enforce contracts and catch type errors early.
- **Annotate all function parameters and return types in TypeScript**: Explicit types (e.g., `function add(a: number, b: number): number`) enhance autocomplete and refactoring safety.
- **Avoid `console.log` in production code; use a logger instead**: Replace with structured logging (e.g., Winston) for better observability and performance.
- **Enable "use strict" mode at the top of files or globally**: Strict mode catches common errors like undeclared variables and unsafe practices.
- **Validate all user inputs with type guards or schemas**: Use libraries like Zod or manual checks to prevent invalid data from propagating.
- **Add JSDoc comments for complex functions or types**: Document params, returns, and examples (e.g., `/** @param {string} name */`) for better IDE support and team onboarding.
- **Use `Object.freeze()` for constants or config objects**: Prevents accidental modifications to shared, immutable data structures.
- **Prefer `Set` or `Map` over plain objects for unique keys or non-string keys**: Built-in collections handle edge cases better than `{}` for lookups and uniqueness.
- **Always handle promise rejections with `.catch()` or try/catch**: Unhandled rejections can crash Node.js processes; explicit handling ensures robustness.
- **Use `JSON.stringify()` with replacer for debugging complex objects**: Customizes output to avoid circular references and improve log readability.
- **Prefer `Array.from()` or spread for array conversions from iterables**: Ensures consistent behavior and avoids mutating originals (e.g., `Array.from(nodeList)`).
- **Implement early returns in conditionals to reduce nesting**: Flattens code structure, making it easier to follow control flow without deep if-else pyramids.
- **Use `private` fields (#private) in classes for encapsulation**: Hides implementation details, preventing external access and promoting better OOP design.
- **Avoid side effects in pure functions; keep them deterministic**: Functions without I/O or mutations are easier to test, cache, and reason about.
- **Format dates with Intl.DateTimeFormat instead of manual strings**: Handles localization and timezones correctly, avoiding cultural formatting errors.
- **Use `AbortController` for cancellable async requests**: Allows timeouts and cleanup, preventing memory leaks in long-running operations.
- **Enforce single quotes for strings and double for HTML attributes**: Consistent quoting reduces visual noise and aligns with linters like ESLint.
- **Group related imports at the top: standard, third-party, then local**: Improves scannability and follows conventions in tools like Prettier.

---

## TESTING REQUIREMENTS

### 4. Test Coverage Standards

**AUGMENT AI RULE: Achieving and Sustaining At Least 98% Comprehensive Test Coverage Across an Expanded Spectrum of 18 Essential Testing Categories**

In the realm of software development, the bedrock of unparalleled quality, reliability, and user satisfaction lies unequivocally in the meticulous orchestration of a multifaceted testing regimen. Testing is not merely a checkpoint but an indispensable, unwavering cornerstone of every Augment AI project, demanding unwavering commitment from inception through to deployment and beyond. This rule enshrines the imperative to attain and perpetually maintain a minimum of 98% test coverage—measured via robust metrics such as line, branch, and path coverage—spanning an exhaustive array of testing layers. These layers collectively fortify the application against anticipated operational flows, aberrant edge cases, environmental variances, and adversarial threats, thereby mitigating risks, accelerating iterations, and elevating the overall integrity of the deliverables.

To operationalize this mandate, Augment AI projects must encompass coverage across **18 primary categories of testing**, each meticulously designed to probe distinct facets of the system's architecture, behavior, and resilience. These categories are not siloed but interwoven, ensuring holistic validation that anticipates real-world complexities and fosters proactive defect detection.

1. **Unit Tests**
   - These foundational tests isolate and rigorously validate the atomic building blocks of the codebase, including individual functions, classes, methods, and procedures, ensuring their intrinsic correctness independent of external dependencies.
   - Sub-focus areas: Edge case handling, boundary conditions, and algorithmic precision.
   - Example: For a `calculateTax()` function, assert that it yields the precise tax amount (e.g., 15% on $100 input equaling $15) across varied inputs like zero values, negative amounts, or international rates, while mocking any external data sources.

2. **Integration Tests**
   - These tests scrutinize the seamless interoperability of multiple modules, services, or components, verifying that data flows, contracts, and handoffs between them are flawless and adhere to defined interfaces.
   - Sub-focus areas: API contract compliance, database schema interactions, and third-party service integrations.
   - Example: Verify that the payment gateway service successfully propagates transaction details to the order management module, resulting in a confirmed database entry for the order without data corruption or timing discrepancies.

3. **End-to-End (E2E) Tests**
   - Mimicking holistic user journeys, these tests traverse the entire application stack—from frontend interactions to backend processing and external integrations—to confirm end-to-end functionality under simulated real-world conditions.
   - Sub-focus areas: Cross-browser compatibility in flows and multi-step workflow persistence.
   - Example: Automate a complete e-commerce checkout sequence, encompassing user authentication, item addition to cart, address validation, payment processing via a mock gateway, and final order confirmation email dispatch.

4. **System Tests**
   - Evaluating the application as a cohesive entity within its intended deployment environment, these tests assess overall system health, resource utilization, and behavioral fidelity against architectural blueprints.
   - Sub-focus areas: Hardware-software interplay and configuration drift detection.
   - Example: Deploy the full application stack on a staging server mirroring production (e.g., AWS EC2 instance) and validate that core features like user dashboard rendering and data synchronization operate without anomalies.

5. **Regression Tests**
   - Designed as a vigilant sentinel against inadvertent disruptions, these tests re-execute prior validated suites post-modifications to ascertain that existing capabilities remain uncompromised.
   - Sub-focus areas: Selective re-running based on code change impact analysis and historical failure pattern monitoring.
   - Example: After implementing a new user profile enhancement, re-run the legacy authentication suite to confirm that login persistence and session management functionalities persist without regression.

6. **Acceptance Tests (UAT)**
   - Aligned with stakeholder-defined criteria, these tests corroborate that the delivered software fulfills business, functional, and non-functional requirements, bridging the gap between technical implementation and user expectations.
   - Sub-focus areas: Scenario-based validation using Gherkin syntax (e.g., BDD frameworks like Cucumber).
   - Example: Collaborate with product owners to script and execute tests verifying that the order fulfillment workflow aligns with specified SLAs, such as processing times under 5 seconds and error rates below 0.1%.

7. **Performance Tests**
   - Quantifying the application's efficiency under baseline operational loads, these tests benchmark metrics like response times, throughput, and resource consumption to ensure snappy, scalable performance.
   - Sub-focus areas: Baseline establishment and trend monitoring over iterations.
   - Example: Utilize tools like JMeter to load-test an API endpoint, confirming average response latency remains below 200ms for 100 concurrent requests with 99th percentile under 500ms.

8. **Load & Stress Tests**
   - Pushing the system to its operational frontiers, these tests emulate peak traffic surges and beyond to uncover bottlenecks, failure thresholds, and graceful degradation points.
   - Sub-focus areas: Vertical (resource scaling) vs. horizontal (instance scaling) stress emulation.
   - Example: Simulate 10x anticipated user concurrency (e.g., 5,000 simultaneous sessions) on the database layer, monitoring for query timeouts, memory leaks, or cascading failures.

9. **Security Tests**
   - Proactively hunting for exploitable weaknesses, these tests encompass vulnerability scanning, penetration simulations, and compliance audits to fortify the application against cyber threats.
   - Sub-focus areas: OWASP Top 10 coverage, including injection attacks and broken authentication.
   - Example: Employ tools like OWASP ZAP to probe for SQL injection in user inputs, cross-site scripting (XSS) in rendered outputs, and cross-site request forgery (CSRF) in form submissions.

10. **Compatibility Tests**
    - Ensuring ubiquitous functionality across diverse ecosystems, these tests validate behavior consistency over varying platforms, browsers, devices, and version matrices.
    - Sub-focus areas: Backward compatibility with legacy systems and forward compatibility with upcoming standards.
    - Example: Test a responsive web application across Chrome (v120+), Firefox (v115+), Safari (v17+), and Edge, plus mobile variants on iOS 17 and Android 14, confirming UI rendering fidelity.

11. **Accessibility Tests**
    - Championing inclusivity, these tests enforce adherence to global standards like WCAG 2.2 and ADA, verifying that the interface is perceivable, operable, understandable, and robust for users with disabilities.
    - Sub-focus areas: Automated scans plus manual audits for color contrast and keyboard navigation.
    - Example: Use screen readers (e.g., NVDA or VoiceOver) to navigate a form-based UI, ensuring alt text for images, ARIA labels for dynamic elements, and focus management for interactive components.

12. **Exploratory & Ad-hoc Tests**
    - Embracing human ingenuity, these unstructured, intuition-driven sessions empower testers to freestyle probe for latent defects through creative scenario invention and anomaly hunting.
    - Sub-focus areas: Heuristic checklists and session-based test management (SBTM).
    - Example: A QA engineer inputs absurd edge cases like Unicode overloads or rapid-fire clicks into a search bar, unearthing unhandled exceptions or UI glitches not captured by scripted tests.

13. **Smoke Tests**
    - Serving as the initial stability gatekeeper, these high-level sanity checks confirm that the build is fundamentally operational and worthy of deeper scrutiny, preventing wasted effort on broken artifacts.
    - Sub-focus areas: Core pathway validation post-build or deployment.
    - Example: Post-CI build, verify that the application launches without crashes, the homepage loads, and basic navigation (e.g., menu clicks) responds affirmatively.

14. **Sanity Tests**
    - Narrowly focused verifications of specific, high-impact functionalities, these quick-hit tests provide rapid confidence in targeted areas after minor changes or hotfixes.
    - Sub-focus areas: Post-fix validation for bug resolutions.
    - Example: After patching a login vulnerability, sanity-check that credential submission still authenticates valid users while rejecting invalids, without broader system interference.

15. **Usability Tests**
    - Centered on human-centered design principles, these tests gauge the intuitiveness, learnability, and satisfaction of user interactions, often involving real-user feedback loops.
    - Sub-focus areas: Task completion rates, error frequencies, and subjective satisfaction scores (e.g., SUS metrics).
    - Example: Conduct moderated sessions where participants attempt tasks like "filter search results," observing friction points in UI affordances or terminology.

16. **Localization & Internationalization (L10n/I18n) Tests**
    - Ensuring global reach, these tests validate proper handling of multilingual content, cultural adaptations, and locale-specific formats (e.g., date/time, currency).
    - Sub-focus areas: Right-to-left (RTL) script rendering and pseudo-localization for string expansion.
    - Example: Translate a dashboard to Spanish and test that date pickers default to DD/MM/YYYY, currency displays as €, and text overflows are handled gracefully in RTL languages like Arabic.

17. **Recovery & Resilience Tests**
    - Probing fault-tolerance mechanisms, these tests simulate disruptions (e.g., network failures, crashes) to confirm automated recovery, data consistency, and minimal user impact.
    - Sub-focus areas: Checkpointing, rollback strategies, and chaos engineering injections.
    - Example: Abruptly terminate a database connection mid-transaction and verify that the system rolls back changes, notifies users appropriately, and resumes upon reconnection.

18. **Data Integrity & Backup Tests**
    - Safeguarding informational fidelity, these tests audit data persistence, validation rules, and archival processes to prevent corruption, loss, or unauthorized alterations.
    - Sub-focus areas: ACID property enforcement and full-system restore simulations.
    - Example: Insert malformed data via bulk import, confirm rejection with audit logs, then execute a backup followed by a point-in-time restore to validate dataset wholeness.

**ENFORCE:**

- **Merge Gate Protocols**: Prohibit the integration of any novel functionality, feature enhancements, or defect resolutions into the main branch unless accompanied by comprehensive, peer-reviewed tests achieving the stipulated 98% coverage threshold within the pertinent categories. Leverage tools like SonarQube or Codecov for automated enforcement.
- **Critical Workflow Mandates**: For mission-critical pathways—such as authentication sequences, financial transactions, or data export pipelines—mandate layered coverage encompassing Build Verification Tests (BVT), End-to-End (E2E), Regression, and Security testing as an irreducible minimum, supplemented by Performance and Recovery tests where applicable.
- **CI/CD Pipeline Integration**: Embed automated test orchestration as a non-optional facet of the continuous integration/continuous deployment (CI/CD) workflow, utilizing frameworks like Jenkins, GitHub Actions, or CircleCI to trigger parallel execution across categories upon every commit or pull request. Incorporate flakiness detection, coverage drift alerts, and mandatory approvals for test suite expansions.
- **Ongoing Vigilance and Evolution**: Conduct quarterly audits of test coverage metrics, incorporating stakeholder feedback to evolve the suite dynamically. Foster a culture of test-driven development (TDD) and behavior-driven development (BDD), with dedicated metrics dashboards to track adherence and pinpoint coverage gaps.

---

### 5. Test Organization

**RULE: Tests Must Mirror Project Structure and Remain Readable**

- Unit tests: `tests/unit/`
- Integration tests: `tests/integration/`
- End-to-End tests: `tests/e2e/`
- Shared test utilities: `tests/utils/`
- Fixtures & mock data: `tests/fixtures/`

**PATTERN:** For every source file/module, there should be a corresponding test
file located in the test directory structure.

---

## DOCUMENTATION STANDARDS

### 6. Automatic Documentation Updates

**RULE: Documentation Must Be Updated with Every Change**

- **VERSION file:** Increment the application version and include release notes.
- **CHANGELOG.md:** Describe changes in detail (files affected, features
  added/removed, bugs fixed).
- **README.md / User Docs:** Update instructions, usage examples, and new
  features.
- **API Docs:** Maintain accurate inline documentation for all public functions
  and interfaces.

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

**AUGMENT AI RULE: Implementing Robust, Secure, Structured, and User-Centric Error Management Practices**

In the pursuit of building resilient and trustworthy software systems, it is imperative to adopt a comprehensive approach to error handling that prioritizes security, maintainability, and an exceptional user experience. This rule mandates the following principles and practices to ensure that errors are managed proactively, transparently (where appropriate), and without compromising the integrity of the application or revealing undue vulnerabilities.

- **Prohibit the Exposure of Internal Diagnostics or Confidential Information to End-Users**: To safeguard sensitive operational details and prevent potential security breaches, under no circumstances should internal stack traces, debugging artifacts, or any form of confidential data—such as API keys, user identifiers, or system configurations—be surfaced to end-users. Instead, these should be confined to internal logging mechanisms accessible only to authorized developers and system administrators.

- **Employ Structured Logging Mechanisms for Comprehensive Error Capture and Analysis**: All errors encountered within the application must be meticulously recorded using a structured logging framework (e.g., JSON-formatted logs with fields for timestamps, error codes, severity levels, and contextual metadata). This facilitates efficient post-mortem analysis, automated alerting, and correlation of issues across distributed systems, thereby accelerating root-cause identification and resolution.

- **Deliver Clear, Informative, and Action-Oriented Error Communications to Users**: Where errors impact the end-user experience, furnish messages that are not only descriptive of the issue at hand but also empower users with practical next steps—such as retrying the operation, contacting support with a specific reference code, or checking system prerequisites. These messages should be crafted in plain, empathetic language, avoiding technical jargon, to foster trust and reduce user frustration without divulging underlying implementation details.

- **Incorporate Graceful Degradation and Fallback Mechanisms for Enhanced Reliability**: Design the system architecture to anticipate failures by integrating fallback strategies, such as defaulting to cached data, invoking alternative service endpoints, or queuing operations for later processing. This ensures that partial functionality remains available during disruptions, minimizing downtime and maintaining a seamless user journey even in the face of transient or unforeseen errors.

- **Automate Issue Reporting for Test Failures with Enriched Contextual Documentation**: In the event that a test case—whether unit, integration, or end-to-end—encounters an anomaly or failure, the system shall automatically generate and submit a detailed GitHub Issue. This issue must include a comprehensive summary of the failure, the exact reproduction steps, relevant logs or screenshots, and the aforementioned descriptive, actionable error messages. Additionally, tag the issue appropriately (e.g., with labels like "bug", "test-failure", or "needs-triage") to streamline triage and assignment, ensuring that development velocity is preserved through swift remediation.

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
- Respect published API quotas usage policies.

---

## VERSION CONTROL & COLLABORATION

### 14. Commit Message Standards

**RULE: Follow Conventional Commit Conventions**

Format: `type(scope): description`  
Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

---

### 15. Errors Logged as "Issues" in GitHub

**RULE: All Errors, Bugs, or Unexpected Behaviors Must Be Tracked in GitHub
Issues**

Errors or anomalies discovered during development, testing, or production must
be logged as **Issues** in GitHub to ensure visibility, traceability, and
accountability. Test Case failures must first be logged as GitHub Issues with
appropriate documentation.

**Guidelines:**

- **Title:** Short, descriptive summary (e.g.,
  `"Login API returns 500 on empty payload"`).
- **Description:** Include detailed context, reproduction steps, expected vs.
  actual behavior, and screenshots/logs if applicable.
- **Labels:** Tag appropriately (`bug`, `security`, `performance`, `docs`,
  etc.).
- **Priority:** Assign severity (`critical`, `high`, `medium`, `low`).
- **Assignees:** Assign responsible developer/team.
- **Linkage:** Connect issues to related commits, PRs, or discussions.
- **Lifecycle:** Issues must be tracked from creation → triage → assignment →
  resolution → closure.

**ENFORCE:**

- No error should remain undocumented.
- Verbal or private reports are insufficient; GitHub Issue tracking is
  mandatory.
- Closed issues should reference the resolving commit or PR.

---

### 16. Branch Management

**RULE: Follow a Structured Branching Strategy**

- `main`: Production-ready branch.
- `develop`: Consolidated development branch.
- `feature/*`: For new features.
- `hotfix/*`: Emergency production fixes.
- `release/*`: Release preparation.

---

### 17. Pre-commit Validation

**RULE: Require Automated Quality Checks**

- Linting for code quality and style consistency.
- Type-checking where supported.
- Automated tests must pass.
- Security scans for dependency vulnerabilities.

---

## DEVELOPMENT WORKFLOW

### 18. Feature Development Process

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

### 19. Code Review Requirements

**RULE: Code Reviews Are Mandatory for All Merges**

Reviewers must check for:

- Functional correctness.
- Security vulnerabilities.
- Test coverage adequacy.
- Documentation accuracy.
- Architectural and stylistic consistency.

---

## ENVIRONMENT & DEPENDENCIES

### 20. Environment Configuration

**RULE: Environments Must Be Isolated and Clearly Defined**

- Provide separate configurations for development, testing, and production.
- Allow local overrides for developers without committing them.
- Validate all configuration schemas.

---

### 21. Dependency Management

**RULE: Secure and Maintainable Dependency Practices**

- Audit dependencies regularly.
- Pin dependency versions to prevent unexpected changes.
- Use trusted package sources.
- Automate dependency update checks.

---

## MONITORING & MAINTENANCE

### 22. Health Monitoring

**RULE: Implement Automated Monitoring**

- Provide application health endpoints.
- Monitor database and external API connectivity.
- Track performance metrics.
- Implement real-time alerting.

---

### 23. Logging Standards

**RULE: Use Structured Logging Across the Application**

- Log with appropriate levels (`error`, `warn`, `info`, `debug`).
- Include correlation IDs for tracking distributed requests.
- Log security-related events explicitly.
- Use structured/JSON logging for production systems.

---

## DEPLOYMENT & PRODUCTION

### 24. Production Readiness

**RULE: All Code Must Pass a Deployment Checklist**

- Pass BVT test suite after every build.
- All tests passing.
- Security scans completed.
- Performance benchmarks validated.
- Documentation fully updated.
- Monitoring configured and operational.

---

### 25. Rollback Procedures

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

### At All Time:

- Follow the Rules and Guidelines for the project.
- Plan out your actions.
- Work logically through the process.
- Be sure to cover all of the instances where am enhancement alters the
  application.
- Handle errors and fallback to seamless solutions.
