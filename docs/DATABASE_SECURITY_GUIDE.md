# Database Security Guide

## Overview

This guide documents the comprehensive security measures implemented in the Business Scraper application to prevent SQL injection attacks and ensure secure database operations. The security enhancements follow OWASP Top 10 guidelines and implement multiple layers of protection.

## Security Architecture

### 1. SecureDatabase Wrapper

The `SecureDatabase` class provides a secure wrapper around postgres.js with the following features:

- **Parameterized Query Execution**: Uses postgres.js template literals instead of unsafe methods
- **Comprehensive Input Validation**: Zod schema validation for all inputs
- **SQL Injection Detection**: Pattern-based detection of malicious SQL
- **Query Timeout Protection**: Prevents long-running malicious queries
- **Transaction Security**: Secure transaction handling with automatic rollback
- **Query Caching**: Safe caching for SELECT queries only
- **Comprehensive Logging**: Detailed security event logging

### 2. Input Validation Schemas

Comprehensive Zod schemas validate all database inputs:

```typescript
// Example: Campaign input validation
const CampaignInputSchema = z.object({
  name: safeString(255),
  description: safeText(1000).optional(),
  industries: z.array(safeString(100)).max(50),
  zipCode: z.string().regex(/^\d{5}(-\d{4})?$/),
  // ... more fields
})
```

### 3. Dynamic Query Building Security

Enhanced query building with explicit parameter binding:

```typescript
// Secure query building example
private buildSecureBusinessQuery(campaignId?: string, filters?: any) {
  const conditions: string[] = []
  const params: any[] = []
  let paramIndex = 1

  if (campaignId) {
    conditions.push(`campaign_id = $${paramIndex}`)
    params.push(campaignId)
    paramIndex++
  }
  
  // ... more conditions with explicit parameter binding
}
```

## Security Features

### SQL Injection Prevention

1. **Pattern Detection**: Detects common SQL injection patterns
   - Comment injection (`--`, `/*`, `*/`, `#`)
   - Boolean-based injection (`OR 1=1`, `AND 1=1`)
   - Union-based injection (`UNION SELECT`)
   - Time-based injection (`SLEEP`, `WAITFOR`, `DELAY`)
   - Stacked queries (`;` followed by SQL keywords)

2. **Parameter Validation**: All parameters are validated for:
   - SQL injection patterns
   - Length limits
   - Type safety
   - Character encoding

3. **Query Structure Validation**: Queries are validated for:
   - Dangerous keywords (`EXEC`, `EXECUTE`, `SP_`, `XP_`)
   - Suspicious patterns
   - Length limits
   - Proper parameterization

### Input Sanitization

All user inputs are sanitized through multiple layers:

1. **Zod Schema Validation**: Structure and type validation
2. **SQL Pattern Detection**: Malicious pattern detection
3. **Length Limits**: Prevent buffer overflow attacks
4. **Character Encoding**: Proper Unicode handling

### Query Execution Security

1. **Template Literals**: Uses postgres.js safe template literals
2. **Parameter Binding**: Explicit parameter binding prevents injection
3. **Prepared Statements**: Automatic statement preparation and caching
4. **Transaction Safety**: Secure transaction handling with validation

## Usage Guidelines

### Safe Query Execution

```typescript
// ✅ CORRECT: Use parameterized queries
const result = await secureDb.query(
  'SELECT * FROM users WHERE email = $1 AND status = $2',
  [email, 'active']
)

// ❌ INCORRECT: Never use string concatenation
const result = await secureDb.query(
  `SELECT * FROM users WHERE email = '${email}'`
)
```

### Input Validation

```typescript
// ✅ CORRECT: Validate inputs with Zod schemas
const validation = BusinessInputSchema.safeParse(inputData)
if (!validation.success) {
  throw new Error('Invalid input data')
}

// ✅ CORRECT: Use validation service
const sqlSafety = DatabaseValidationService.validateSqlSafety(userInput)
if (!sqlSafety.isValid) {
  throw new Error('Input contains dangerous patterns')
}
```

### Transaction Security

```typescript
// ✅ CORRECT: Use secure transactions
await secureDb.transaction(async (tx) => {
  await tx.query('INSERT INTO users (name) VALUES ($1)', [name])
  await tx.query('INSERT INTO profiles (user_id) VALUES ($1)', [userId])
})
```

## Security Testing

### Test Categories

1. **SQL Injection Tests**: Test against known attack patterns
2. **Parameter Validation Tests**: Validate input sanitization
3. **Query Structure Tests**: Ensure safe query construction
4. **Business Logic Tests**: Test application-specific security
5. **Edge Case Tests**: Handle boundary conditions
6. **Performance Tests**: Prevent DoS attacks

### Running Security Tests

```bash
# Run all security tests
npm test -- --testPathPattern=security

# Run specific security test suites
npm test src/tests/security/sql-injection-prevention.test.ts
npm test src/tests/security/secure-database.test.ts
```

## Monitoring and Alerting

### Security Event Logging

All security events are logged with appropriate levels:

- **DEBUG**: Query execution details
- **INFO**: Successful operations
- **WARN**: Suspicious patterns detected
- **ERROR**: Security violations and failures

### Monitoring Metrics

Key security metrics to monitor:

1. **Query Validation Failures**: Failed validation attempts
2. **Suspicious Pattern Detections**: Potential attack attempts
3. **Query Timeouts**: Possible DoS attempts
4. **Parameter Validation Errors**: Input validation failures

## Best Practices

### Development Guidelines

1. **Always Use Parameterized Queries**: Never concatenate user input into SQL
2. **Validate All Inputs**: Use Zod schemas for all user inputs
3. **Follow Least Privilege**: Use minimal database permissions
4. **Regular Security Audits**: Review and test security measures
5. **Keep Dependencies Updated**: Maintain current security patches

### Code Review Checklist

- [ ] All database queries use parameterized queries
- [ ] User inputs are validated with Zod schemas
- [ ] No string concatenation in SQL queries
- [ ] Proper error handling without information leakage
- [ ] Security tests cover new functionality
- [ ] Logging includes security events

## Incident Response

### Security Incident Handling

1. **Detection**: Monitor logs for security violations
2. **Assessment**: Evaluate the scope and impact
3. **Containment**: Block malicious requests
4. **Investigation**: Analyze attack patterns
5. **Recovery**: Restore normal operations
6. **Lessons Learned**: Update security measures

### Emergency Procedures

1. **Immediate Response**: Block suspicious IP addresses
2. **Database Protection**: Enable additional monitoring
3. **Application Security**: Increase validation strictness
4. **Communication**: Notify security team and stakeholders

## Compliance

### OWASP Top 10 Compliance

- [x] **A03:2021 – Injection**: Comprehensive SQL injection prevention
- [x] **A05:2021 – Security Misconfiguration**: Secure database configuration
- [x] **A06:2021 – Vulnerable Components**: Updated dependencies
- [x] **A09:2021 – Security Logging**: Comprehensive security logging

### Security Standards

- **Input Validation**: All inputs validated and sanitized
- **Output Encoding**: Proper data encoding for output
- **Authentication**: Secure database authentication
- **Authorization**: Principle of least privilege
- **Error Handling**: Secure error handling without information disclosure

## Troubleshooting

### Common Issues

1. **Validation Errors**: Check input format and schema compliance
2. **Query Timeouts**: Optimize query performance or increase timeout
3. **Parameter Binding**: Ensure correct parameter count and types
4. **Cache Issues**: Clear cache if stale data is returned

### Debug Mode

Enable debug logging for detailed security information:

```typescript
const result = await secureDb.query(query, params, {
  logQuery: true,
  validateQuery: true
})
```

## Future Enhancements

### Planned Security Improvements

1. **Advanced Threat Detection**: Machine learning-based attack detection
2. **Real-time Monitoring**: Enhanced security monitoring dashboard
3. **Automated Response**: Automatic blocking of malicious requests
4. **Security Metrics**: Advanced security analytics and reporting

### Security Roadmap

- **Q1**: Enhanced monitoring and alerting
- **Q2**: Advanced threat detection
- **Q3**: Automated security response
- **Q4**: Security analytics dashboard

---

For questions or security concerns, contact the security team or create an issue in the GitHub repository.
