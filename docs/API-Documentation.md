# Business Scraper API Documentation

## Overview

The Business Scraper API v1 provides comprehensive RESTful endpoints for business data export, template management, scheduling, and analytics. The API supports OAuth 2.0 authentication, webhook notifications, and enterprise-grade rate limiting.

## Base URL
```
https://your-domain.com/api/v1
```

## Authentication

### OAuth 2.0 (Recommended)
```bash
# Step 1: Get authorization code
GET /api/v1/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&response_type=code&scope=read:businesses write:exports

# Step 2: Exchange code for token
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&code=AUTHORIZATION_CODE&redirect_uri=YOUR_REDIRECT_URI
```

### API Key
```bash
curl -H "X-API-Key: YOUR_API_KEY" https://your-domain.com/api/v1/exports
```

## Rate Limits

- **Per Client**: 100 requests/minute, 1,000 requests/hour
- **Global**: 1,000 requests/minute, 10,000 requests/hour
- **Headers**: `X-RateLimit-Remaining`, `X-RateLimit-Reset`

## Endpoints

### Export Templates

#### List Templates
```bash
GET /api/v1/templates
```

**Query Parameters:**
- `platform` (optional): Filter by platform (salesforce, hubspot, pipedrive, mailchimp, constant-contact)
- `category` (optional): Filter by category (crm, email-marketing)
- `search` (optional): Search templates by name or description
- `details` (optional): Include detailed field mappings (true/false)

**Response:**
```json
{
  "success": true,
  "data": {
    "templates": [
      {
        "id": "salesforce-leads",
        "name": "Salesforce Leads",
        "platform": "salesforce",
        "description": "Export business data as Salesforce Lead records",
        "version": "1.0.0",
        "category": "crm",
        "tags": ["crm", "salesforce", "leads"],
        "createdAt": "2025-01-24T00:00:00.000Z"
      }
    ],
    "count": 5,
    "statistics": {
      "availableTemplates": 5,
      "templatesByPlatform": {
        "salesforce": 1,
        "hubspot": 1,
        "pipedrive": 1,
        "mailchimp": 1,
        "constant-contact": 1
      }
    }
  }
}
```

#### Get Template Details
```bash
GET /api/v1/templates/{templateId}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "template": {
      "id": "salesforce-leads",
      "name": "Salesforce Leads",
      "platform": "salesforce",
      "fieldMappings": [
        {
          "type": "direct",
          "sourceFields": ["businessName"],
          "targetField": "Company",
          "validation": [
            {
              "type": "required",
              "message": "Company name is required"
            }
          ]
        }
      ],
      "requiredFields": ["Company"],
      "optionalFields": ["Phone", "Email", "Website"]
    },
    "validation": {
      "isValid": true,
      "errors": [],
      "warnings": []
    }
  }
}
```

### Exports

#### Create Export
```bash
POST /api/v1/exports
Content-Type: application/json

{
  "templateId": "salesforce-leads",
  "businesses": [
    {
      "businessName": "Acme Corp",
      "email": ["contact@acme.com"],
      "phone": ["555-0123"],
      "website": "https://acme.com",
      "address": {
        "street": "123 Main St",
        "city": "Anytown",
        "state": "CA",
        "zipCode": "12345"
      },
      "industry": "Technology"
    }
  ],
  "options": {
    "format": "csv",
    "validateData": true,
    "includeData": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "export": {
      "id": "export_1706140800000",
      "templateId": "salesforce-leads",
      "status": "completed",
      "recordsProcessed": 1,
      "recordsExported": 1,
      "recordsSkipped": 0,
      "errors": [],
      "warnings": []
    },
    "exportData": [
      {
        "Company": "Acme Corp",
        "Phone": "(555) 012-3456",
        "Email": "contact@acme.com",
        "Website": "https://acme.com",
        "Street": "123 Main St",
        "City": "Anytown",
        "State": "CA",
        "PostalCode": "12345",
        "Industry": "Technology",
        "LeadSource": "Web Scraping",
        "Rating": "Warm"
      }
    ],
    "download": {
      "filename": "salesforce-export-2025-01-24.csv",
      "mimeType": "text/csv",
      "data": "base64-encoded-content",
      "size": 1024
    }
  }
}
```

#### Export Preview
```bash
POST /api/v1/exports/preview
Content-Type: application/json

{
  "templateId": "salesforce-leads",
  "businesses": [...],
  "sampleSize": 3
}
```

#### Multi-Platform Export
```bash
POST /api/v1/exports/multi-platform
Content-Type: application/json

{
  "templateIds": ["salesforce-leads", "hubspot-companies", "mailchimp-contacts"],
  "businesses": [...],
  "options": {
    "continueOnError": true
  }
}
```

### Schedules

#### Create Schedule
```bash
POST /api/v1/schedules
Content-Type: application/json

{
  "name": "Daily CRM Export",
  "description": "Export new leads to Salesforce daily",
  "templateId": "salesforce-leads",
  "schedule": {
    "type": "cron",
    "expression": "0 9 * * *",
    "timezone": "America/New_York"
  },
  "filters": {
    "industries": ["Technology", "Healthcare"],
    "dateRange": {
      "start": "2025-01-01",
      "end": "2025-12-31"
    }
  },
  "delivery": {
    "method": "webhook",
    "destination": "https://your-webhook.com/exports",
    "format": "csv"
  }
}
```

#### List Schedules
```bash
GET /api/v1/schedules?status=active&templateId=salesforce-leads
```

#### Get Schedule Details
```bash
GET /api/v1/schedules/{scheduleId}
```

#### Update Schedule
```bash
PUT /api/v1/schedules/{scheduleId}
Content-Type: application/json

{
  "status": "paused",
  "schedule": {
    "expression": "0 10 * * *"
  }
}
```

#### Delete Schedule
```bash
DELETE /api/v1/schedules/{scheduleId}
```

### Analytics

#### Get Usage Analytics
```bash
# Client analytics
GET /api/v1/analytics?type=client&clientId=your-client-id&startDate=2025-01-01&endDate=2025-01-24

# System analytics
GET /api/v1/analytics?type=system&startDate=2025-01-01&endDate=2025-01-24

# Real-time metrics
GET /api/v1/analytics?type=realtime
```

#### Export Analytics Data
```bash
GET /api/v1/analytics/export?format=csv&type=usage
```

#### Health Status
```bash
GET /api/v1/analytics/health
```

**Response:**
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "services": [
      {
        "service": "api-framework",
        "status": "healthy",
        "lastCheck": "2025-01-24T12:00:00.000Z",
        "responseTime": 45,
        "uptime": 86400
      }
    ],
    "performance": {
      "realTime": {
        "requestsPerMinute": 25,
        "averageResponseTime": 150,
        "errorRate": 0.5,
        "activeClients": 5
      },
      "alerts": []
    }
  }
}
```

#### Rate Limit Status
```bash
GET /api/v1/analytics/rate-limits?clientId=your-client-id
```

## Webhooks

### Webhook Events

- `export.completed` - Export operation completed successfully
- `export.failed` - Export operation failed
- `data.scraped` - New business data scraped
- `data.validated` - Business data validation completed

### Webhook Payload Format
```json
{
  "id": "payload_1706140800000_abc123",
  "event": "export.completed",
  "timestamp": "2025-01-24T12:00:00.000Z",
  "data": {
    "exportId": "export_1706140800000",
    "templateId": "salesforce-leads",
    "recordsExported": 150,
    "status": "completed"
  },
  "metadata": {
    "source": "business-scraper",
    "version": "v1",
    "requestId": "req_1706140800000_xyz789"
  }
}
```

### Webhook Security

Webhooks include HMAC-SHA256 signatures in the `X-Webhook-Signature` header:

```javascript
const crypto = require('crypto');

function verifyWebhook(payload, signature, secret) {
  const expectedSignature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');
  
  const providedSignature = signature.replace('sha256=', '');
  
  return crypto.timingSafeEqual(
    Buffer.from(expectedSignature, 'hex'),
    Buffer.from(providedSignature, 'hex')
  );
}
```

## Error Handling

### Error Response Format
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid template ID provided"
  },
  "metadata": {
    "requestId": "req_1706140800000_abc123",
    "timestamp": "2025-01-24T12:00:00.000Z",
    "version": "v1"
  }
}
```

### Common Error Codes

- `400` - Bad Request (validation errors, missing parameters)
- `401` - Unauthorized (invalid or missing authentication)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found (resource doesn't exist)
- `429` - Too Many Requests (rate limit exceeded)
- `500` - Internal Server Error (server-side errors)

## SDKs and Examples

### JavaScript/Node.js
```javascript
const BusinessScraperAPI = require('@business-scraper/api-client');

const client = new BusinessScraperAPI({
  apiKey: 'your-api-key',
  baseUrl: 'https://your-domain.com/api/v1'
});

// Export businesses to Salesforce
const result = await client.exports.create({
  templateId: 'salesforce-leads',
  businesses: businessData,
  options: { format: 'csv' }
});

console.log(`Exported ${result.recordsExported} records`);
```

### Python
```python
from business_scraper_api import BusinessScraperClient

client = BusinessScraperClient(
    api_key='your-api-key',
    base_url='https://your-domain.com/api/v1'
)

# Create scheduled export
schedule = client.schedules.create({
    'name': 'Daily CRM Export',
    'templateId': 'salesforce-leads',
    'schedule': {
        'type': 'cron',
        'expression': '0 9 * * *'
    },
    'delivery': {
        'method': 'webhook',
        'destination': 'https://your-webhook.com/exports'
    }
})

print(f"Created schedule: {schedule['id']}")
```

## Support

For API support and questions:
- Documentation: [https://docs.business-scraper.com](https://docs.business-scraper.com)
- Support: [support@business-scraper.com](mailto:support@business-scraper.com)
- Status Page: [https://status.business-scraper.com](https://status.business-scraper.com)
