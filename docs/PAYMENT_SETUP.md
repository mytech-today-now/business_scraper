# Payment System Setup Guide

## Overview

This guide provides comprehensive instructions for setting up the Stripe payment
system in the Business Scraper application. The payment system supports
subscription-based billing with multiple tiers and secure payment processing.

## Prerequisites

- Node.js 18+ installed
- Stripe account (sign up at https://stripe.com)
- Business Scraper application deployed or running locally
- Access to environment configuration files

## 1. Stripe Account Setup

### Create Stripe Account

1. Sign up at https://stripe.com
2. Complete account verification process
3. Enable payment methods for your region
4. Complete business information and tax settings

### Get API Keys

1. Navigate to **Developers > API keys** in Stripe Dashboard
2. Copy your **Publishable key** (starts with `pk_`)
3. Copy your **Secret key** (starts with `sk_`)
4. Keep these keys secure - never commit them to version control

### Create Products and Prices

1. Navigate to **Products** in Stripe Dashboard
2. Create the following products:

#### Starter Plan

- **Name**: Starter
- **Description**: Perfect for small businesses getting started
- **Monthly Price**: $29.00 USD
- **Yearly Price**: $290.00 USD (17% discount)

#### Professional Plan

- **Name**: Professional
- **Description**: Ideal for growing businesses with advanced needs
- **Monthly Price**: $79.00 USD
- **Yearly Price**: $790.00 USD (17% discount)

#### Enterprise Plan

- **Name**: Enterprise
- **Description**: For large organizations with unlimited requirements
- **Monthly Price**: $199.00 USD
- **Yearly Price**: $1,990.00 USD (17% discount)

3. Copy the Price IDs for each plan (starts with `price_`)

## 2. Webhook Configuration

### Create Webhook Endpoint

1. Navigate to **Developers > Webhooks** in Stripe Dashboard
2. Click **Add endpoint**
3. Set endpoint URL to: `https://yourdomain.com/api/webhooks/stripe`
4. Select the following events to send:
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `payment_intent.succeeded`
   - `payment_intent.payment_failed`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`
   - `customer.created`
   - `customer.updated`
   - `customer.deleted`

5. Copy the **Webhook signing secret** (starts with `whsec_`)

## 3. Environment Configuration

### Production Environment (`config/production.env`)

```bash
# Stripe Payment Configuration (Production)
STRIPE_PUBLISHABLE_KEY=pk_live_YOUR_LIVE_PUBLISHABLE_KEY
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_YOUR_LIVE_PUBLISHABLE_KEY
STRIPE_SECRET_KEY=sk_live_YOUR_LIVE_SECRET_KEY
STRIPE_WEBHOOK_SECRET=whsec_YOUR_LIVE_WEBHOOK_SECRET

# Stripe Price IDs for subscription plans
STRIPE_STARTER_PRICE_ID=price_YOUR_STARTER_MONTHLY_PRICE_ID
STRIPE_PROFESSIONAL_PRICE_ID=price_YOUR_PROFESSIONAL_MONTHLY_PRICE_ID
STRIPE_ENTERPRISE_PRICE_ID=price_YOUR_ENTERPRISE_MONTHLY_PRICE_ID
STRIPE_STARTER_YEARLY_PRICE_ID=price_YOUR_STARTER_YEARLY_PRICE_ID
STRIPE_PROFESSIONAL_YEARLY_PRICE_ID=price_YOUR_PROFESSIONAL_YEARLY_PRICE_ID
STRIPE_ENTERPRISE_YEARLY_PRICE_ID=price_YOUR_ENTERPRISE_YEARLY_PRICE_ID

# Payment URLs
PAYMENT_SUCCESS_URL=https://yourdomain.com/payment/success
PAYMENT_CANCEL_URL=https://yourdomain.com/payment/cancel
```

### Development Environment (`config/development.env`)

```bash
# Stripe Payment Configuration (Development)
STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_TEST_PUBLISHABLE_KEY
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_test_YOUR_TEST_PUBLISHABLE_KEY
STRIPE_SECRET_KEY=sk_test_YOUR_TEST_SECRET_KEY
STRIPE_WEBHOOK_SECRET=whsec_YOUR_TEST_WEBHOOK_SECRET

# Stripe Price IDs for subscription plans (test mode)
STRIPE_STARTER_PRICE_ID=price_test_starter_monthly
STRIPE_PROFESSIONAL_PRICE_ID=price_test_professional_monthly
STRIPE_ENTERPRISE_PRICE_ID=price_test_enterprise_monthly
STRIPE_STARTER_YEARLY_PRICE_ID=price_test_starter_yearly
STRIPE_PROFESSIONAL_YEARLY_PRICE_ID=price_test_professional_yearly
STRIPE_ENTERPRISE_YEARLY_PRICE_ID=price_test_enterprise_yearly

# Payment URLs (development)
PAYMENT_SUCCESS_URL=http://localhost:3000/payment/success
PAYMENT_CANCEL_URL=http://localhost:3000/payment/cancel
```

## 4. Database Migration

The payment system requires database tables for storing subscription and payment
data.

### Run Migration

```bash
npm run db:migrate
```

### Manual Database Setup

If automatic migration fails, create the following tables:

```sql
-- Subscription plans table
CREATE TABLE subscription_plans (
  id VARCHAR(100) PRIMARY KEY,
  stripe_price_id VARCHAR(200) NOT NULL,
  name VARCHAR(100) NOT NULL,
  description TEXT,
  price_cents INTEGER NOT NULL,
  currency VARCHAR(3) NOT NULL DEFAULT 'USD',
  interval VARCHAR(10) NOT NULL CHECK (interval IN ('month', 'year')),
  features JSONB NOT NULL DEFAULT '[]',
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User subscriptions table
CREATE TABLE user_subscriptions (
  id VARCHAR(100) PRIMARY KEY,
  user_id VARCHAR(100) NOT NULL,
  stripe_subscription_id VARCHAR(200) NOT NULL,
  plan_id VARCHAR(100) NOT NULL REFERENCES subscription_plans(id),
  status VARCHAR(20) NOT NULL,
  current_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
  current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
  cancel_at_period_end BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Payment transactions table
CREATE TABLE payment_transactions (
  id VARCHAR(100) PRIMARY KEY,
  user_id VARCHAR(100) NOT NULL,
  stripe_payment_intent_id VARCHAR(200),
  amount_cents INTEGER NOT NULL,
  currency VARCHAR(3) NOT NULL DEFAULT 'USD',
  status VARCHAR(20) NOT NULL,
  description TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Feature usage tracking table
CREATE TABLE feature_usage (
  id VARCHAR(100) PRIMARY KEY,
  user_id VARCHAR(100) NOT NULL,
  feature_type VARCHAR(50) NOT NULL,
  usage_count INTEGER NOT NULL DEFAULT 1,
  date DATE NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_user_subscriptions_user_id ON user_subscriptions(user_id);
CREATE INDEX idx_user_subscriptions_status ON user_subscriptions(status);
CREATE INDEX idx_payment_transactions_user_id ON payment_transactions(user_id);
CREATE INDEX idx_feature_usage_user_id_date ON feature_usage(user_id, date);
```

## 5. Testing the Payment System

### Test Cards for Development

Use these test card numbers in development mode:

- **Success**: 4242 4242 4242 4242
- **Decline**: 4000 0000 0000 0002
- **3D Secure**: 4000 0025 0000 3155
- **Insufficient Funds**: 4000 0000 0000 9995

### Testing Webhooks Locally

1. Install Stripe CLI: https://stripe.com/docs/stripe-cli
2. Login to Stripe CLI: `stripe login`
3. Forward webhooks to local server:
   ```bash
   stripe listen --forward-to localhost:3000/api/webhooks/stripe
   ```
4. Copy the webhook signing secret from CLI output
5. Update your development environment with the webhook secret

### Test Subscription Flow

1. Navigate to `/pricing` page
2. Select a subscription plan
3. Use test card number: 4242 4242 4242 4242
4. Complete payment process
5. Verify success page displays correctly
6. Check Stripe Dashboard for subscription creation

## 6. Production Deployment

### Security Checklist

- [ ] Use live Stripe keys (not test keys)
- [ ] Webhook endpoint is HTTPS only
- [ ] Environment variables are secure
- [ ] Database is backed up
- [ ] SSL certificate is valid
- [ ] CORS is properly configured

### Monitoring

- Monitor webhook delivery in Stripe Dashboard
- Set up alerts for failed payments
- Monitor subscription metrics and churn
- Track payment success/failure rates

## 7. Troubleshooting

### Common Issues

#### Webhook Signature Verification Failed

- Verify webhook secret is correct
- Check that endpoint URL matches exactly
- Ensure webhook is receiving raw body (not parsed JSON)

#### Payment Intent Creation Failed

- Verify Stripe secret key is correct
- Check that customer exists in Stripe
- Validate payment amount and currency

#### Subscription Not Created

- Check webhook delivery in Stripe Dashboard
- Verify database connection
- Check application logs for errors

### Support Resources

- Stripe Documentation: https://stripe.com/docs
- Stripe Support: https://support.stripe.com
- Application Logs: Check `/logs` directory
- Database Logs: Check PostgreSQL logs

## 8. Security Best Practices

- Never log sensitive payment data
- Use HTTPS for all payment endpoints
- Validate webhook signatures
- Implement rate limiting on payment endpoints
- Regular security audits and updates
- PCI compliance for handling card data
- Encrypt sensitive data at rest
