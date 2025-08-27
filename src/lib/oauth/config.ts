/**
 * OAuth 2.0 Configuration
 * Central configuration for OAuth 2.0 server implementation
 */

import { OAuthConfig, SecurityConfig, OAuthScope } from '@/types/oauth'

/**
 * OAuth 2.0 Server Configuration
 */
export const oauthConfig: OAuthConfig = {
  issuer: process.env.OAUTH_ISSUER || 'https://localhost:3000',
  authorizationEndpoint: '/api/oauth/authorize',
  tokenEndpoint: '/api/oauth/token',
  userinfoEndpoint: '/api/oauth/userinfo',
  introspectionEndpoint: '/api/oauth/introspect',
  revocationEndpoint: '/api/oauth/revoke',
  jwksUri: '/api/oauth/.well-known/jwks.json',

  supportedGrantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
  supportedResponseTypes: ['code'],
  supportedScopes: ['openid', 'profile', 'email', 'read', 'write', 'admin'],
  supportedCodeChallengeMethods: ['S256', 'plain'],
  tokenEndpointAuthMethods: ['client_secret_basic', 'client_secret_post', 'none'],

  // Token lifetimes (in seconds)
  accessTokenLifetime: parseInt(process.env.OAUTH_ACCESS_TOKEN_LIFETIME || '3600'), // 1 hour
  refreshTokenLifetime: parseInt(process.env.OAUTH_REFRESH_TOKEN_LIFETIME || '2592000'), // 30 days
  authorizationCodeLifetime: parseInt(process.env.OAUTH_AUTH_CODE_LIFETIME || '600'), // 10 minutes

  // Security settings
  requirePkce: process.env.OAUTH_REQUIRE_PKCE === 'true' || true,
  allowPublicClients: process.env.OAUTH_ALLOW_PUBLIC_CLIENTS === 'true' || true,
}

/**
 * Security Configuration
 */
export const securityConfig: SecurityConfig = {
  requireHttps: process.env.NODE_ENV === 'production',
  allowedOrigins: process.env.OAUTH_ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  corsEnabled: true,

  rateLimiting: {
    authorization: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 100,
      skipSuccessfulRequests: false,
    },
    token: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 50,
      skipSuccessfulRequests: false,
    },
    introspection: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 200,
      skipSuccessfulRequests: true,
    },
    userinfo: {
      windowMs: 15 * 60 * 1000, // 15 minutes
      maxRequests: 100,
      skipSuccessfulRequests: true,
    },
  },

  bruteForceProtection: {
    enabled: true,
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    blockDurationMs: 30 * 60 * 1000, // 30 minutes
  },
}

/**
 * Default OAuth Scopes
 */
export const defaultScopes: OAuthScope[] = [
  {
    name: 'openid',
    description: 'OpenID Connect authentication',
    isDefault: true,
    requiresConsent: false,
  },
  {
    name: 'profile',
    description: 'Access to basic profile information',
    isDefault: true,
    requiresConsent: false,
  },
  {
    name: 'email',
    description: 'Access to email address',
    isDefault: false,
    requiresConsent: true,
  },
  {
    name: 'read',
    description: 'Read access to business data',
    isDefault: false,
    requiresConsent: true,
  },
  {
    name: 'write',
    description: 'Write access to business data',
    isDefault: false,
    requiresConsent: true,
  },
  {
    name: 'admin',
    description: 'Administrative access to all resources',
    isDefault: false,
    requiresConsent: true,
  },
]

/**
 * JWT Configuration
 */
export const jwtConfig = {
  algorithm: 'HS256' as const,
  secret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
  issuer: oauthConfig.issuer,
  audience: 'business-scraper-api',
}

/**
 * PKCE Configuration
 */
export const pkceConfig = {
  codeVerifierLength: 128,
  supportedMethods: ['S256', 'plain'] as const,
  defaultMethod: 'S256' as const,
}

/**
 * Client Registration Configuration
 */
export const clientRegistrationConfig = {
  allowDynamicRegistration: process.env.OAUTH_ALLOW_DYNAMIC_REGISTRATION === 'true' || false,
  requireRegistrationAccessToken: false,
  defaultTokenEndpointAuthMethod: 'client_secret_basic',
  defaultGrantTypes: ['authorization_code', 'refresh_token'] as const,
  defaultResponseTypes: ['code'] as const,
  defaultScope: 'openid profile',
  clientSecretLength: 64,
  clientIdLength: 32,
}

/**
 * Database Configuration for OAuth
 */
export const oauthDatabaseConfig = {
  // Table names
  tables: {
    clients: 'oauth_clients',
    authorizationCodes: 'oauth_authorization_codes',
    accessTokens: 'oauth_access_tokens',
    refreshTokens: 'oauth_refresh_tokens',
    sessions: 'oauth_sessions',
    scopes: 'oauth_scopes',
    users: 'oauth_users',
  },

  // Cleanup intervals (in milliseconds)
  cleanup: {
    expiredTokensInterval: 60 * 60 * 1000, // 1 hour
    expiredCodesInterval: 10 * 60 * 1000, // 10 minutes
    expiredSessionsInterval: 24 * 60 * 60 * 1000, // 24 hours
  },
}

/**
 * Error Messages
 */
export const oauthErrorMessages = {
  invalid_request:
    'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.',
  invalid_client:
    'Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method).',
  invalid_grant:
    'The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client.',
  unauthorized_client:
    'The authenticated client is not authorized to use this authorization grant type.',
  unsupported_grant_type:
    'The authorization grant type is not supported by the authorization server.',
  invalid_scope: 'The requested scope is invalid, unknown, or malformed.',
  access_denied: 'The resource owner or authorization server denied the request.',
  unsupported_response_type:
    'The authorization server does not support obtaining an authorization code using this method.',
  server_error:
    'The authorization server encountered an unexpected condition that prevented it from fulfilling the request.',
  temporarily_unavailable:
    'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
}

/**
 * Well-known OAuth 2.0 Discovery Document
 */
export const discoveryDocument = {
  issuer: oauthConfig.issuer,
  authorization_endpoint: `${oauthConfig.issuer}${oauthConfig.authorizationEndpoint}`,
  token_endpoint: `${oauthConfig.issuer}${oauthConfig.tokenEndpoint}`,
  userinfo_endpoint: `${oauthConfig.issuer}${oauthConfig.userinfoEndpoint}`,
  introspection_endpoint: `${oauthConfig.issuer}${oauthConfig.introspectionEndpoint}`,
  revocation_endpoint: `${oauthConfig.issuer}${oauthConfig.revocationEndpoint}`,
  jwks_uri: `${oauthConfig.issuer}${oauthConfig.jwksUri}`,
  registration_endpoint: `${oauthConfig.issuer}/api/oauth/register`,

  response_types_supported: oauthConfig.supportedResponseTypes,
  grant_types_supported: oauthConfig.supportedGrantTypes,
  subject_types_supported: ['public'],
  id_token_signing_alg_values_supported: [jwtConfig.algorithm],
  scopes_supported: oauthConfig.supportedScopes,
  token_endpoint_auth_methods_supported: oauthConfig.tokenEndpointAuthMethods,
  code_challenge_methods_supported: oauthConfig.supportedCodeChallengeMethods,

  claims_supported: ['sub', 'name', 'email', 'roles', 'permissions'],
  response_modes_supported: ['query', 'fragment'],

  service_documentation: `${oauthConfig.issuer}/docs/oauth`,
  ui_locales_supported: ['en'],
}
