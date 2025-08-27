/**
 * OAuth 2.0 Type Definitions
 * Comprehensive types for OAuth 2.0 implementation with PKCE support
 */

export interface OAuthClient {
  id: string
  secret?: string // Only for confidential clients
  name: string
  type: 'public' | 'confidential'
  redirectUris: string[]
  allowedGrantTypes: GrantType[]
  allowedScopes: string[]
  createdAt: Date
  updatedAt: Date
  isActive: boolean
  metadata?: Record<string, unknown>
}

export interface OAuthScope {
  name: string
  description: string
  isDefault: boolean
  requiresConsent: boolean
}

export interface AuthorizationCode {
  code: string
  clientId: string
  userId: string
  redirectUri: string
  scopes: string[]
  codeChallenge?: string
  codeChallengeMethod?: 'S256' | 'plain'
  expiresAt: Date
  createdAt: Date
  isUsed: boolean
}

export interface AccessToken {
  token: string
  tokenType: 'Bearer'
  clientId: string
  userId: string
  scopes: string[]
  expiresAt: Date
  createdAt: Date
  isRevoked: boolean
  refreshToken?: string
}

export interface RefreshToken {
  token: string
  clientId: string
  userId: string
  scopes: string[]
  expiresAt: Date
  createdAt: Date
  isRevoked: boolean
  accessTokenId: string
}

export interface OAuthUser {
  id: string
  username: string
  email?: string
  roles: string[]
  permissions: string[]
  isActive: boolean
  createdAt: Date
  updatedAt: Date
}

export interface PKCEChallenge {
  codeVerifier: string
  codeChallenge: string
  codeChallengeMethod: 'S256' | 'plain'
}

export interface AuthorizationRequest {
  responseType: 'code'
  clientId: string
  redirectUri: string
  scope?: string
  state?: string
  codeChallenge?: string
  codeChallengeMethod?: 'S256' | 'plain'
}

export interface TokenRequest {
  grantType: GrantType
  clientId: string
  clientSecret?: string
  code?: string
  redirectUri?: string
  codeVerifier?: string
  refreshToken?: string
  scope?: string
}

export interface TokenResponse {
  accessToken: string
  tokenType: 'Bearer'
  expiresIn: number
  refreshToken?: string
  scope?: string
}

export interface IntrospectionResponse {
  active: boolean
  scope?: string
  clientId?: string
  username?: string
  tokenType?: string
  exp?: number
  iat?: number
  nbf?: number
  sub?: string
  aud?: string
  iss?: string
  jti?: string
}

export interface UserInfoResponse {
  sub: string
  name?: string
  email?: string
  roles?: string[]
  permissions?: string[]
}

export interface OAuthError {
  error: OAuthErrorType
  errorDescription?: string
  errorUri?: string
  state?: string
}

export type OAuthErrorType =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unauthorized_client'
  | 'unsupported_grant_type'
  | 'invalid_scope'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'server_error'
  | 'temporarily_unavailable'

export type GrantType = 'authorization_code' | 'refresh_token' | 'client_credentials'

export interface OAuthConfig {
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userinfoEndpoint: string
  introspectionEndpoint: string
  revocationEndpoint: string
  jwksUri: string
  supportedGrantTypes: GrantType[]
  supportedResponseTypes: string[]
  supportedScopes: string[]
  supportedCodeChallengeMethods: string[]
  tokenEndpointAuthMethods: string[]
  accessTokenLifetime: number
  refreshTokenLifetime: number
  authorizationCodeLifetime: number
  requirePkce: boolean
  allowPublicClients: boolean
}

export interface JWTPayload {
  iss: string // Issuer
  sub: string // Subject (user ID)
  aud: string // Audience (client ID)
  exp: number // Expiration time
  iat: number // Issued at
  jti: string // JWT ID
  scope: string // Scopes
  client_id: string
  token_type: 'access_token' | 'refresh_token'
}

export interface ClientRegistrationRequest {
  clientName: string
  clientType: 'public' | 'confidential'
  redirectUris: string[]
  scope?: string
  grantTypes?: GrantType[]
  responseTypes?: string[]
  tokenEndpointAuthMethod?: string
  contacts?: string[]
  logoUri?: string
  clientUri?: string
  policyUri?: string
  tosUri?: string
}

export interface ClientRegistrationResponse {
  clientId: string
  clientSecret?: string
  clientIdIssuedAt: number
  clientSecretExpiresAt?: number
  clientName: string
  clientType: 'public' | 'confidential'
  redirectUris: string[]
  grantTypes: GrantType[]
  responseTypes: string[]
  scope: string
  tokenEndpointAuthMethod: string
  registrationAccessToken?: string
  registrationClientUri?: string
}

export interface OAuthSession {
  id: string
  userId: string
  clientId: string
  scopes: string[]
  authorizationCode?: string
  accessToken?: string
  refreshToken?: string
  expiresAt: Date
  createdAt: Date
  lastAccessed: Date
  isActive: boolean
  metadata?: Record<string, unknown>
}

export interface RateLimitConfig {
  windowMs: number
  maxRequests: number
  skipSuccessfulRequests?: boolean
  skipFailedRequests?: boolean
}

export interface SecurityConfig {
  requireHttps: boolean
  allowedOrigins: string[]
  corsEnabled: boolean
  rateLimiting: {
    authorization: RateLimitConfig
    token: RateLimitConfig
    introspection: RateLimitConfig
    userinfo: RateLimitConfig
  }
  bruteForceProtection: {
    enabled: boolean
    maxAttempts: number
    windowMs: number
    blockDurationMs: number
  }
}
