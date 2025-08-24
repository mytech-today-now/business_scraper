'use strict';

import { EmailValidationResult } from '@/types/business';
import { logger } from '@/utils/logger';
import dns from 'dns/promises';
import net from 'net';
import crypto from 'crypto';

/**
 * Advanced Email Validation Service
 * Implements comprehensive email validation including syntax, domain, deliverability,
 * disposable email detection, and role-based email identification
 */
export class EmailValidationService {
  private static instance: EmailValidationService;
  private validationCache = new Map<string, EmailValidationResult>();
  private mxRecordCache = new Map<string, boolean>();
  private smtpCache = new Map<string, { verified: boolean; response: string; timestamp: number }>();
  private catchAllCache = new Map<string, { isCatchAll: boolean; timestamp: number }>();
  private reputationCache = new Map<string, { score: number; timestamp: number }>();

  // SMTP timeout settings
  private readonly SMTP_TIMEOUT = 10000; // 10 seconds
  private readonly CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

  // Common disposable email domains
  private readonly disposableDomains = new Set([
    '10minutemail.com', '10minutemail.net', 'guerrillamail.com', 'mailinator.com',
    'tempmail.org', 'temp-mail.org', 'throwaway.email', 'yopmail.com',
    'maildrop.cc', 'sharklasers.com', 'guerrillamailblock.com', 'pokemail.net',
    'spam4.me', 'bccto.me', 'chacuo.net', 'dispostable.com', 'emailondeck.com',
    'fakeinbox.com', 'hide.biz.st', 'mytrashmail.com', 'mailnesia.com',
    'trashmail.net', 'trashmail.org', 'trashmail.me', 'trashmail.de',
    'mailcatch.com', 'mailexpire.com', 'mailforspam.com', 'mailfreeonline.com',
    'mailnull.com', 'mailshell.com', 'mailsac.com', 'mailtemp.info',
    'mohmal.com', 'mvrht.com', 'nwldx.com', 'objectmail.com', 'protonmail.com',
    'putthisinyourspamdatabase.com', 'quickemailverification.com', 'rcpt.at',
    'recode.me', 'rhyta.com', 'rppkn.com', 'safe-mail.net', 'selfdestructingmail.com',
    'sendspamhere.com', 'shieldedmail.com', 'slopsbox.com', 'smashmail.de',
    'snakemail.com', 'sneakemail.com', 'sogetthis.com', 'soodonims.com',
    'spambog.com', 'spambog.de', 'spambog.ru', 'spambox.us', 'spamcannon.com',
    'spamcannon.net', 'spamcon.org', 'spamcorptastic.com', 'spamday.com',
    'spamex.com', 'spamfree24.com', 'spamfree24.de', 'spamfree24.eu',
    'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org', 'spamhole.com',
    'spamify.com', 'spaminator.de', 'spamkill.info', 'spaml.com', 'spaml.de',
    'spammotel.com', 'spamobox.com', 'spamspot.com', 'spamthis.co.uk',
    'spamthisplease.com', 'spamtrail.com', 'spamtroll.net', 'speed.1s.fr',
    'spoofmail.de', 'stuffmail.de', 'super-auswahl.de', 'supergreatmail.com',
    'supermailer.jp', 'superrito.com', 'superstachel.de', 'suremail.info',
    'tagyourself.com', 'teewars.org', 'teleworm.com', 'teleworm.us',
    'temp-mail.ru', 'tempalias.com', 'tempe-mail.com', 'tempemail.biz',
    'tempemail.com', 'tempinbox.co.uk', 'tempinbox.com', 'tempmail.eu',
    'tempmail2.com', 'tempmaildemo.com', 'tempmailer.com', 'tempmailer.de',
    'tempmailaddress.com', 'tempthe.net', 'thanksnospam.info', 'thankyou2010.com',
    'thecloudindex.com', 'thisisnotmyrealemail.com', 'thismail.net',
    'throwawayemailaddresses.com', 'tilien.com', 'tmail.ws', 'tmailinator.com',
    'toiea.com', 'toomail.biz', 'topranklist.de', 'tradermail.info',
    'trash2009.com', 'trash2010.com', 'trash2011.com', 'trash-amil.com',
    'trashdevil.com', 'trashemail.de', 'trashymail.com', 'tyldd.com',
    'uggsrock.com', 'umail.net', 'upliftnow.com', 'uplipht.com', 'uroid.com',
    'us.af', 'venompen.com', 'veryrealemail.com', 'viditag.com', 'viewcastmedia.com',
    'viewcastmedia.net', 'viewcastmedia.org', 'vomoto.com', 'vpn.st',
    'vsimcard.com', 'vubby.com', 'wasteland.rfc822.org', 'webemail.me',
    'weg-werf-email.de', 'wegwerfadresse.de', 'wegwerfemail.com', 'wegwerfemail.de',
    'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org', 'wh4f.org',
    'whyspam.me', 'willselfdestruct.com', 'winemaven.info', 'wronghead.com',
    'wuzup.net', 'wuzupmail.net', 'www.e4ward.com', 'www.gishpuppy.com',
    'www.mailinator.com', 'wwwnew.eu', 'x.ip6.li', 'xagloo.com', 'xemaps.com',
    'xents.com', 'xmaily.com', 'xoxy.net', 'yapped.net', 'yeah.net',
    'yep.it', 'yogamaven.com', 'yopmail.fr', 'yopmail.net', 'ypmail.webredirect.org',
    'yuurok.com', 'zehnminutenmail.de', 'zetmail.com', 'zippymail.info',
    'zoaxe.com', 'zoemail.org'
  ]);

  // Role-based email patterns
  private readonly roleBasedPatterns = [
    /^(info|contact|sales|support|admin|office|hello|inquiries|service|help|team|general)@/i,
    /^(marketing|hr|careers|jobs|billing|finance|accounting|legal|compliance)@/i,
    /^(webmaster|postmaster|hostmaster|abuse|security|privacy|noreply|no-reply)@/i,
    /^(orders|shipping|returns|customer|clients|partners|vendors|suppliers)@/i
  ];

  // Enhanced email regex for better syntax validation - ReDoS safe version
  private readonly emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?){0,10}$/;

  private constructor() {
    this.initializeDisposableDomains();
  }

  public static getInstance(): EmailValidationService {
    if (!EmailValidationService.instance) {
      EmailValidationService.instance = new EmailValidationService();
    }
    return EmailValidationService.instance;
  }

  /**
   * Validate email address with comprehensive checks
   */
  public async validateEmail(email: string): Promise<EmailValidationResult> {
    const normalizedEmail = email.toLowerCase().trim();

    // Check cache first
    if (this.validationCache.has(normalizedEmail)) {
      const cachedResult = this.validationCache.get(normalizedEmail)!;
      // Return with original email case preserved
      return { ...cachedResult, email };
    }

    const result = await this.performValidation(email, normalizedEmail);

    // Cache the result with normalized email as key
    this.validationCache.set(normalizedEmail, result);

    return result;
  }

  /**
   * Validate multiple emails in batch
   */
  public async validateEmails(emails: string[]): Promise<EmailValidationResult[]> {
    const validationPromises = emails.map(email => this.validateEmail(email));
    return Promise.all(validationPromises);
  }

  /**
   * Perform comprehensive email validation with advanced features
   */
  private async performValidation(originalEmail: string, normalizedEmail: string): Promise<EmailValidationResult> {
    const domain = this.extractDomain(normalizedEmail);
    const validationTimestamp = new Date().toISOString();
    const errors: string[] = [];

    // 1. Syntax validation (use normalized email for validation)
    const syntaxValid = this.validateSyntax(normalizedEmail);
    if (!syntaxValid) {
      errors.push('Invalid email syntax');
    }

    // 2. Domain validation (MX record check)
    const mxRecords = await this.checkMXRecords(domain);
    if (!mxRecords) {
      errors.push('Domain has no valid MX records');
    }

    // 3. Disposable email detection
    const isDisposable = this.isDisposableEmail(domain);
    if (isDisposable) {
      errors.push('Disposable email domain detected');
    }

    // 4. Role-based email detection (use normalized email)
    const isRoleBased = this.isRoleBasedEmail(normalizedEmail);

    // 5. Advanced SMTP verification (only if basic checks pass)
    let smtpVerified = false;
    let mailServerResponse = '';
    let greylisted = false;

    if (syntaxValid && mxRecords && !isDisposable) {
      try {
        const smtpResult = await this.performSMTPVerification(normalizedEmail, domain);
        smtpVerified = smtpResult.verified;
        mailServerResponse = smtpResult.response;
        greylisted = smtpResult.greylisted;
      } catch (error) {
        logger.debug('EmailValidationService', `SMTP verification failed for ${normalizedEmail}`, error);
        errors.push('SMTP verification failed');
      }
    }

    // 6. Catch-all domain detection
    let catchAllDomain = false;
    if (mxRecords) {
      try {
        catchAllDomain = await this.detectCatchAllDomain(domain);
      } catch (error) {
        logger.debug('EmailValidationService', `Catch-all detection failed for ${domain}`, error);
      }
    }

    // 7. Email reputation scoring
    let reputationScore = 50; // Default neutral score
    try {
      reputationScore = await this.calculateEmailReputation(normalizedEmail, domain);
    } catch (error) {
      logger.debug('EmailValidationService', `Reputation scoring failed for ${normalizedEmail}`, error);
    }

    // 8. Bounce rate prediction
    const bounceRatePrediction = this.predictBounceRate(
      syntaxValid, mxRecords, isDisposable, isRoleBased, smtpVerified, catchAllDomain, reputationScore
    );

    // 9. Calculate deliverability score with advanced factors
    const deliverabilityScore = this.calculateAdvancedDeliverabilityScore(
      syntaxValid, mxRecords, isDisposable, isRoleBased, smtpVerified, catchAllDomain, reputationScore
    );

    // 10. Calculate overall confidence with advanced factors
    const confidence = this.calculateAdvancedConfidence(
      syntaxValid, mxRecords, deliverabilityScore, isDisposable, isRoleBased,
      smtpVerified, catchAllDomain, reputationScore
    );

    const result: EmailValidationResult = {
      email: originalEmail, // Preserve original case
      isValid: syntaxValid && mxRecords && !isDisposable && (smtpVerified || !catchAllDomain),
      deliverabilityScore,
      isDisposable,
      isRoleBased,
      domain,
      mxRecords,
      confidence,
      validationTimestamp,
      errors: errors.length > 0 ? errors : undefined,
      // Advanced validation features
      smtpVerified,
      catchAllDomain,
      reputationScore,
      bounceRatePrediction,
      mailServerResponse: mailServerResponse || undefined,
      greylisted
    };

    logger.debug('EmailValidationService', `Advanced validation completed for ${originalEmail}`, {
      isValid: result.isValid,
      confidence: result.confidence,
      deliverabilityScore: result.deliverabilityScore,
      smtpVerified: result.smtpVerified,
      reputationScore: result.reputationScore
    });

    return result;
  }

  /**
   * Validate email syntax using enhanced regex
   */
  private validateSyntax(email: string): boolean {
    if (!email || email.length > 254) return false;
    
    // Check for basic format
    if (!this.emailRegex.test(email)) return false;
    
    // Additional checks
    const [localPart, domainPart] = email.split('@');
    
    // Local part checks
    if (localPart.length > 64) return false;
    if (localPart.startsWith('.') || localPart.endsWith('.')) return false;
    if (localPart.includes('..')) return false;
    
    // Domain part checks
    if (domainPart.length > 253) return false;
    if (domainPart.startsWith('-') || domainPart.endsWith('-')) return false;
    
    return true;
  }

  /**
   * Check MX records for domain
   */
  private async checkMXRecords(domain: string): Promise<boolean> {
    // Check cache first
    if (this.mxRecordCache.has(domain)) {
      return this.mxRecordCache.get(domain)!;
    }

    try {
      const mxRecords = await dns.resolveMx(domain);
      const hasMX = mxRecords && mxRecords.length > 0;
      
      // Cache the result
      this.mxRecordCache.set(domain, hasMX);
      
      return hasMX;
    } catch (error) {
      logger.debug('EmailValidationService', `MX record check failed for ${domain}`, error);
      this.mxRecordCache.set(domain, false);
      return false;
    }
  }

  /**
   * Check if email domain is disposable
   */
  private isDisposableEmail(domain: string): boolean {
    return this.disposableDomains.has(domain.toLowerCase());
  }

  /**
   * Check if email is role-based
   */
  private isRoleBasedEmail(email: string): boolean {
    return this.roleBasedPatterns.some(pattern => pattern.test(email));
  }

  /**
   * Extract domain from email
   */
  private extractDomain(email: string): string {
    const parts = email.split('@');
    return parts.length === 2 ? parts[1].toLowerCase() : '';
  }

  /**
   * Calculate deliverability score (0-100) - Legacy method
   */
  private calculateDeliverabilityScore(
    syntaxValid: boolean,
    mxRecords: boolean,
    isDisposable: boolean,
    isRoleBased: boolean
  ): number {
    let score = 0;

    if (syntaxValid) score += 30;
    if (mxRecords) score += 40;
    if (!isDisposable) score += 20;
    if (!isRoleBased) score += 10;

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Calculate advanced deliverability score with SMTP and reputation factors
   */
  private calculateAdvancedDeliverabilityScore(
    syntaxValid: boolean,
    mxRecords: boolean,
    isDisposable: boolean,
    isRoleBased: boolean,
    smtpVerified: boolean,
    catchAllDomain: boolean,
    reputationScore: number
  ): number {
    let score = 0;

    // Basic factors
    if (syntaxValid) score += 20;
    if (mxRecords) score += 25;
    if (!isDisposable) score += 15;
    if (!isRoleBased) score += 10;

    // Advanced factors
    if (smtpVerified) score += 20;
    if (!catchAllDomain) score += 10;

    // Reputation factor (0-100 scale, normalize to 0-10)
    score += (reputationScore / 100) * 10;

    return Math.min(100, Math.max(0, Math.round(score)));
  }

  /**
   * Calculate overall confidence score (0-100) - Legacy method
   */
  private calculateConfidence(
    syntaxValid: boolean,
    mxRecords: boolean,
    deliverabilityScore: number,
    isDisposable: boolean,
    isRoleBased: boolean
  ): number {
    // If syntax is invalid, confidence should be 0
    if (!syntaxValid) return 0;

    let confidence = deliverabilityScore;

    // Adjust confidence based on additional factors
    if (isDisposable) confidence *= 0.3; // Heavily penalize disposable emails
    if (isRoleBased) confidence *= 0.8; // Slightly penalize role-based emails
    if (!mxRecords) confidence *= 0.5; // Penalize no MX records

    return Math.round(Math.min(100, Math.max(0, confidence)));
  }

  /**
   * Calculate advanced confidence score with all validation factors
   */
  private calculateAdvancedConfidence(
    syntaxValid: boolean,
    mxRecords: boolean,
    deliverabilityScore: number,
    isDisposable: boolean,
    isRoleBased: boolean,
    smtpVerified: boolean,
    catchAllDomain: boolean,
    reputationScore: number
  ): number {
    // If syntax is invalid, confidence should be 0
    if (!syntaxValid) return 0;

    let confidence = deliverabilityScore;

    // Adjust confidence based on validation factors
    if (isDisposable) confidence *= 0.2; // Heavily penalize disposable emails
    if (isRoleBased) confidence *= 0.85; // Slightly penalize role-based emails
    if (!mxRecords) confidence *= 0.3; // Heavily penalize no MX records
    if (smtpVerified) confidence *= 1.1; // Boost for SMTP verification
    if (catchAllDomain) confidence *= 0.7; // Penalize catch-all domains

    // Reputation factor adjustment
    const reputationFactor = Math.max(0.5, reputationScore / 100);
    confidence *= reputationFactor;

    return Math.round(Math.min(100, Math.max(0, confidence)));
  }

  /**
   * Perform SMTP verification for email address
   */
  private async performSMTPVerification(email: string, domain: string): Promise<{
    verified: boolean;
    response: string;
    greylisted: boolean;
  }> {
    // Check cache first
    const cacheKey = email;
    const cached = this.smtpCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
      return {
        verified: cached.verified,
        response: cached.response,
        greylisted: cached.response.includes('greylist') || cached.response.includes('try again')
      };
    }

    try {
      // Get MX records for the domain
      const mxRecords = await dns.resolveMx(domain);
      if (!mxRecords || mxRecords.length === 0) {
        throw new Error('No MX records found');
      }

      // Sort MX records by priority
      mxRecords.sort((a, b) => a.priority - b.priority);
      const mailServer = mxRecords[0].exchange;

      // Perform SMTP connection test
      const result = await this.testSMTPConnection(mailServer, email);

      // Cache the result
      this.smtpCache.set(cacheKey, {
        verified: result.verified,
        response: result.response,
        timestamp: Date.now()
      });

      return result;
    } catch (error) {
      const errorResult = {
        verified: false,
        response: error instanceof Error ? error.message : 'SMTP verification failed',
        greylisted: false
      };

      // Cache negative results for shorter time
      this.smtpCache.set(cacheKey, {
        verified: false,
        response: errorResult.response,
        timestamp: Date.now()
      });

      return errorResult;
    }
  }

  /**
   * Test SMTP connection to verify email deliverability
   */
  private async testSMTPConnection(mailServer: string, email: string): Promise<{
    verified: boolean;
    response: string;
    greylisted: boolean;
  }> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let response = '';
      let verified = false;
      let greylisted = false;

      const timeout = setTimeout(() => {
        socket.destroy();
        resolve({
          verified: false,
          response: 'Connection timeout',
          greylisted: false
        });
      }, this.SMTP_TIMEOUT);

      socket.connect(25, mailServer, () => {
        // Connected to SMTP server
      });

      socket.on('data', (data) => {
        const serverResponse = data.toString();
        response += serverResponse;

        // Check for greylist indicators
        if (serverResponse.includes('greylist') ||
            serverResponse.includes('try again') ||
            serverResponse.includes('temporarily rejected')) {
          greylisted = true;
        }

        // Simple SMTP verification - check if server accepts the email format
        if (serverResponse.includes('250') && !serverResponse.includes('550')) {
          verified = true;
        }

        // Close connection after getting response
        socket.end();
      });

      socket.on('error', (error) => {
        clearTimeout(timeout);
        resolve({
          verified: false,
          response: error.message,
          greylisted: false
        });
      });

      socket.on('close', () => {
        clearTimeout(timeout);
        resolve({
          verified,
          response: response.trim(),
          greylisted
        });
      });

      // Send basic SMTP commands
      socket.write(`HELO ${domain}\r\n`);
      socket.write(`MAIL FROM:<test@example.com>\r\n`);
      socket.write(`RCPT TO:<${email}>\r\n`);
      socket.write(`QUIT\r\n`);
    });
  }

  /**
   * Detect if domain is catch-all (accepts any email)
   */
  private async detectCatchAllDomain(domain: string): Promise<boolean> {
    // Check cache first
    const cached = this.catchAllCache.get(domain);
    if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
      return cached.isCatchAll;
    }

    try {
      // Test with a random email address that's unlikely to exist
      const randomEmail = `test-${crypto.randomBytes(8).toString('hex')}@${domain}`;
      const smtpResult = await this.performSMTPVerification(randomEmail, domain);

      // If the random email is accepted, it's likely a catch-all domain
      const isCatchAll = smtpResult.verified;

      // Cache the result
      this.catchAllCache.set(domain, {
        isCatchAll,
        timestamp: Date.now()
      });

      return isCatchAll;
    } catch (error) {
      logger.debug('EmailValidationService', `Catch-all detection failed for ${domain}`, error);

      // Cache negative result
      this.catchAllCache.set(domain, {
        isCatchAll: false,
        timestamp: Date.now()
      });

      return false;
    }
  }

  /**
   * Calculate email reputation score based on domain and patterns
   */
  private async calculateEmailReputation(email: string, domain: string): Promise<number> {
    // Check cache first
    const cacheKey = email;
    const cached = this.reputationCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < this.CACHE_TTL) {
      return cached.score;
    }

    let score = 50; // Start with neutral score

    try {
      // Domain reputation factors
      const domainFactors = this.analyzeDomainReputation(domain);
      score += domainFactors;

      // Email pattern analysis
      const patternFactors = this.analyzeEmailPatterns(email);
      score += patternFactors;

      // Normalize score to 0-100 range
      score = Math.min(100, Math.max(0, score));

      // Cache the result
      this.reputationCache.set(cacheKey, {
        score,
        timestamp: Date.now()
      });

      return score;
    } catch (error) {
      logger.debug('EmailValidationService', `Reputation calculation failed for ${email}`, error);
      return 50; // Return neutral score on error
    }
  }

  /**
   * Analyze domain reputation factors
   */
  private analyzeDomainReputation(domain: string): number {
    let score = 0;

    // Well-known email providers get positive score
    const trustedProviders = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
      'icloud.com', 'protonmail.com', 'zoho.com', 'fastmail.com'
    ];

    if (trustedProviders.includes(domain.toLowerCase())) {
      score += 20;
    }

    // Business domains (non-free email providers) get positive score
    if (!this.isFreeEmailProvider(domain)) {
      score += 15;
    }

    // Domain age and structure analysis
    if (domain.includes('-') || domain.includes('_')) {
      score -= 5; // Slightly penalize domains with special characters
    }

    if (domain.length < 4) {
      score -= 10; // Penalize very short domains
    }

    if (domain.length > 20) {
      score -= 5; // Slightly penalize very long domains
    }

    return score;
  }

  /**
   * Analyze email pattern factors
   */
  private analyzeEmailPatterns(email: string): number {
    let score = 0;
    const localPart = email.split('@')[0];

    // Professional-looking email patterns get positive score
    if (/^[a-zA-Z]+\.[a-zA-Z]+$/.test(localPart)) {
      score += 10; // firstname.lastname pattern
    }

    if (/^[a-zA-Z]+$/.test(localPart)) {
      score += 5; // simple name pattern
    }

    // Suspicious patterns get negative score
    if (/\d{4,}/.test(localPart)) {
      score -= 10; // Many consecutive numbers
    }

    if (localPart.length > 30) {
      score -= 10; // Very long local part
    }

    if (/^(test|temp|fake|dummy|sample)/.test(localPart.toLowerCase())) {
      score -= 20; // Test/fake email patterns
    }

    return score;
  }

  /**
   * Check if domain is a free email provider
   */
  private isFreeEmailProvider(domain: string): boolean {
    const freeProviders = [
      'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
      'icloud.com', 'live.com', 'msn.com', 'ymail.com', 'rocketmail.com',
      'mail.com', 'gmx.com', 'inbox.com', 'mail.ru', 'yandex.com'
    ];

    return freeProviders.includes(domain.toLowerCase());
  }

  /**
   * Predict bounce rate based on validation factors
   */
  private predictBounceRate(
    syntaxValid: boolean,
    mxRecords: boolean,
    isDisposable: boolean,
    isRoleBased: boolean,
    smtpVerified: boolean,
    catchAllDomain: boolean,
    reputationScore: number
  ): number {
    let bounceRate = 0;

    // Base bounce rate factors
    if (!syntaxValid) bounceRate += 90;
    if (!mxRecords) bounceRate += 80;
    if (isDisposable) bounceRate += 70;
    if (isRoleBased) bounceRate += 20;
    if (!smtpVerified) bounceRate += 30;
    if (catchAllDomain) bounceRate += 40;

    // Reputation factor (inverse relationship)
    bounceRate += (100 - reputationScore) * 0.3;

    // Normalize to 0-100 range
    return Math.min(100, Math.max(0, Math.round(bounceRate)));
  }

  /**
   * Initialize disposable domains from external source (placeholder)
   */
  private async initializeDisposableDomains(): Promise<void> {
    // In a production environment, this could fetch from an external API
    // or load from a regularly updated file
    // For now, we use the hardcoded list above
    logger.debug('EmailValidationService', `Initialized with ${this.disposableDomains.size} disposable domains`);
  }

  /**
   * Clear all validation caches
   */
  public clearCache(): void {
    this.validationCache.clear();
    this.mxRecordCache.clear();
    this.smtpCache.clear();
    this.catchAllCache.clear();
    this.reputationCache.clear();
    logger.debug('EmailValidationService', 'All validation caches cleared');
  }

  /**
   * Clear expired cache entries
   */
  public clearExpiredCache(): void {
    const now = Date.now();

    // Clear expired SMTP cache entries
    for (const [key, value] of this.smtpCache.entries()) {
      if (now - value.timestamp > this.CACHE_TTL) {
        this.smtpCache.delete(key);
      }
    }

    // Clear expired catch-all cache entries
    for (const [key, value] of this.catchAllCache.entries()) {
      if (now - value.timestamp > this.CACHE_TTL) {
        this.catchAllCache.delete(key);
      }
    }

    // Clear expired reputation cache entries
    for (const [key, value] of this.reputationCache.entries()) {
      if (now - value.timestamp > this.CACHE_TTL) {
        this.reputationCache.delete(key);
      }
    }

    logger.debug('EmailValidationService', 'Expired cache entries cleared');
  }

  /**
   * Get comprehensive cache statistics
   */
  public getCacheStats(): {
    validationCacheSize: number;
    mxCacheSize: number;
    smtpCacheSize: number;
    catchAllCacheSize: number;
    reputationCacheSize: number;
  } {
    return {
      validationCacheSize: this.validationCache.size,
      mxCacheSize: this.mxRecordCache.size,
      smtpCacheSize: this.smtpCache.size,
      catchAllCacheSize: this.catchAllCache.size,
      reputationCacheSize: this.reputationCache.size
    };
  }
}
