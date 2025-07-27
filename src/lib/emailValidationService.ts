'use strict';

import { EmailValidationResult } from '@/types/business';
import { logger } from '@/utils/logger';
import dns from 'dns/promises';

/**
 * Advanced Email Validation Service
 * Implements comprehensive email validation including syntax, domain, deliverability,
 * disposable email detection, and role-based email identification
 */
export class EmailValidationService {
  private static instance: EmailValidationService;
  private validationCache = new Map<string, EmailValidationResult>();
  private disposableDomainsCache = new Set<string>();
  private mxRecordCache = new Map<string, boolean>();

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

  // Enhanced email regex for better syntax validation
  private readonly emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

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
   * Perform comprehensive email validation
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

    // 5. Calculate deliverability score
    const deliverabilityScore = this.calculateDeliverabilityScore(
      syntaxValid, mxRecords, isDisposable, isRoleBased
    );

    // 6. Calculate overall confidence
    const confidence = this.calculateConfidence(
      syntaxValid, mxRecords, deliverabilityScore, isDisposable, isRoleBased
    );

    const result: EmailValidationResult = {
      email: originalEmail, // Preserve original case
      isValid: syntaxValid && mxRecords && !isDisposable,
      deliverabilityScore,
      isDisposable,
      isRoleBased,
      domain,
      mxRecords,
      confidence,
      validationTimestamp,
      errors: errors.length > 0 ? errors : undefined
    };

    logger.debug('EmailValidationService', `Validated email ${originalEmail}`, {
      isValid: result.isValid,
      confidence: result.confidence,
      deliverabilityScore: result.deliverabilityScore
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
   * Calculate deliverability score (0-100)
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
   * Calculate overall confidence score (0-100)
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
   * Initialize disposable domains from external source (placeholder)
   */
  private async initializeDisposableDomains(): Promise<void> {
    // In a production environment, this could fetch from an external API
    // or load from a regularly updated file
    // For now, we use the hardcoded list above
    logger.debug('EmailValidationService', `Initialized with ${this.disposableDomains.size} disposable domains`);
  }

  /**
   * Clear validation cache
   */
  public clearCache(): void {
    this.validationCache.clear();
    this.mxRecordCache.clear();
    logger.debug('EmailValidationService', 'Validation cache cleared');
  }

  /**
   * Get cache statistics
   */
  public getCacheStats(): { validationCacheSize: number; mxCacheSize: number } {
    return {
      validationCacheSize: this.validationCache.size,
      mxCacheSize: this.mxRecordCache.size
    };
  }
}
