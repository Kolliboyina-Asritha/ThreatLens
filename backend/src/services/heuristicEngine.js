import {
  HEURISTIC_WEIGHTS,
  INDICATOR_SEVERITY,
  THRESHOLDS
} from '../config/constants.js';

/**
 * Evaluates extracted URL features against modular heuristic rules.
 * Each rule operates independently and produces an explainable indicator if triggered.
 * 
 * @param {object} features - Extracted URL features from urlAnalyzer
 * @returns {Array<{ type: string, severity: string, score: number, message: string, details?: object }>}
 */
export const evaluateHeuristics = (features) => {
  const indicators = [];

  // Rule 1: No HTTPS (Plaintext HTTP)
  if (!features.usesHttps) {
    indicators.push({
      type: 'NO_HTTPS',
      severity: INDICATOR_SEVERITY.MEDIUM,
      score: HEURISTIC_WEIGHTS.NO_HTTPS,
      message: 'The URL does not use HTTPS encryption, transmitting data in cleartext.',
      details: {
        protocol: features.protocol
      }
    });
  }

  // Rule 2: IP Address Hostname
  if (features.isIpAddress) {
    indicators.push({
      type: 'IP_ADDRESS_HOSTNAME',
      severity: INDICATOR_SEVERITY.HIGH,
      score: HEURISTIC_WEIGHTS.IP_HOSTNAME,
      message: 'The hostname is a raw IP address rather than a registered domain name, common in malicious campaigns.',
      details: {
        hostname: features.hostname,
        isIpv4: features.isIpv4,
        isIpv6: features.isIpv6
      }
    });
  }

  // Rule 3: Suspicious Security Keywords
  if (features.detectedKeywords && features.detectedKeywords.length > 0) {
    const count = features.detectedKeywords.length;
    // Base score + additional per extra keyword
    const keywordScore = Math.min(
      HEURISTIC_WEIGHTS.SUSPICIOUS_KEYWORD_BASE + (count - 1) * HEURISTIC_WEIGHTS.SUSPICIOUS_KEYWORD_ADDITIONAL,
      20
    );

    indicators.push({
      type: 'SUSPICIOUS_KEYWORDS',
      severity: count > 2 ? INDICATOR_SEVERITY.MEDIUM : INDICATOR_SEVERITY.LOW,
      score: keywordScore,
      message: `Detected ${count} security-sensitive keyword(s) in URL path/query (e.g. credentials, verification, or banking terms).`,
      details: {
        keywords: features.detectedKeywords
      }
    });
  }

  // Rule 4: Excessive Subdomains
  if (features.subdomainCount >= THRESHOLDS.SUBDOMAIN_COUNT_HIGH) {
    indicators.push({
      type: 'EXCESSIVE_SUBDOMAINS',
      severity: INDICATOR_SEVERITY.MEDIUM,
      score: HEURISTIC_WEIGHTS.EXCESSIVE_SUBDOMAINS,
      message: `The domain contains ${features.subdomainCount} subdomain layers, often used in phishing to disguise destination origins.`,
      details: {
        subdomains: features.subdomains,
        subdomainCount: features.subdomainCount
      }
    });
  }

  // Rule 5: Excessive URL Length
  if (features.urlLength >= THRESHOLDS.URL_LENGTH_HIGH) {
    const isVeryLong = features.urlLength > 150;
    indicators.push({
      type: 'EXCESSIVE_URL_LENGTH',
      severity: isVeryLong ? INDICATOR_SEVERITY.MEDIUM : INDICATOR_SEVERITY.LOW,
      score: isVeryLong ? HEURISTIC_WEIGHTS.LONG_URL + 4 : HEURISTIC_WEIGHTS.LONG_URL,
      message: `The URL length is unusually long (${features.urlLength} characters), potentially hiding suspicious query parameters or payload obfuscation.`,
      details: {
        urlLength: features.urlLength,
        pathnameLength: features.pathnameLength,
        queryLength: features.queryLength
      }
    });
  }

  // Rule 6: Excessive Special Characters
  if (features.specialCharacterCount >= THRESHOLDS.SPECIAL_CHAR_COUNT_HIGH) {
    indicators.push({
      type: 'EXCESSIVE_SPECIAL_CHARACTERS',
      severity: INDICATOR_SEVERITY.MEDIUM,
      score: HEURISTIC_WEIGHTS.EXCESSIVE_SPECIAL_CHARS,
      message: `Contains an abnormally high frequency of special characters (${features.specialCharacterCount}), frequently seen in URL obfuscation techniques.`,
      details: {
        specialCharacterCount: features.specialCharacterCount,
        hyphenCount: features.hyphenCount,
        underscoreCount: features.underscoreCount
      }
    });
  }

  // Rule 7: Suspicious Percent Encoding
  if (features.percentCount >= THRESHOLDS.PERCENT_ENCODING_COUNT_HIGH) {
    indicators.push({
      type: 'SUSPICIOUS_PERCENT_ENCODING',
      severity: INDICATOR_SEVERITY.MEDIUM,
      score: HEURISTIC_WEIGHTS.SUSPICIOUS_PERCENT_ENCODING,
      message: `Contains multiple percent-encoded sequences (${features.percentCount}), which may be used to bypass signature detection.`,
      details: {
        percentCount: features.percentCount
      }
    });
  }

  // Rule 8: Suspicious Hostname Structure (Hyphens / Long labels)
  if (features.hostnameHyphenCount >= THRESHOLDS.HOSTNAME_HYPHEN_COUNT_HIGH) {
    indicators.push({
      type: 'SUSPICIOUS_HOSTNAME_STRUCTURE',
      severity: INDICATOR_SEVERITY.MEDIUM,
      score: HEURISTIC_WEIGHTS.SUSPICIOUS_HOSTNAME_STRUCTURE,
      message: `The hostname contains multiple hyphens (${features.hostnameHyphenCount}), commonly used in typo-squatting or brand impersonation.`,
      details: {
        hostname: features.hostname,
        hostnameHyphenCount: features.hostnameHyphenCount
      }
    });
  }

  // Additional Rule: '@' symbol in URL (Credential confusion/redirection)
  if (features.atSymbolCount > 0) {
    indicators.push({
      type: 'EMBEDDED_AT_SYMBOL',
      severity: INDICATOR_SEVERITY.HIGH,
      score: HEURISTIC_WEIGHTS.AT_SYMBOL_IN_URL,
      message: 'The URL contains an "@" symbol, which can mislead users by prefixing spoofed credentials before the real authority.',
      details: {
        atSymbolCount: features.atSymbolCount
      }
    });
  }

  return indicators;
};
