import { normalizeUrl } from './urlNormalizer.js';
import { isIPAddress, isIPv4Address, isIPv6Address } from '../utils/ipValidator.js';
import { SUSPICIOUS_KEYWORDS, THRESHOLDS } from '../config/constants.js';

/**
 * Extracts Top-Level Domain (TLD) and domain components from hostname.
 * @param {string} hostname
 * @param {boolean} isIp
 * @returns {{ tld: string, domain: string, subdomains: string[], subdomainCount: number }}
 */
const extractDomainComponents = (hostname, isIp) => {
  if (isIp || !hostname) {
    return {
      tld: '',
      domain: hostname,
      subdomains: [],
      subdomainCount: 0
    };
  }

  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 1) {
    return {
      tld: '',
      domain: hostname,
      subdomains: [],
      subdomainCount: 0
    };
  }

  // Basic TLD extraction (last part or ccTLD like co.uk)
  const tld = parts[parts.length - 1];
  const secondLast = parts.length > 2 ? parts[parts.length - 2] : '';
  const knownTwoPartSuffixes = ['co.uk', 'com.br', 'gov.uk', 'co.nz', 'com.au', 'org.uk', 'net.au'];
  const fullSuffix = `${secondLast}.${tld}`;

  let domain = '';
  let subdomains = [];

  if (knownTwoPartSuffixes.includes(fullSuffix) && parts.length > 2) {
    domain = parts.slice(-3).join('.');
    subdomains = parts.slice(0, -3);
  } else {
    domain = parts.slice(-2).join('.');
    subdomains = parts.slice(0, -2);
  }

  return {
    tld,
    domain,
    subdomains,
    subdomainCount: subdomains.length
  };
};

/**
 * Detects security-sensitive keywords inside URL components.
 * @param {string} urlString
 * @param {string[]} keywords
 * @returns {string[]} Detected unique keywords
 */
export const findSuspiciousKeywords = (urlString, keywords = SUSPICIOUS_KEYWORDS) => {
  if (!urlString) return [];
  const lower = urlString.toLowerCase();
  const detected = [];

  for (const kw of keywords) {
    const kwLower = kw.toLowerCase();
    // Check if the keyword appears as a standalone token or part of path/subdomain/query
    const regex = new RegExp(`(^|[^a-z0-9])${kwLower}([^a-z0-9]|$)`, 'i');
    if (regex.test(lower) || lower.includes(kwLower)) {
      if (!detected.includes(kwLower)) {
        detected.push(kwLower);
      }
    }
  }

  return detected;
};

/**
 * Extracts comprehensive deterministic security and structural features from a URL.
 * @param {string} rawUrl
 * @returns {object} Extracted feature set
 */
export const extractUrlFeatures = (rawUrl) => {
  const { originalUrl, normalizedUrl, parsedUrl } = normalizeUrl(rawUrl);

  const protocol = parsedUrl.protocol.replace(':', '').toLowerCase();
  const hostname = parsedUrl.hostname.toLowerCase();
  const port = parsedUrl.port || (protocol === 'https' ? '443' : '80');
  const pathname = parsedUrl.pathname || '/';
  const queryString = parsedUrl.search || '';

  const isIp = isIPAddress(hostname);
  const isIpv4 = isIPv4Address(hostname);
  const isIpv6 = isIPv6Address(hostname);

  const domainInfo = extractDomainComponents(hostname, isIp);

  // Length features
  const totalLength = normalizedUrl.length;
  const originalLength = originalUrl.length;
  const hostnameLength = hostname.length;
  const pathnameLength = pathname.length;
  const queryLength = queryString.length;

  // Structural character counts (calculated on normalizedUrl)
  const dotCount = (normalizedUrl.match(/\./g) || []).length;
  const hostnameDotCount = (hostname.match(/\./g) || []).length;
  const pathSegments = pathname.split('/').filter(Boolean);
  const pathSegmentCount = pathSegments.length;
  const queryParamsCount = parsedUrl.searchParams ? Array.from(parsedUrl.searchParams.keys()).length : 0;

  // Specific characters
  const hyphenCount = (normalizedUrl.match(/-/g) || []).length;
  const hostnameHyphenCount = (hostname.match(/-/g) || []).length;
  const underscoreCount = (normalizedUrl.match(/_/g) || []).length;
  const atSymbolCount = Math.max((originalUrl.match(/@/g) || []).length, (normalizedUrl.match(/@/g) || []).length);
  const equalsCount = (normalizedUrl.match(/=/g) || []).length;
  const ampersandCount = (normalizedUrl.match(/&/g) || []).length;
  const percentCount = Math.max((originalUrl.match(/%/g) || []).length, (normalizedUrl.match(/%/g) || []).length);
  const digitsCount = (normalizedUrl.match(/\d/g) || []).length;
  const specialCharsMatch = normalizedUrl.match(/[^a-zA-Z0-9:/._\-?=&%#]/g) || [];
  const specialCharacterCount = specialCharsMatch.length + percentCount + atSymbolCount;

  // Suspicious keywords in path and query
  const pathAndQuery = `${pathname}${queryString}`;
  const detectedKeywords = findSuspiciousKeywords(pathAndQuery);
  const hostnameKeywords = isIp ? [] : findSuspiciousKeywords(hostname);
  const allDetectedKeywords = Array.from(new Set([...detectedKeywords, ...hostnameKeywords]));

  // Suspicious hostname pattern evaluation
  const hostnameLabels = hostname.split('.');
  const hasUnusuallyLongLabel = hostnameLabels.some((lbl) => lbl.length > THRESHOLDS.HOSTNAME_LABEL_LENGTH_HIGH);
  const containsSuspiciousHostnamePattern =
    hostnameHyphenCount >= THRESHOLDS.HOSTNAME_HYPHEN_COUNT_HIGH ||
    hasUnusuallyLongLabel ||
    (isIp && pathname.length > 1);

  // Boolean features
  const usesHttps = protocol === 'https';
  const usesHttp = protocol === 'http';
  const containsSuspiciousKeyword = allDetectedKeywords.length > 0;
  const containsEncodedCharacters = percentCount > 0;
  const containsExcessiveSubdomains = domainInfo.subdomainCount >= THRESHOLDS.SUBDOMAIN_COUNT_HIGH;
  const containsExcessiveSpecialCharacters = specialCharacterCount >= THRESHOLDS.SPECIAL_CHAR_COUNT_HIGH;
  const containsExcessiveLength = totalLength >= THRESHOLDS.URL_LENGTH_HIGH;

  return {
    // General
    originalUrl,
    normalizedUrl,
    protocol,
    hostname,
    port,
    pathname,
    queryString,
    tld: domainInfo.tld,
    domain: domainInfo.domain,
    subdomains: domainInfo.subdomains,

    // Length features
    urlLength: totalLength,
    originalLength,
    hostnameLength,
    pathnameLength,
    queryLength,

    // Structural counts
    dotCount,
    hostnameDotCount,
    subdomainCount: domainInfo.subdomainCount,
    pathSegmentCount,
    queryParamsCount,
    specialCharacterCount,
    digitsCount,
    hyphenCount,
    hostnameHyphenCount,
    underscoreCount,
    atSymbolCount,
    equalsCount,
    ampersandCount,
    percentCount,

    // Boolean security features
    usesHttps,
    usesHttp,
    isIpAddress: isIp,
    isIpv4,
    isIpv6,
    containsSuspiciousKeyword,
    detectedKeywords: allDetectedKeywords,
    containsEncodedCharacters,
    containsSuspiciousHostnamePattern,
    containsExcessiveSubdomains,
    containsExcessiveSpecialCharacters,
    containsExcessiveLength
  };
};
