export const RISK_LEVELS = {
  SAFE: 'SAFE',
  SUSPICIOUS: 'SUSPICIOUS',
  HIGH_RISK: 'HIGH_RISK'
};

export const RISK_THRESHOLDS = {
  SAFE_MAX: 30,
  SUSPICIOUS_MAX: 70
};

export const SUSPICIOUS_KEYWORDS = [
  'login',
  'signin',
  'sign-in',
  'verify',
  'verification',
  'account',
  'update',
  'secure',
  'security',
  'bank',
  'password',
  'credential',
  'confirm',
  'wallet',
  'payment',
  'billing',
  'authenticate',
  'authentication',
  'webscr',
  'ebayisapi',
  'banking',
  'recover',
  'unlock',
  'validation'
];

// Exact 9 Modular Heuristic Rules
export const HEURISTIC_RULES = {
  RULE_1_NO_HTTPS: 'NO_HTTPS',
  RULE_2_IP_ADDRESS_HOSTNAME: 'IP_ADDRESS_HOSTNAME',
  RULE_3_SUSPICIOUS_KEYWORDS: 'SUSPICIOUS_KEYWORDS',
  RULE_4_EXCESSIVE_SUBDOMAINS: 'EXCESSIVE_SUBDOMAINS',
  RULE_5_EXCESSIVE_URL_LENGTH: 'EXCESSIVE_URL_LENGTH',
  RULE_6_EXCESSIVE_SPECIAL_CHARACTERS: 'EXCESSIVE_SPECIAL_CHARACTERS',
  RULE_7_SUSPICIOUS_PERCENT_ENCODING: 'SUSPICIOUS_PERCENT_ENCODING',
  RULE_8_SUSPICIOUS_HOSTNAME_STRUCTURE: 'SUSPICIOUS_HOSTNAME_STRUCTURE',
  RULE_9_EMBEDDED_AT_SYMBOL: 'EMBEDDED_AT_SYMBOL'
};

export const HEURISTIC_WEIGHTS = {
  NO_HTTPS: 12,
  IP_HOSTNAME: 28,
  SUSPICIOUS_KEYWORD_BASE: 8,
  SUSPICIOUS_KEYWORD_ADDITIONAL: 4,
  EXCESSIVE_SUBDOMAINS: 16,
  LONG_URL: 10,
  LONG_PATH: 8,
  EXCESSIVE_SPECIAL_CHARS: 12,
  SUSPICIOUS_PERCENT_ENCODING: 15,
  SUSPICIOUS_HOSTNAME_STRUCTURE: 14,
  AT_SYMBOL_IN_URL: 20
};

export const THRESHOLDS = {
  URL_LENGTH_HIGH: 80,
  PATH_LENGTH_HIGH: 50,
  SUBDOMAIN_COUNT_HIGH: 3,
  SPECIAL_CHAR_COUNT_HIGH: 6,
  PERCENT_ENCODING_COUNT_HIGH: 3,
  HOSTNAME_HYPHEN_COUNT_HIGH: 2,
  HOSTNAME_LABEL_LENGTH_HIGH: 30
};

export const INDICATOR_SEVERITY = {
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL'
};

export const AUTH_CONSTANTS = {
  ACCESS_TOKEN_EXPIRY: '15m',
  REFRESH_TOKEN_EXPIRY: '7d',
  REFRESH_COOKIE_NAME: 'threatlens_refresh_token',
  REFRESH_COOKIE_MAX_AGE: 7 * 24 * 60 * 60 * 1000 // 7 days in ms
};

// Phase 2: Risk Fusion Engine Default Weights
export const RISK_FUSION_WEIGHTS = {
  HEURISTICS: 0.35,
  MACHINE_LEARNING: 0.40,
  THREAT_INTELLIGENCE: 0.25
};

// Phase 2: ML Feature Schema Contract (18 Features)
export const ML_FEATURE_SCHEMA_VERSION = 'threatlens_features_v1.0';
export const ML_FEATURE_NAMES = [
  'url_length',
  'hostname_length',
  'path_length',
  'query_length',
  'dot_count',
  'subdomain_count',
  'path_segment_count',
  'query_params_count',
  'special_char_count',
  'digits_count',
  'hyphen_count',
  'underscore_count',
  'at_symbol_count',
  'percent_count',
  'uses_https',
  'is_ip_address',
  'suspicious_keyword_count',
  'suspicious_hostname_pattern'
];

export const SERVICE_CONFIG = {
  ML_TIMEOUT_MS: 3000,
  VIRUSTOTAL_TIMEOUT_MS: 4000,
  LLM_TIMEOUT_MS: 5000,
  TI_CACHE_TTL_HOURS: 24
};

// Phase 3: User-Controlled Protection Policies & Enforcement
export const PROTECTION_MODES = {
  ASK_ME: 'ASK_ME',
  BALANCED: 'BALANCED',
  STRICT: 'STRICT',
  CUSTOM: 'CUSTOM'
};

export const PROTECTION_RECOMMENDATIONS = {
  ALLOW: 'ALLOW',
  WARN: 'WARN',
  BLOCK: 'BLOCK'
};

export const PROTECTION_ACTIONS = {
  ALLOW: 'ALLOW',
  WARN: 'WARN',
  BLOCK: 'BLOCK'
};

export const USER_DECISIONS = {
  ALLOW: 'ALLOW',
  WARN: 'WARN',
  BLOCK: 'BLOCK',
  OVERRIDE: 'OVERRIDE'
};

export const SECURITY_EVENT_SOURCES = {
  WEB: 'WEB',
  EXTENSION: 'EXTENSION',
  SCANNER: 'SCANNER'
};

