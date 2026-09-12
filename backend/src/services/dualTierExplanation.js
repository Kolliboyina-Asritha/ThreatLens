/**
 * ThreatLens AI - Dual-Tier Security Explanation Registry
 * 
 * Provides structured 3-part explanations for all security concepts, heuristic rules,
 * ML signals, threat intel feeds, and user protection policy actions:
 * 1. Technical Explanation (precise forensic finding)
 * 2. In Simple Words (plain-language explanation for ordinary users)
 * 3. Why It Matters (practical risk and security consequence)
 */

export const DUAL_TIER_EXPLANATIONS = {
  // Heuristic Rule Explanations
  NO_HTTPS: {
    title: 'Unencrypted Connection (No HTTPS)',
    technical: 'The target URL utilizes the plaintext HTTP protocol rather than HTTPS. TLS/SSL encryption is absent for network transit.',
    simple: 'This website is not using a secure, encrypted connection to protect your web traffic.',
    whyItMatters: 'Any passwords, financial details, or personal information you enter can be intercepted by eavesdroppers on the same network.'
  },
  IP_ADDRESS_HOSTNAME: {
    title: 'Direct IP Address Hostname',
    technical: 'The hostname resolves to a literal IPv4 or IPv6 address instead of a registered domain name (RFC 1123).',
    simple: 'The link sends you directly to a numerical computer address instead of a normal website domain name like google.com.',
    whyItMatters: 'Legitimate services almost always use domain names. Attackers often use direct IP addresses to bypass domain reputation checks and domain takedowns.'
  },
  SUSPICIOUS_KEYWORDS: {
    title: 'Security & Credential Keywords Detected',
    technical: 'The URL path or query string contains sensitive authentication or transaction tokens (e.g. login, verify, account, billing, secure).',
    simple: 'The web address contains sensitive words like "login", "verify", or "account" trying to look like an official service.',
    whyItMatters: 'Phishing pages use these keywords to trick users into believing they are visiting an official bank, email, or account recovery portal.'
  },
  EXCESSIVE_SUBDOMAINS: {
    title: 'Excessive Subdomain Stacking',
    technical: 'The hostname contains 3 or more nested subdomain labels preceding the registered domain zone.',
    simple: 'The website address has unusually many dots and prefixes stacked together (e.g., login.verify.portal.account.example.com).',
    whyItMatters: 'Phishing kits stack familiar brand names in subdomains to deceive mobile and desktop users into trusting a fraudulent domain.'
  },
  SUSPICIOUS_PERCENT_ENCODING: {
    title: 'Obfuscated Percent-Encoding',
    technical: 'The URL contains dense or consecutive percent-encoded hex sequences (%20, %2F, %3F, %25) designed to evade signature matching.',
    simple: 'The link contains hidden or scrambled characters (like %20 or %2F) that mask its real destination.',
    whyItMatters: 'Attackers scramble parts of the address so security scanners cannot easily read the malicious payload before you click it.'
  },
  EMBEDDED_AT_SYMBOL: {
    title: 'Embedded "@" Hostname Confusion',
    technical: 'The URL contains an "@" delimiter in the authority component, causing user-info authentication confusion per RFC 3986.',
    simple: 'The link includes an "@" symbol inside the address (e.g. http://google.com@evil-site.com).',
    whyItMatters: 'Browsers ignore everything before the "@" symbol and actually navigate to whatever follows it, creating a dangerous visual illusion.'
  },
  EXCESSIVE_URL_LENGTH: {
    title: 'Excessive URL Length',
    technical: 'The total character count of the URL exceeds standard thresholds (>80 characters), frequently correlating with embedded payloads.',
    simple: 'The web address is unusually long and crowded with excessive text.',
    whyItMatters: 'Attackers create extremely long links to push the actual malicious domain off-screen on smartphones and compact browsers.'
  },
  EXCESSIVE_SPECIAL_CHARACTERS: {
    title: 'Excessive Special Characters',
    technical: 'High density of non-alphanumeric special characters across the URL structure.',
    simple: 'The link is cluttered with symbols like hyphens, underscores, slashes, and question marks.',
    whyItMatters: 'Abnormal symbol density often indicates automated phishing kit generation or obfuscated redirection parameters.'
  },
  SUSPICIOUS_HOSTNAME_STRUCTURE: {
    title: 'Suspicious Hostname Structure & Typosquatting',
    technical: 'Hostname contains multiple hyphens or unusually long label segments mimicking brand domain namespaces.',
    simple: 'The website name looks like a misspelling or variation of a well-known brand (e.g. paypal-security-update.com).',
    whyItMatters: 'Typosquatting and hyphenated lookalikes are designed to trick you into believing you are on a genuine brand website.'
  },

  // Machine Learning & Core Engine Concepts
  RANDOM_FOREST_ML: {
    title: 'Random Forest Machine Learning Classifier',
    technical: 'An ensemble of 100 decision trees evaluating 18 lexical and structural URL dimensions trained on Tranco top legitimate sites and PhishTank/URLhaus feeds.',
    simple: 'Our AI model compares the link’s patterns against thousands of known safe and malicious websites.',
    whyItMatters: 'Machine learning spots subtle patterns and new emerging threats that simple rule checks might miss.'
  },
  VIRUSTOTAL_INTEL: {
    title: 'VirusTotal Threat Intelligence Feed',
    technical: 'Multi-vendor consensus telemetry queried via SHA-256 URL hash against 70+ global antivirus engines and security research labs.',
    simple: 'A worldwide network of security scanners that check whether this link has already been reported as dangerous.',
    whyItMatters: 'If global security vendors have already flagged this site, it is actively participating in known cyber attacks.'
  },
  RISK_FUSION: {
    title: 'Multi-Engine Risk Fusion',
    technical: 'Weighted composite normalization combining Heuristics (35%), Machine Learning (40%), and Threat Intelligence (25%) with dynamic weight renormalization.',
    simple: 'We combine all our security checks into a single overall risk score from 0 to 100.',
    whyItMatters: 'No single security tool catches everything; fusing multiple independent checks provides far more accurate and reliable protection.'
  },

  // Protection Modes & Actions
  ASK_ME_MODE: {
    title: 'Ask Me Protection Mode',
    technical: 'Advisory mode: Evaluates complete threat evidence and provides recommended action, but never automatically blocks navigation without explicit user approval.',
    simple: 'ThreatLens will warn you when a site looks dangerous, but always lets you decide whether to go back or proceed anyway.',
    whyItMatters: 'You retain complete control over your browsing while staying fully informed about every potential risk.'
  },
  BALANCED_MODE: {
    title: 'Balanced Protection Mode (Recommended)',
    technical: 'Tiered enforcement: Automatically allows safe URLs (<30), displays interactive warnings for suspicious URLs (30–69), and blocks high-risk threats (>=70) with reversible overrides.',
    simple: 'The recommended setting: blocks clear threats, warns you about suspicious links, and stays quiet on safe sites.',
    whyItMatters: 'Provides robust everyday security against real threats without interrupting your normal browsing.'
  },
  STRICT_MODE: {
    title: 'Strict Protection Mode',
    technical: 'Maximum security policy: Automatically enforces blocking on all high-risk threats and surfaces mandatory warnings on any suspicious indicators.',
    simple: 'High-security mode that immediately stops access to dangerous links to prevent accidental clicks.',
    whyItMatters: 'Best for high-security environments, banking tasks, or users who want maximum automated protection.'
  },
  CUSTOM_MODE: {
    title: 'Custom Protection Mode',
    technical: 'User-configured numerical threshold enforcement defining personalized allowMax and warnMax cutoffs.',
    simple: 'Custom mode where you set your own sensitivity levels for when ThreatLens should allow, warn, or block.',
    whyItMatters: 'Gives advanced users and analysts the flexibility to tune detection sensitivity to their exact preferences.'
  },
  ALLOWLIST_OVERRIDE: {
    title: 'Allowlisted by User',
    technical: 'User-configured domain or URL allowlist match bypassing automated blocking recommendations.',
    simple: 'You previously marked this website as trusted, so ThreatLens allows it.',
    whyItMatters: 'Ensures your trusted personal tools and websites are never blocked, while keeping the decision fully reversible.'
  },
  BLOCKLIST_ENFORCED: {
    title: 'Blocklisted by User',
    technical: 'Explicit domain or URL blocklist match enforcing immediate blocking regardless of heuristic or ML scores.',
    simple: 'You previously added this website to your personal blocklist.',
    whyItMatters: 'Gives you complete control to permanently block unwanted or dangerous sites from ever opening.'
  }
};

/**
 * Returns a complete dual-tier explanation object for a given indicator rule or concept key.
 * @param {string} key - Concept or rule key
 * @returns {{ title: string, technical: string, simple: string, whyItMatters: string }}
 */
export const getDualTierExplanation = (key) => {
  if (!key) return null;
  const normalizedKey = String(key).toUpperCase();
  return (
    DUAL_TIER_EXPLANATIONS[normalizedKey] || {
      title: key,
      technical: `Security indicator identified: ${key}. Evaluated against ThreatLens forensic rules.`,
      simple: `ThreatLens detected an unusual pattern with this link related to "${key}".`,
      whyItMatters: 'Unusual patterns can indicate phishing, spoofing, or malicious deception attempts.'
    }
  );
};
