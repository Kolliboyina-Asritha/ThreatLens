import React, { useState } from 'react';
import { HelpCircle, X, ShieldAlert, Sparkles, Cpu, BookOpen } from 'lucide-react';

export const DUAL_TIER_DATABASE = {
  NO_HTTPS: {
    title: 'Unencrypted Connection (No HTTPS)',
    badge: 'Transport Security',
    technical: 'The target URL utilizes plaintext HTTP rather than HTTPS. Transport Layer Security (TLS/SSL) encryption is absent for network transit.',
    simple: 'This website is not using a secure, encrypted connection to protect your web traffic.',
    whyItMatters: 'Any passwords, financial details, or personal information you enter can be intercepted by eavesdroppers on the same network.'
  },
  IP_ADDRESS_HOSTNAME: {
    title: 'Direct IP Address Hostname',
    badge: 'Network Addressing',
    technical: 'The hostname resolves directly to an IPv4/IPv6 address instead of a registered domain name (RFC 1123).',
    simple: 'The link sends you directly to a numerical computer address instead of a normal website domain name like google.com.',
    whyItMatters: 'Legitimate services almost always use domain names. Attackers often use direct IP addresses to bypass domain reputation checks and domain takedowns.'
  },
  SUSPICIOUS_KEYWORDS: {
    title: 'Security & Credential Keywords Detected',
    badge: 'Lexical Deception',
    technical: 'The URL path or query string contains sensitive authentication or transaction tokens (e.g. login, verify, account, billing, secure).',
    simple: 'The web address contains sensitive words like "login", "verify", or "account" trying to look like an official service.',
    whyItMatters: 'Phishing pages use these keywords to trick users into believing they are visiting an official bank, email, or account recovery portal.'
  },
  EXCESSIVE_SUBDOMAINS: {
    title: 'Excessive Subdomain Stacking',
    badge: 'Domain Structure',
    technical: 'The hostname contains 3 or more nested subdomain labels preceding the registered domain zone.',
    simple: 'The website address has unusually many dots and prefixes stacked together (e.g., login.verify.portal.account.example.com).',
    whyItMatters: 'Phishing kits stack familiar brand names in subdomains to deceive mobile and desktop users into trusting a fraudulent domain.'
  },
  SUSPICIOUS_PERCENT_ENCODING: {
    title: 'Obfuscated Percent-Encoding',
    badge: 'Evasion Technique',
    technical: 'The URL contains dense or consecutive percent-encoded hex sequences (%20, %2F, %3F, %25) designed to evade signature matching.',
    simple: 'The link contains hidden or scrambled characters (like %20 or %2F) that mask its real destination.',
    whyItMatters: 'Attackers scramble parts of the address so security scanners cannot easily read the malicious payload before you click it.'
  },
  EMBEDDED_AT_SYMBOL: {
    title: 'Embedded "@" Hostname Confusion',
    badge: 'RFC 3986 Exploitation',
    technical: 'The URL contains an "@" delimiter in the authority component, causing user-info authentication confusion per RFC 3986.',
    simple: 'The link includes an "@" symbol inside the address (e.g. http://google.com@evil-site.com).',
    whyItMatters: 'Browsers ignore everything before the "@" symbol and actually navigate to whatever follows it, creating a dangerous visual illusion.'
  },
  EXCESSIVE_URL_LENGTH: {
    title: 'Excessive URL Length',
    badge: 'Payload Correlate',
    technical: 'The total character count of the URL exceeds standard thresholds (>80 characters), frequently correlating with embedded payloads.',
    simple: 'The web address is unusually long and crowded with excessive text.',
    whyItMatters: 'Attackers create extremely long links to push the actual malicious domain off-screen on smartphones and compact browsers.'
  },
  EXCESSIVE_SPECIAL_CHARACTERS: {
    title: 'Excessive Special Characters',
    badge: 'Structural Anomaly',
    technical: 'High density of non-alphanumeric special characters across the URL structure.',
    simple: 'The link is cluttered with symbols like hyphens, underscores, slashes, and question marks.',
    whyItMatters: 'Abnormal symbol density often indicates automated phishing kit generation or obfuscated redirection parameters.'
  },
  SUSPICIOUS_HOSTNAME_STRUCTURE: {
    title: 'Suspicious Hostname Structure & Typosquatting',
    badge: 'Brand Mimicry',
    technical: 'Hostname contains multiple hyphens or unusually long label segments mimicking brand domain namespaces.',
    simple: 'The website name looks like a misspelling or variation of a well-known brand (e.g. paypal-security-update.com).',
    whyItMatters: 'Typosquatting and hyphenated lookalikes are designed to trick you into believing you are on a genuine brand website.'
  },
  RANDOM_FOREST_ML: {
    title: 'Random Forest ML Classifier',
    badge: 'Machine Learning',
    technical: 'An ensemble of 100 decision trees evaluating 18 lexical and structural URL dimensions trained on Tranco top legitimate sites and PhishTank/URLhaus feeds.',
    simple: 'Our AI model compares the link’s patterns against thousands of known safe and malicious websites.',
    whyItMatters: 'Machine learning spots subtle patterns and new emerging threats that simple rule checks might miss.'
  },
  VIRUSTOTAL_INTEL: {
    title: 'VirusTotal Threat Intelligence',
    badge: 'Global Telemetry',
    technical: 'Multi-vendor consensus telemetry queried via SHA-256 URL hash against 70+ global antivirus engines and security research labs.',
    simple: 'A worldwide network of security scanners that check whether this link has already been reported as dangerous.',
    whyItMatters: 'If global security vendors have already flagged this site, it is actively participating in known cyber attacks.'
  },
  RISK_FUSION: {
    title: 'Multi-Engine Risk Fusion',
    badge: 'Unified Risk Scoring',
    technical: 'Weighted composite normalization combining Heuristics (35%), Machine Learning (40%), and Threat Intelligence (25%) with dynamic weight renormalization.',
    simple: 'We combine all our security checks into a single overall risk score from 0 to 100.',
    whyItMatters: 'No single security tool catches everything; fusing multiple independent checks provides far more accurate and reliable protection.'
  }
};

export const DualTierExplainer = ({ conceptKey, fallbackTitle, buttonLabel = 'Explain This' }) => {
  const [isOpen, setIsOpen] = useState(false);

  const key = String(conceptKey || '').toUpperCase();
  const data = DUAL_TIER_DATABASE[key] || {
    title: fallbackTitle || conceptKey || 'Security Finding',
    badge: 'Security Signal',
    technical: `Forensic indicator "${conceptKey}" evaluated against ThreatLens detection models.`,
    simple: `ThreatLens detected an unusual pattern with this link related to "${conceptKey}".`,
    whyItMatters: 'Unusual patterns can indicate phishing, spoofing, or malicious deception attempts.'
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setIsOpen(true)}
        className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 transition-colors"
        title="View Technical & Plain-Language Explanation"
      >
        <BookOpen className="w-3 h-3" />
        <span>{buttonLabel}</span>
      </button>

      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
          <div className="relative w-full max-w-lg bg-cyber-card border border-cyber-border rounded-2xl p-6 shadow-2xl space-y-5">
            {/* Header */}
            <div className="flex items-start justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  {data.badge}
                </span>
                <h3 className="font-mono font-bold text-slate-100 text-base mt-1.5">
                  {data.title}
                </h3>
              </div>
              <button
                onClick={() => setIsOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* 3-Part Dual Tier Breakdown */}
            <div className="space-y-4">
              {/* Technical Explanation */}
              <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
                <div className="flex items-center space-x-1.5 text-xs font-mono text-cyan-400 font-semibold">
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Technical Forensic Explanation:</span>
                </div>
                <p className="text-xs text-slate-300 font-mono leading-relaxed">
                  {data.technical}
                </p>
              </div>

              {/* In Simple Words */}
              <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1">
                <div className="flex items-center space-x-1.5 text-xs font-mono text-emerald-400 font-semibold">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>In Simple Words:</span>
                </div>
                <p className="text-xs text-slate-200 font-sans leading-relaxed">
                  {data.simple}
                </p>
              </div>

              {/* Why It Matters */}
              <div className="p-3.5 rounded-xl bg-amber-500/5 border border-amber-500/20 space-y-1">
                <div className="flex items-center space-x-1.5 text-xs font-mono text-amber-300 font-semibold">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Why It Matters:</span>
                </div>
                <p className="text-xs text-amber-200/90 font-sans leading-relaxed">
                  {data.whyItMatters}
                </p>
              </div>
            </div>

            {/* Footer */}
            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={() => setIsOpen(false)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-semibold transition-colors"
              >
                Close Explanation
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
