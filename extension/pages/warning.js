import { getExplanationForIndicator } from '../shared/explainerData.js';

const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url') || '';
const score = urlParams.get('score') || '45';
const level = urlParams.get('level') || 'SUSPICIOUS';

let reasons = [];
try {
  reasons = JSON.parse(urlParams.get('reasons') || '[]');
} catch {
  reasons = [];
}

let indicators = [];
try {
  indicators = JSON.parse(urlParams.get('indicators') || '[]');
} catch {
  indicators = [];
}

// Populate DOM
document.getElementById('targetUrl').textContent = targetUrl || 'Unknown URL';
document.getElementById('riskScore').textContent = `${score}/100`;
document.getElementById('riskLevel').textContent = level;

if (indicators.length > 0) {
  const firstInd = indicators[0];
  const info = getExplanationForIndicator(firstInd.type);
  document.getElementById('explanationSimple').textContent = info.simple;
  document.getElementById('explanationTechnical').textContent = info.technical;
} else if (reasons.length > 0) {
  document.getElementById('explanationSimple').textContent = reasons[0];
}

// Action Handlers
document.getElementById('btnGoBack').addEventListener('click', () => {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = 'chrome://newtab';
  }
});

document.getElementById('btnOverride').addEventListener('click', () => {
  chrome.runtime.sendMessage(
    {
      type: 'RECORD_OVERRIDE',
      url: targetUrl,
      reason: 'User accepted risk on warning screen.'
    },
    (res) => {
      if (chrome.runtime.lastError) {
        console.error('ThreatLens warning page message failed:', chrome.runtime.lastError.message);
      }
      window.location.href = targetUrl;
    }
  );
});

document.getElementById('btnAllowlist').addEventListener('click', () => {
  chrome.runtime.sendMessage(
    {
      type: 'ADD_ALLOWLIST',
      value: targetUrl,
      entryType: 'URL'
    },
    (res) => {
      if (chrome.runtime.lastError) {
        console.error('ThreatLens warning page message failed:', chrome.runtime.lastError.message);
        window.location.href = targetUrl;
        return;
      }
      if (res?.success) {
        window.location.href = targetUrl;
      } else {
        alert('Could not update allowlist. Proceeding via temporary override.');
        window.location.href = targetUrl;
      }
    }
  );
});
