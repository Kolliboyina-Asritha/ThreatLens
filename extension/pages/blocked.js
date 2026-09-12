import { getExplanationForIndicator } from '../shared/explainerData.js';

const urlParams = new URLSearchParams(window.location.search);
const targetUrl = urlParams.get('url') || '';
const score = urlParams.get('score') || '85';
const level = urlParams.get('level') || 'HIGH_RISK';

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

document.getElementById('btnDashboard').addEventListener('click', () => {
  window.open('http://localhost:5173/protection', '_blank');
});

document.getElementById('btnOverride').addEventListener('click', () => {
  if (confirm('Warning: You are bypassing high-risk security protection. Proceed anyway?')) {
    chrome.runtime.sendMessage(
      {
        type: 'RECORD_OVERRIDE',
        url: targetUrl,
        reason: 'User explicitly overrode high-risk block.'
      },
      (res) => {
        if (chrome.runtime.lastError) {
          console.error('ThreatLens blocked page message failed:', chrome.runtime.lastError.message);
        }
        window.location.href = targetUrl;
      }
    );
  }
});
