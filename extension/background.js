/**
 * ThreatLens AI — Background Service Worker (Manifest V3)
 * Provides real-time URL navigation interception, user policy enforcement,
 * and secure automated session management with silent token refresh.
 */

console.log('[ThreatLens] SW_BOOT_TEST_2026');

// ----------------------------------------------------
// 1. Internal Message Dispatcher (Options & Popup Pages)
// ----------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[ThreatLens] MESSAGE_RECEIVED_2026:', message?.type);

  if (!message || !message.type) {
    sendResponse({ ok: false, error: 'Invalid message payload' });
    return false;
  }

  // Diagnostic Ping Handler
  if (message.type === 'THREATLENS_PING') {
    console.log('[ThreatLens] PING_RESPONSE_2026');

    sendResponse({
      ok: true,
      service: 'ThreatLens background',
      version: '3.0.0'
    });

    return false;
  }

  // 1. GET_AUTH_STATUS
  if (message.type === 'GET_AUTH_STATUS' || message.type === 'GET_AUTH_STATE') {
    getSettings()
      .then((settings) => {
        const isAuthenticated = settings.sessionStatus === 'AUTHENTICATED' && !!settings.authToken;
        sendResponse({
          ok: true,
          authenticated: isAuthenticated,
          isAuthenticated: isAuthenticated,
          sessionStatus: settings.sessionStatus,
          user: isAuthenticated || settings.userEmail ? {
            email: settings.userEmail,
            name: settings.userName,
            id: settings.userId
          } : null,
          userEmail: settings.userEmail,
          userName: settings.userName,
          backendUrl: settings.backendUrl,
          webDashboardUrl: settings.webDashboardUrl,
          protectionMode: settings.protectionMode
        });
      })
      .catch((err) => {
        sendResponse({
          ok: false,
          authenticated: false,
          isAuthenticated: false,
          sessionStatus: 'DISCONNECTED',
          user: null,
          error: err?.message || 'Unable to get auth status'
        });
      });
    return true;
  }

  // 2. TEST_CONNECTION
  if (message.type === 'TEST_CONNECTION') {
    (async () => {
      try {
        const settings = await getSettings();
        if (!settings.authToken) {
          sendResponse({
            ok: false,
            success: false,
            status: 401,
            message: 'Not authenticated. Please sign in with ThreatLens first.'
          });
          return;
        }

        const res = await fetchWithAuth(`${settings.backendUrl}/api/protection/evaluate`, {
          method: 'POST',
          body: JSON.stringify({ url: 'https://example.com' })
        });

        if (res.ok) {
          sendResponse({
            ok: true,
            success: true,
            status: 200,
            message: `Connected to ThreatLens (${settings.userEmail || 'Authenticated User'}).`
          });
        } else if (res.status === 401) {
          sendResponse({
            ok: false,
            success: false,
            status: 401,
            message: 'Authentication session expired. Please sign in again.'
          });
        } else if (res.status === 403) {
          sendResponse({
            ok: false,
            success: false,
            status: 403,
            message: 'Access forbidden (403). Invalid credentials.'
          });
        } else {
          sendResponse({
            ok: false,
            success: false,
            status: res.status || 500,
            message: res.message || `Backend returned HTTP ${res.status}`
          });
        }
      } catch (err) {
        sendResponse({
          ok: false,
          success: false,
          status: 503,
          message: `Cannot connect to backend: ${err.message}`
        });
      }
    })();
    return true;
  }

  // 3. START_SIGN_IN
  if (message.type === 'START_SIGN_IN') {
    (async () => {
      try {
        const state = crypto.randomUUID();
        await new Promise((resolve) => chrome.storage.local.set({ authStateChallenge: state }, resolve));
        const settings = await getSettings();
        const authUrl = `${settings.webDashboardUrl}/login?extId=${chrome.runtime.id}&state=${state}`;
        chrome.tabs.create({ url: authUrl });
        sendResponse({ ok: true, success: true, authUrl });
      } catch (err) {
        sendResponse({ ok: false, success: false, error: err?.message || 'Failed to start sign in' });
      }
    })();
    return true;
  }

  // 4. SIGN_OUT
  if (message.type === 'SIGN_OUT') {
    (async () => {
      try {
        const settings = await getSettings();
        if (settings.refreshToken) {
          try {
            await fetch(`${settings.backendUrl}/api/auth/extension/logout`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ refreshToken: settings.refreshToken })
            });
          } catch {
            // Non-blocking
          }
        }
        await clearSession('DISCONNECTED');
        sendResponse({ ok: true, success: true });
      } catch (err) {
        sendResponse({ ok: false, success: false, error: err?.message || 'Sign out failed' });
      }
    })();
    return true;
  }

  // 5. EVALUATE_URL
  if (message.type === 'EVALUATE_URL') {
    evaluateUrlWithBackend(message.url)
      .then((res) => {
        sendResponse({ ok: true, ...res });
      })
      .catch((err) => {
        sendResponse({ ok: false, action: 'PROTECTION_UNAVAILABLE', error: err?.message });
      });
    return true;
  }

  // 6. RECORD_OVERRIDE
  if (message.type === 'RECORD_OVERRIDE') {
    const targetUrl = message.url;
    temporaryOverrides.set(targetUrl, Date.now() + OVERRIDE_TTL_MS);

    (async () => {
      try {
        const settings = await getSettings();
        if (settings.authToken) {
          try {
            await fetchWithAuth(`${settings.backendUrl}/api/protection/override`, {
              method: 'POST',
              body: JSON.stringify({
                url: targetUrl,
                userDecision: 'OVERRIDE',
                reason: message.reason || 'User bypassed warning in browser extension.'
              })
            });
          } catch (e) {
            console.warn('[ThreatLens Extension] Override logging error:', e);
          }
        }
        sendResponse({ ok: true, success: true, url: targetUrl });
      } catch (err) {
        sendResponse({ ok: false, success: false, error: err?.message, url: targetUrl });
      }
    })();
    return true;
  }

  // 7. ADD_ALLOWLIST
  if (message.type === 'ADD_ALLOWLIST') {
    (async () => {
      try {
        const settings = await getSettings();
        if (!settings.authToken) {
          sendResponse({ ok: false, success: false, error: 'No active session' });
          return;
        }
        const res = await fetchWithAuth(`${settings.backendUrl}/api/protection/allowlist`, {
          method: 'POST',
          body: JSON.stringify({
            value: message.value,
            type: message.entryType || 'URL'
          })
        });
        const json = await res.json();
        temporaryOverrides.set(message.value, Date.now() + OVERRIDE_TTL_MS);
        sendResponse({ ok: true, success: true, data: json });
      } catch (err) {
        sendResponse({ ok: false, success: false, error: err?.message });
      }
    })();
    return true;
  }

  sendResponse({ ok: false, error: `Unhandled message type: ${message?.type}` });
  return false;
});

console.log('[ThreatLens] ONMESSAGE_REGISTERED_2026');

// ----------------------------------------------------
// 2. External Message Listener (ThreatLens Web Dashboard Handoff)
// ----------------------------------------------------
chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
  console.log('[ThreatLens] EXTERNAL_MESSAGE_RECEIVED_2026');

  const origin = sender.origin || (sender.url ? new URL(sender.url).origin : '');
  const isTrustedOrigin =
    origin.includes('localhost:5173') ||
    origin.includes('127.0.0.1:5173') ||
    origin.includes('threatlens123.netlify.app') ||
    origin.endsWith('.netlify.app') ||
    origin.endsWith('.threatlens.io') ||
    origin === 'https://threatlens.io';

  if (!isTrustedOrigin) {
    console.warn('[ThreatLens] Untrusted external message origin:', origin);
    sendResponse({ success: false, error: 'Untrusted origin' });
    return false;
  }

  if (message?.type === 'THREATLENS_AUTH_CODE') {
    console.log('[ThreatLens] AUTH_CODE_EXTERNAL_RECEIVED_2026');
    const { authCode, state, backendUrl: payloadBackendUrl } = message;

    (async () => {
      try {
        const items = await new Promise((resolve) =>
          chrome.storage.local.get(['authStateChallenge', 'backendUrl', 'webDashboardUrl'], resolve)
        );
        const storedChallenge = items.authStateChallenge;
        
        let backendUrl = items.backendUrl;
        if (!backendUrl || backendUrl === 'http://localhost:5000') {
          if (origin.includes('netlify.app')) {
            backendUrl = 'https://threatlens-backend-3c3s.onrender.com';
          } else if (payloadBackendUrl) {
            backendUrl = payloadBackendUrl;
          } else {
            backendUrl = backendUrl || 'http://localhost:5000';
          }
        }

        if (!storedChallenge || storedChallenge !== state) {
          console.warn('[ThreatLens] State challenge mismatch or expired');
          sendResponse({ success: false, error: 'Invalid state challenge' });
          return;
        }

        console.log('[ThreatLens] AUTH_CODE_STATE_VALID_2026');

        const exchangeRes = await fetch(`${backendUrl}/api/auth/extension/exchange`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            authCode,
            extensionId: chrome.runtime.id,
            state
          })
        });

        if (!exchangeRes.ok) {
          const errData = await exchangeRes.json().catch(() => ({}));
          console.warn('[ThreatLens] Extension code exchange failed:', exchangeRes.status);
          sendResponse({ success: false, error: errData.message || 'Code exchange failed' });
          return;
        }

        console.log('[ThreatLens] AUTH_CODE_EXCHANGE_SUCCESS_2026');

        const exchangeJson = await exchangeRes.json();
        const { accessToken, refreshToken, user } = exchangeJson.data;

        await new Promise((resolve) =>
          chrome.storage.local.set(
            {
              authToken: accessToken,
              refreshToken,
              backendUrl: backendUrl,
              webDashboardUrl: origin.includes('netlify.app') ? 'https://threatlens123.netlify.app' : (items.webDashboardUrl || 'http://localhost:5173'),
              userEmail: user.email,
              userName: user.name,
              userId: user.id,
              sessionStatus: 'AUTHENTICATED',
              sessionUpdatedAt: Date.now(),
              authStateChallenge: null
            },
            resolve
          )
        );

        console.log('[ThreatLens] EXTENSION_SESSION_STORED_2026');
        sendResponse({ success: true, user: { email: user.email, name: user.name, id: user.id } });
      } catch (err) {
        console.error('[ThreatLens] External auth error:', err?.message);
        sendResponse({ success: false, error: err?.message || 'External auth failed' });
      }
    })();

    return true; // Async response
  }

  sendResponse({ success: false, error: 'Unknown external message' });
  return false;
});

console.log('[ThreatLens] EXTERNAL_LISTENER_REGISTERED_2026');

// ----------------------------------------------------
// 3. Navigation Interception Listener
// ----------------------------------------------------
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept main frame navigation
  if (details.frameId !== 0) return;
  if (isInternalUrl(details.url)) return;

  const targetUrl = details.url;
  const evaluation = await evaluateUrlWithBackend(targetUrl);

  if (evaluation.action === 'BLOCK') {
    setTabBadge(details.tabId, 'ERR', '#ef4444');
    const blockedUrl = chrome.runtime.getURL(
      `pages/blocked.html?url=${encodeURIComponent(targetUrl)}&score=${evaluation.riskScore}&level=${evaluation.riskLevel}&reasons=${encodeURIComponent(JSON.stringify(evaluation.reasons || []))}&indicators=${encodeURIComponent(JSON.stringify(evaluation.indicators || []))}`
    );
    chrome.tabs.update(details.tabId, { url: blockedUrl });
  } else if (evaluation.action === 'WARN') {
    setTabBadge(details.tabId, 'WARN', '#f59e0b');
    const warningUrl = chrome.runtime.getURL(
      `pages/warning.html?url=${encodeURIComponent(targetUrl)}&score=${evaluation.riskScore}&level=${evaluation.riskLevel}&reasons=${encodeURIComponent(JSON.stringify(evaluation.reasons || []))}&indicators=${encodeURIComponent(JSON.stringify(evaluation.indicators || []))}`
    );
    chrome.tabs.update(details.tabId, { url: warningUrl });
  } else if (evaluation.action === 'AUTH_REQUIRED' || evaluation.action === 'SESSION_EXPIRED') {
    setTabBadge(details.tabId, 'AUTH', '#64748b');
  } else if (evaluation.action === 'PROTECTION_UNAVAILABLE') {
    setTabBadge(details.tabId, 'OFF', '#64748b');
  } else {
    setTabBadge(details.tabId, 'OK', '#10b981');
  }
});

// ----------------------------------------------------
// 4. In-Memory Cache & State
// ----------------------------------------------------
const temporaryOverrides = new Map(); // url -> timestamp
const urlEvaluationCache = new Map(); // url -> { result, timestamp }

const OVERRIDE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const CACHE_TTL_MS = 2 * 60 * 1000;      // 2 minutes

// Shared atomic lock/promise for concurrent 401 refresh handling
let refreshPromise = null;

// Helpers
function isInternalUrl(url) {
  if (!url) return true;
  return (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:') ||
    url.startsWith('file://') ||
    url.startsWith('devtools://') ||
    url.includes('localhost:5000') ||
    url.includes('localhost:5173') ||
    url.includes('127.0.0.1:5000') ||
    url.includes('127.0.0.1:5173') ||
    url.includes('threatlens123.netlify.app') ||
    url.includes('threatlens-backend-3c3s.onrender.com') ||
    url.includes('threatlens.io')
  );
}

function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(
      [
        'backendUrl',
        'webDashboardUrl',
        'authToken',
        'refreshToken',
        'userEmail',
        'userName',
        'userId',
        'sessionStatus',
        'protectionMode'
      ],
      (items) => {
        resolve({
          backendUrl: items.backendUrl || 'https://threatlens-backend-3c3s.onrender.com',
          webDashboardUrl: items.webDashboardUrl || 'https://threatlens123.netlify.app',
          authToken: items.authToken || '',
          refreshToken: items.refreshToken || '',
          userEmail: items.userEmail || '',
          userName: items.userName || '',
          userId: items.userId || '',
          sessionStatus: items.sessionStatus || (items.authToken ? 'AUTHENTICATED' : 'DISCONNECTED'),
          protectionMode: items.protectionMode || 'ASK_ME'
        });
      }
    );
  });
}

function clearSession(status = 'DISCONNECTED') {
  return new Promise((resolve) => {
    chrome.storage.local.set(
      {
        authToken: '',
        refreshToken: '',
        userEmail: '',
        userName: '',
        userId: '',
        sessionStatus: status,
        authStateChallenge: null
      },
      resolve
    );
  });
}

function setTabBadge(tabId, text, color) {
  if (!tabId || tabId < 0) return;
  try {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch {
    // Ignore if tab closed
  }
}

/**
 * Authenticated Fetch wrapper with automatic silent token refresh on 401
 * and shared refresh locking for concurrent requests.
 */
async function fetchWithAuth(url, options = {}) {
  const settings = await getSettings();
  if (!settings.authToken) {
    return {
      status: 401,
      ok: false,
      error: 'AUTH_REQUIRED',
      message: 'ThreatLens extension is not authenticated. Please sign in.'
    };
  }

  const makeRequest = async (token) => {
    const headers = new Headers(options.headers || {});
    headers.set('Authorization', `Bearer ${token}`);
    headers.set('x-threatlens-source', 'extension');
    if (!headers.has('Content-Type') && options.body) {
      headers.set('Content-Type', 'application/json');
    }
    return fetch(url, { ...options, headers });
  };

  try {
    let response = await makeRequest(settings.authToken);

    // If access token expired (HTTP 401), trigger silent auto-refresh
    if (response.status === 401) {
      if (!refreshPromise) {
        refreshPromise = (async () => {
          const currentSettings = await getSettings();
          if (!currentSettings.refreshToken) {
            await clearSession('SESSION_EXPIRED');
            return null;
          }

          try {
            const refreshEndpoint = `${currentSettings.backendUrl}/api/auth/extension/refresh`;
            const refreshRes = await fetch(refreshEndpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                refreshToken: currentSettings.refreshToken,
                extensionId: chrome.runtime.id
              })
            });

            if (!refreshRes.ok) {
              await clearSession('SESSION_EXPIRED');
              return null;
            }

            const refreshJson = await refreshRes.json();
            const newAccessToken = refreshJson.data?.accessToken;
            const newRefreshToken = refreshJson.data?.refreshToken || currentSettings.refreshToken;

            if (newAccessToken) {
              await chrome.storage.local.set({
                authToken: newAccessToken,
                refreshToken: newRefreshToken,
                sessionStatus: 'AUTHENTICATED'
              });
              return newAccessToken;
            } else {
              await clearSession('SESSION_EXPIRED');
              return null;
            }
          } catch (refreshErr) {
            console.warn('[ThreatLens Extension] Token refresh network error:', refreshErr);
            return null;
          } finally {
            refreshPromise = null;
          }
        })();
      }

      const refreshedToken = await refreshPromise;
      if (refreshedToken) {
        // Retry original request exactly once with new token
        response = await makeRequest(refreshedToken);
      } else {
        return {
          status: 401,
          ok: false,
          error: 'SESSION_EXPIRED',
          message: 'ThreatLens session has expired. Please sign in again.'
        };
      }
    }

    return response;
  } catch (err) {
    console.warn('[ThreatLens Extension] Network error during authenticated fetch:', err);
    return {
      status: 503,
      ok: false,
      error: 'PROTECTION_UNAVAILABLE',
      message: 'ThreatLens backend service is currently unreachable.'
    };
  }
}

/**
 * Evaluates target URL with ThreatLens API backend
 */
async function evaluateUrlWithBackend(targetUrl) {
  // 1. Check temporary local override
  const now = Date.now();
  if (temporaryOverrides.has(targetUrl)) {
    const expiresAt = temporaryOverrides.get(targetUrl);
    if (now < expiresAt) {
      return { action: 'ALLOW', overridden: true };
    }
    temporaryOverrides.delete(targetUrl);
  }

  // 2. Check recent cache
  if (urlEvaluationCache.has(targetUrl)) {
    const cached = urlEvaluationCache.get(targetUrl);
    if (now - cached.timestamp < CACHE_TTL_MS) {
      return cached.result;
    }
  }

  const settings = await getSettings();
  if (!settings.authToken) {
    return { action: 'AUTH_REQUIRED', error: 'Authentication required' };
  }

  try {
    const endpoint = `${settings.backendUrl}/api/protection/evaluate`;
    const response = await fetchWithAuth(endpoint, {
      method: 'POST',
      body: JSON.stringify({ url: targetUrl })
    });

    if (!response.ok) {
      if (response.error === 'AUTH_REQUIRED' || response.error === 'SESSION_EXPIRED') {
        return { action: response.error, error: response.message };
      }
      return { action: 'PROTECTION_UNAVAILABLE', error: 'Service unavailable' };
    }

    const json = await response.json();
    const data = json.data;

    const result = {
      action: data.action || 'ALLOW',
      recommendation: data.recommendation || 'ALLOW',
      riskScore: data.riskScore ?? 0,
      riskLevel: data.riskLevel || 'SAFE',
      reasons: data.reasons || [],
      indicators: data.indicators || [],
      policy: data.policy || 'ASK_ME',
      url: targetUrl
    };

    urlEvaluationCache.set(targetUrl, { result, timestamp: now });
    return result;
  } catch (err) {
    console.warn('[ThreatLens Extension] Evaluation error:', err);
    return { action: 'PROTECTION_UNAVAILABLE', error: err.message };
  }
}


