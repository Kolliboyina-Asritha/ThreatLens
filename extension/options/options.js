// ThreatLens Options Script

console.log('[ThreatLens Options] Script loaded in context:', {
  url: typeof window !== 'undefined' ? window.location.href : null,
  protocol: typeof window !== 'undefined' ? window.location.protocol : null,
  isExtensionProtocol: typeof window !== 'undefined' && window.location.protocol === 'chrome-extension:',
  extensionId: (typeof chrome !== 'undefined' && chrome.runtime) ? chrome.runtime.id : null
});

// Safe DOM helper utilities to prevent null selector crashes
const safeGet = (idOrEl) => (typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl);

const safeSetText = (idOrEl, text) => {
  const el = safeGet(idOrEl);
  if (el) el.textContent = text;
};

const safeSetClass = (idOrEl, className) => {
  const el = safeGet(idOrEl);
  if (el) el.className = className;
};

const safeSetDisplay = (idOrEl, display) => {
  const el = safeGet(idOrEl);
  if (el && el.style) el.style.display = display;
};

const safeSetBg = (idOrEl, bg) => {
  const el = safeGet(idOrEl);
  if (el && el.style) el.style.background = bg;
};

const safeSetValue = (idOrEl, value) => {
  const el = safeGet(idOrEl);
  if (el) el.value = value;
};

const initOptionsPage = () => {
  const statusAlert = safeGet('statusAlert');
  const backendUrlInput = safeGet('backendUrl');
  const webDashboardUrlInput = safeGet('webDashboardUrl');
  const configForm = safeGet('configForm');
  const btnTestConn = safeGet('btnTestConn');
  const btnSignIn = safeGet('btnSignIn');
  const btnSignOut = safeGet('btnSignOut');

  const showStatus = (msg, isSuccess) => {
    if (!statusAlert) return;
    statusAlert.style.display = 'block';
    statusAlert.style.background = isSuccess ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)';
    statusAlert.style.border = isSuccess ? '1px solid #10b981' : '1px solid #ef4444';
    statusAlert.style.color = isSuccess ? '#10b981' : '#f87171';
    statusAlert.textContent = msg;
  };

  const showBackgroundServiceError = (msg) => {
    showStatus(msg, false);
  };

  // Diagnostic ping to background service worker
  console.log('[ThreatLens Options] PING_SEND_2026');
  chrome.runtime.sendMessage(
    { type: 'THREATLENS_PING' },
    (response) => {
      if (chrome.runtime.lastError) {
        console.error(
          '[ThreatLens Options] PING_ERROR_2026:',
          chrome.runtime.lastError.message
        );
        return;
      }

      console.log('[ThreatLens Options] PING_RESPONSE_2026:', response);
    }
  );

  const updateSessionUI = (state = {}) => {
    if (state.backendUrl && backendUrlInput) backendUrlInput.value = state.backendUrl;
    if (state.webDashboardUrl && webDashboardUrlInput) webDashboardUrlInput.value = state.webDashboardUrl;

    const isAuth = Boolean(state.authenticated ?? state.isAuthenticated);
    const email = state.user?.email || state.userEmail || '';
    const sessionStatus = state.sessionStatus || (isAuth ? 'AUTHENTICATED' : 'DISCONNECTED');
    const protectionMode = state.protectionMode || 'ASK_ME';

    if (isAuth && email) {
      safeSetClass('sessionBadge', 'session-badge badge-active mono');
      safeSetBg('sessionDot', '#10b981');
      safeSetText('sessionText', 'Authenticated');
      safeSetText('userEmailText', `Signed in as: ${email}`);
      safeSetText('sessionDetail', `Session active • Policy: ${protectionMode} • Automatic silent token renewal enabled.`);
      safeSetDisplay('btnSignIn', 'none');
      safeSetDisplay('btnSignOut', 'inline-block');
    } else if (sessionStatus === 'SESSION_EXPIRED') {
      safeSetClass('sessionBadge', 'session-badge badge-expired mono');
      safeSetBg('sessionDot', '#ef4444');
      safeSetText('sessionText', 'Session Expired');
      safeSetText('userEmailText', email ? `Session expired for ${email}` : 'Account session expired');
      safeSetText('sessionDetail', 'Your session has expired. Click below to sign in again.');
      safeSetDisplay('btnSignIn', 'inline-block');
      safeSetText('btnSignIn', 'Sign in with ThreatLens');
      safeSetDisplay('btnSignOut', 'inline-block');
    } else {
      safeSetClass('sessionBadge', 'session-badge badge-disconnected mono');
      safeSetBg('sessionDot', '#94a3b8');
      safeSetText('sessionText', 'Not Authenticated');
      safeSetText('userEmailText', 'No account linked');
      safeSetText('sessionDetail', 'Sign in to sync your personalized policies and allowlists.');
      safeSetDisplay('btnSignIn', 'inline-block');
      safeSetText('btnSignIn', 'Sign in with ThreatLens');
      safeSetDisplay('btnSignOut', 'none');
    }
  };

  const loadAuthState = () => {
    console.log('[ThreatLens Options] sending:', 'GET_AUTH_STATUS');
    chrome.runtime.sendMessage({ type: 'GET_AUTH_STATUS' }, (res) => {
      if (chrome.runtime.lastError) {
        console.error(
          'ThreatLens background service error:',
          chrome.runtime.lastError.message
        );
        chrome.storage.local.get(
          ['backendUrl', 'webDashboardUrl', 'authToken', 'userEmail', 'sessionStatus', 'protectionMode'],
          (items) => {
            updateSessionUI({
              backendUrl: items?.backendUrl,
              webDashboardUrl: items?.webDashboardUrl,
              authenticated: items?.sessionStatus === 'AUTHENTICATED' && !!items?.authToken,
              isAuthenticated: items?.sessionStatus === 'AUTHENTICATED' && !!items?.authToken,
              sessionStatus: items?.sessionStatus || 'DISCONNECTED',
              userEmail: items?.userEmail,
              user: items?.userEmail ? { email: items.userEmail } : null,
              protectionMode: items?.protectionMode || 'ASK_ME'
            });
          }
        );
        return;
      }

      if (!res) {
        showBackgroundServiceError('Background service returned no response.');
        return;
      }

      if (res.ok) {
        updateSessionUI(res);
      }
    });
  };

  // Initial load
  loadAuthState();

  // Listen for storage changes in real-time
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
      loadAuthState();
    }
  });

  // Sign In button
  if (btnSignIn) {
    btnSignIn.addEventListener('click', () => {
      btnSignIn.disabled = true;
      btnSignIn.textContent = 'Connecting...';
      console.log('[ThreatLens Options] sending:', 'START_SIGN_IN');
      chrome.runtime.sendMessage({ type: 'START_SIGN_IN' }, (res) => {
        btnSignIn.disabled = false;
        btnSignIn.textContent = 'Sign in with ThreatLens';

        if (chrome.runtime.lastError) {
          console.error(
            'ThreatLens background service error:',
            chrome.runtime.lastError.message
          );
          showBackgroundServiceError('Unable to communicate with ThreatLens background service.');
          return;
        }

        if (!res) {
          showBackgroundServiceError('Background service returned no response.');
          return;
        }

        if (!res.success && !res.ok) {
          showStatus(res.error || 'Failed to initiate sign in handoff.', false);
        } else {
          showStatus('Opening ThreatLens login page. Please sign in to connect your extension.', true);
        }
      });
    });
  }

  // Sign Out button
  if (btnSignOut) {
    btnSignOut.addEventListener('click', () => {
      btnSignOut.disabled = true;
      btnSignOut.textContent = 'Signing out...';
      console.log('[ThreatLens Options] sending:', 'SIGN_OUT');
      chrome.runtime.sendMessage({ type: 'SIGN_OUT' }, (res) => {
        btnSignOut.disabled = false;
        btnSignOut.textContent = 'Sign Out';

        if (chrome.runtime.lastError) {
          console.error(
            'ThreatLens background service error:',
            chrome.runtime.lastError.message
          );
          showBackgroundServiceError('Unable to communicate with ThreatLens background service.');
          return;
        }

        if (!res) {
          showBackgroundServiceError('Background service returned no response.');
          return;
        }

        if (res.success || res.ok) {
          showStatus('Signed out of ThreatLens extension.', true);
        } else {
          showStatus(res.error || 'Sign out encountered an issue.', false);
        }
        loadAuthState();
      });
    });
  }

  // Save Endpoint Configuration
  if (configForm) {
    configForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const backendUrl = backendUrlInput ? backendUrlInput.value.trim() || 'http://localhost:5000' : 'http://localhost:5000';
      const webDashboardUrl = webDashboardUrlInput ? webDashboardUrlInput.value.trim() || 'http://localhost:5173' : 'http://localhost:5173';

      chrome.storage.local.set({ backendUrl, webDashboardUrl }, () => {
        showStatus('Configuration saved successfully.', true);
      });
    });
  }

  // Test Connection
  if (btnTestConn) {
    btnTestConn.addEventListener('click', () => {
      btnTestConn.disabled = true;
      btnTestConn.textContent = 'Testing...';
      console.log('[ThreatLens Options] sending:', 'TEST_CONNECTION');
      chrome.runtime.sendMessage({ type: 'TEST_CONNECTION' }, (res) => {
        btnTestConn.disabled = false;
        btnTestConn.textContent = 'Test Connection';

        if (chrome.runtime.lastError) {
          console.error(
            'ThreatLens background service error:',
            chrome.runtime.lastError.message
          );
          showBackgroundServiceError('Unable to communicate with ThreatLens background service.');
          return;
        }

        if (!res) {
          showBackgroundServiceError('Background service returned no response.');
          return;
        }

        if (res.success || res.ok) {
          showStatus(res.message || 'ThreatLens connection and authentication verified.', true);
        } else {
          showStatus(res.message || res.error || 'Connection failed.', false);
        }
      });
    });
  }
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initOptionsPage);
} else {
  initOptionsPage();
}

