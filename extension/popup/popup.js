// ThreatLens Extension Popup Script

const safeGetEl = (id) => document.getElementById(id);

const initPopup = async () => {
  const currentTabUrlEl = safeGetEl('currentTabUrl');
  const currentStatusEl = safeGetEl('currentStatus');
  const badgeModeEl = safeGetEl('badgeMode');
  const btnScanEl = safeGetEl('btnScanCurrentTab');
  const connDotEl = safeGetEl('connDot');
  const userAccountTextEl = safeGetEl('userAccountText');
  const authActionLinkEl = safeGetEl('authActionLink');
  const authCtaBoxEl = safeGetEl('authCtaBox');
  const btnPopupSignInEl = safeGetEl('btnPopupSignIn');
  const protectionStatusTextEl = safeGetEl('protectionStatusText');
  const riskScoreContainer = safeGetEl('riskScoreContainer');
  const riskScoreValue = safeGetEl('riskScoreValue');

  let currentAuthState = null;

  const updatePopupAuthUI = (state) => {
    currentAuthState = state;
    if (state.protectionMode && badgeModeEl) {
      badgeModeEl.textContent = state.protectionMode;
    }

    const isAuth = Boolean(state.authenticated ?? state.isAuthenticated);
    const email = state.user?.email || state.userEmail || '';

    if (isAuth && email) {
      if (connDotEl) connDotEl.className = 'status-dot status-active';
      if (userAccountTextEl) {
        userAccountTextEl.textContent = email;
        userAccountTextEl.style.color = '#34d399';
      }
      if (authActionLinkEl) {
        authActionLinkEl.textContent = 'Sign Out';
        authActionLinkEl.style.color = '#94a3b8';
      }
      if (authCtaBoxEl) authCtaBoxEl.style.display = 'none';
      if (protectionStatusTextEl) protectionStatusTextEl.textContent = 'Protection: Active';
    } else if (state.sessionStatus === 'SESSION_EXPIRED') {
      if (connDotEl) connDotEl.className = 'status-dot status-offline';
      if (userAccountTextEl) {
        userAccountTextEl.textContent = 'Session Expired';
        userAccountTextEl.style.color = '#f87171';
      }
      if (authActionLinkEl) {
        authActionLinkEl.textContent = 'Sign In';
        authActionLinkEl.style.color = '#38bdf8';
      }
      if (authCtaBoxEl) authCtaBoxEl.style.display = 'block';
      if (protectionStatusTextEl) protectionStatusTextEl.textContent = 'Session Expired';
    } else {
      if (connDotEl) connDotEl.className = 'status-dot status-idle';
      if (userAccountTextEl) {
        userAccountTextEl.textContent = 'Not Signed In';
        userAccountTextEl.style.color = '#94a3b8';
      }
      if (authActionLinkEl) {
        authActionLinkEl.textContent = 'Sign In';
        authActionLinkEl.style.color = '#38bdf8';
      }
      if (authCtaBoxEl) authCtaBoxEl.style.display = 'block';
      if (protectionStatusTextEl) protectionStatusTextEl.textContent = 'Sign In Required';
    }
  };

  const loadAuthState = () => {
    chrome.runtime.sendMessage({ type: 'GET_AUTH_STATUS' }, (res) => {
      if (chrome.runtime.lastError) {
        console.error('ThreatLens popup message failed:', chrome.runtime.lastError.message);
        chrome.storage.local.get(
          ['backendUrl', 'webDashboardUrl', 'authToken', 'userEmail', 'sessionStatus', 'protectionMode'],
          (items) => {
            updatePopupAuthUI({
              backendUrl: items.backendUrl,
              webDashboardUrl: items.webDashboardUrl,
              authenticated: items.sessionStatus === 'AUTHENTICATED' && !!items.authToken,
              isAuthenticated: items.sessionStatus === 'AUTHENTICATED' && !!items.authToken,
              sessionStatus: items.sessionStatus || 'DISCONNECTED',
              userEmail: items.userEmail,
              user: items.userEmail ? { email: items.userEmail } : null,
              protectionMode: items.protectionMode || 'ASK_ME'
            });
          }
        );
        return;
      }
      if (res) {
        updatePopupAuthUI(res);
      }
    });
  };

  loadAuthState();

  // Listen for storage changes in real-time
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
      loadAuthState();
    }
  });

  // Handle Auth Action Link (Sign In / Sign Out)
  if (authActionLinkEl) {
    authActionLinkEl.addEventListener('click', () => {
      if (currentAuthState?.isAuthenticated || currentAuthState?.authenticated) {
        chrome.runtime.sendMessage({ type: 'SIGN_OUT' }, (res) => {
          if (chrome.runtime.lastError) {
            console.error('ThreatLens popup message failed:', chrome.runtime.lastError.message);
            return;
          }
          loadAuthState();
        });
      } else {
        chrome.runtime.sendMessage({ type: 'START_SIGN_IN' }, (res) => {
          if (chrome.runtime.lastError) {
            console.error('ThreatLens popup message failed:', chrome.runtime.lastError.message);
          }
        });
      }
    });
  }

  if (btnPopupSignInEl) {
    btnPopupSignInEl.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'START_SIGN_IN' }, (res) => {
        if (chrome.runtime.lastError) {
          console.error('ThreatLens popup message failed:', chrome.runtime.lastError.message);
        }
      });
    });
  }

  // Query current tab
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    const activeTab = tabs[0];

    if (activeTab && activeTab.url) {
      if (currentTabUrlEl) currentTabUrlEl.textContent = activeTab.url;

      if (activeTab.url.startsWith('chrome://') || activeTab.url.startsWith('about:') || activeTab.url.startsWith('edge://')) {
        if (currentStatusEl) {
          currentStatusEl.textContent = 'INTERNAL (SAFE)';
          currentStatusEl.style.color = '#10b981';
        }
        if (btnScanEl) btnScanEl.disabled = true;
      } else {
        if (currentStatusEl) currentStatusEl.textContent = 'READY TO SCAN';
      }
    }

    // Scan current tab on click
    if (btnScanEl) {
      btnScanEl.addEventListener('click', async () => {
        if (!activeTab || !activeTab.url) return;

        btnScanEl.disabled = true;
        btnScanEl.textContent = 'Analyzing URL...';
        if (currentStatusEl) currentStatusEl.textContent = 'ANALYZING...';

        chrome.runtime.sendMessage(
          { type: 'EVALUATE_URL', url: activeTab.url },
          (response) => {
            btnScanEl.disabled = false;
            btnScanEl.textContent = 'Scan Current Webpage';

            if (chrome.runtime.lastError) {
              console.error('ThreatLens popup message failed:', chrome.runtime.lastError.message);
              if (currentStatusEl) {
                currentStatusEl.textContent = 'SERVICE ERROR';
                currentStatusEl.style.color = '#ef4444';
              }
              return;
            }

            if (response && response.riskScore !== undefined) {
              if (riskScoreContainer) riskScoreContainer.style.display = 'block';
              if (riskScoreValue) riskScoreValue.textContent = `${response.riskScore}/100 (${response.riskLevel})`;

              if (response.action === 'BLOCK') {
                if (currentStatusEl) {
                  currentStatusEl.textContent = 'BLOCKED';
                  currentStatusEl.style.color = '#ef4444';
                }
                if (riskScoreValue) riskScoreValue.style.color = '#ef4444';
              } else if (response.action === 'WARN') {
                if (currentStatusEl) {
                  currentStatusEl.textContent = 'SUSPICIOUS';
                  currentStatusEl.style.color = '#f59e0b';
                }
                if (riskScoreValue) riskScoreValue.style.color = '#f59e0b';
              } else {
                if (currentStatusEl) {
                  currentStatusEl.textContent = 'SAFE';
                  currentStatusEl.style.color = '#10b981';
                }
                if (riskScoreValue) riskScoreValue.style.color = '#10b981';
              }
            } else if (response?.action === 'AUTH_REQUIRED' || response?.action === 'SESSION_EXPIRED') {
              if (currentStatusEl) {
                currentStatusEl.textContent = 'SIGN IN REQUIRED';
                currentStatusEl.style.color = '#f59e0b';
              }
              loadAuthState();
            } else {
              if (currentStatusEl) {
                currentStatusEl.textContent = 'OFFLINE / UNREACHABLE';
                currentStatusEl.style.color = '#94a3b8';
              }
            }
          }
        );
      });
    }
  } catch (err) {
    console.warn('[ThreatLens] Popup tab query error:', err);
  }

  const linkOptions = safeGetEl('linkOptions');
  if (linkOptions) {
    linkOptions.addEventListener('click', (e) => {
      e.preventDefault();
      chrome.runtime.openOptionsPage();
    });
  }

  const linkDashboard = safeGetEl('linkDashboard');
  if (linkDashboard) {
    linkDashboard.addEventListener('click', (e) => {
      e.preventDefault();
      chrome.runtime.sendMessage({ type: 'GET_AUTH_STATUS' }, (settings) => {
        if (chrome.runtime.lastError) {
          console.error('ThreatLens popup message failed:', chrome.runtime.lastError.message);
          window.open('http://localhost:5173/protection', '_blank');
          return;
        }
        const url = settings?.webDashboardUrl || 'http://localhost:5173';
        window.open(`${url}/protection`, '_blank');
      });
    });
  }
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initPopup);
} else {
  initPopup();
}
