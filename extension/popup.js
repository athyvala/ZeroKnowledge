// Updated extension popup script with account-based session sharing
document.addEventListener('DOMContentLoaded', async () => {
  const loginSection = document.getElementById('loginSection');
  const mainSection = document.getElementById('mainSection');
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const registerBtn = document.getElementById('registerBtn');
  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const userInfo = document.getElementById('userInfo');
  const saveSessionBtn = document.getElementById('saveSessionBtn');
  const loadSessionBtn = document.getElementById('loadSessionBtn');
  
  const sessionsDropdown = document.getElementById('sessionsDropdown');
  const deleteSessionBtn = document.getElementById('deleteSessionBtn');
  const status = document.getElementById('status');
  const domainEl = document.getElementById('currentDomain');

  // Share session elements
  const shareSessionBtn = document.getElementById('shareSessionBtn');
  const shareModal = document.getElementById('shareModal');
  const shareEmailInput = document.getElementById('shareEmail');
  const confirmShareBtn = document.getElementById('confirmShareBtn');
  const cancelShareBtn = document.getElementById('cancelShareBtn');

  // Shared sessions elements
  const sharedSessionsBtn = document.getElementById('sharedSessionsBtn');
  const sharedSessionsModal = document.getElementById('sharedSessionsModal');
  const sharedSessionsList = document.getElementById('sharedSessionsList');
  const closeSharedModalBtn = document.getElementById('closeSharedModalBtn');

  // Manage my shares elements
  const manageMySharesBtn = document.getElementById('manageMySharesBtn');
  const manageMySharesModal = document.getElementById('manageMySharesModal');
  const mySharesList = document.getElementById('mySharesList');
  const closeManageMySharesBtn = document.getElementById('closeManageMySharesBtn');

  // Access request elements
  const requestAccessBtn = document.getElementById('requestAccessBtn');
  const requestAccessModal = document.getElementById('requestAccessModal');
  const requestDomainInput = document.getElementById('requestDomain');
  const requestMessageInput = document.getElementById('requestMessage');
  const confirmRequestBtn = document.getElementById('confirmRequestBtn');
  const cancelRequestBtn = document.getElementById('cancelRequestBtn');

  // View requests elements
  const viewRequestsBtn = document.getElementById('viewRequestsBtn');
  const viewRequestsModal = document.getElementById('viewRequestsModal');
  const viewRequestsList = document.getElementById('viewRequestsList');
  const closeViewRequestsBtn = document.getElementById('closeViewRequestsBtn');

  // Manage requests elements
  const manageRequestsBtn = document.getElementById('manageRequestsBtn');
  const manageRequestsModal = document.getElementById('manageRequestsModal');
  const manageRequestsList = document.getElementById('manageRequestsList');
  const closeManageRequestsBtn = document.getElementById('closeManageRequestsBtn');

  // Friends elements
  const friendsBtn = document.getElementById('friendsBtn');
  const friendsModal = document.getElementById('friendsModal');
  const friendsList = document.getElementById('friendsList');
  const closeFriendsBtn = document.getElementById('closeFriendsBtn');

  // Add friend elements
  const addFriendBtn = document.getElementById('addFriendBtn');
  const addFriendModal = document.getElementById('addFriendModal');
  const friendEmailInput = document.getElementById('friendEmail');
  const friendRequestMessageInput = document.getElementById('friendRequestMessage');
  const confirmAddFriendBtn = document.getElementById('confirmAddFriendBtn');
  const cancelAddFriendBtn = document.getElementById('cancelAddFriendBtn');

  // Friend requests elements
  const friendRequestsBtn = document.getElementById('friendRequestsBtn');
  const friendRequestsModal = document.getElementById('friendRequestsModal');
  const incomingFriendRequestsTab = document.getElementById('incomingFriendRequestsTab');
  const outgoingFriendRequestsTab = document.getElementById('outgoingFriendRequestsTab');
  const incomingFriendRequestsList = document.getElementById('incomingFriendRequestsList');
  const outgoingFriendRequestsList = document.getElementById('outgoingFriendRequestsList');
  const closeFriendRequestsBtn = document.getElementById('closeFriendRequestsBtn');

  // Request access from friends elements
  const requestAccessFromFriendsModal = document.getElementById('requestAccessFromFriendsModal');
  const requestFromFriendsDomainInput = document.getElementById('requestFromFriendsDomain');
  const requestFromFriendsMessageInput = document.getElementById('requestFromFriendsMessage');
  const friendsWithSessionsList = document.getElementById('friendsWithSessionsList');
  const confirmRequestFromFriendsBtn = document.getElementById('confirmRequestFromFriendsBtn');
  const cancelRequestFromFriendsBtn = document.getElementById('cancelRequestFromFriendsBtn');
  const closeRequestAccessFromFriendsBtn = document.getElementById('closeRequestAccessFromFriendsBtn');

  // Expiration and active session elements
  const activeSessionDiv = document.getElementById('activeSession');
  const sessionDomainEl = document.getElementById('sessionDomain');
  const sessionTimerEl = document.getElementById('sessionTimer');
  const timerProgressBar = document.getElementById('timerProgressBar');
  const clearSessionBtn = document.getElementById('clearSessionBtn');

  const API_BASE = 'http://localhost:3000/api'; // Replace with your server URL
  let currentTab = null;
  let currentDomain = '';
  let currentUser = null;
  let timerInterval = null; // For active session countdown

  // Initialize
  await init();

  // Check server health and display feature status
  async function checkServerHealth() {
    try {
      const response = await fetch(`${API_BASE}/health`);
      const health = await response.json();
      
      // Display server status
      const serverStatus = document.getElementById('serverStatus');
      if (serverStatus) {
        serverStatus.textContent = `Server: ${health.status}`;
        if (health.features?.expiration) {
          serverStatus.textContent += ' | Auto-expiration: ✓';
          serverStatus.style.color = '#28a745';
        } else {
          serverStatus.textContent += ' | Auto-expiration: ⚠️ (migration needed)';
          serverStatus.style.color = '#ffc107';
        }
      }
      
      return health.features;
    } catch (error) {
      console.error('Failed to check server health:', error);
      const serverStatus = document.getElementById('serverStatus');
      if (serverStatus) {
        serverStatus.textContent = 'Server: Disconnected';
        serverStatus.style.color = '#dc3545';
      }
      return { expiration: false };
    }
  }

  async function init() {
    // Check server health first
    await checkServerHealth();
    
    // Get current tab and domain
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      currentTab = tabs[0];
      const url = new URL(currentTab.url);
      currentDomain = url.hostname;
      domainEl.textContent = currentDomain;
    } catch (error) {
      showStatus('Error getting current tab', 'error');
      return;
    }

    // Check if user is already logged in
    const userData = await getStoredUser();
    if (userData) {
      currentUser = userData;
      showMainSection();
      await loadUserSessions();
    } else {
      showLoginSection();
    }

    // Check for active imported sessions (expiration feature)
    await checkActiveSession();
  }

  // Storage helpers
  async function storeUser(userData) {
    await chrome.storage.local.set({ user: userData });
  }

  async function getStoredUser() {
    const result = await chrome.storage.local.get(['user']);
    return result.user;
  }

  async function clearStoredUser() {
    await chrome.storage.local.remove(['user']);
  }

  // UI helpers
  function showLoginSection() {
    loginSection.style.display = 'block';
    mainSection.style.display = 'none';
  }

  function showMainSection() {
    loginSection.style.display = 'none';
    mainSection.style.display = 'block';
    userInfo.textContent = `Logged in as: ${currentUser.email}`;
  }

  // Expiration and Active Session Management
  async function checkActiveSession() {
    const result = await chrome.storage.local.get('activeSession');
    
    if (result.activeSession) {
      const session = result.activeSession;
      const now = Date.now();
      
      if (now < session.autoLogoutTime) {
        // Session is still active, but check if it's been revoked on the server
        if (session.isSharedSession && currentUser) {
          try {
            // Check if the shared session is still accessible
            const response = await fetch(`${API_BASE}/sessions/shared/${session.sessionId || 'check'}`, {
              headers: {
                'Authorization': `Bearer ${currentUser.token}`
              }
            });
            
            if (!response.ok) {
              // Session no longer accessible (likely revoked)
              await clearImportedSession('revoked');
              return;
            }
          } catch (error) {
            console.log('Could not check session status:', error);
            // Continue with normal flow if we can't check
          }
        }
        
        // Session is still active
        sessionDomainEl.textContent = session.domain;
        activeSessionDiv.style.display = 'block';
        
        // Update timer
        updateSessionTimer(session.autoLogoutTime);
        
        // Set interval to update timer and periodically check revocation status
        if (timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(async () => {
          updateSessionTimer(session.autoLogoutTime);
          
          // Check revocation status every 30 seconds for shared sessions
          if (session.isSharedSession && currentUser && Date.now() % 30000 < 1000) {
            try {
              const response = await fetch(`${API_BASE}/sessions/shared/${session.sessionId || 'check'}`, {
                headers: {
                  'Authorization': `Bearer ${currentUser.token}`
                }
              });
              
              if (!response.ok) {
                await clearImportedSession('revoked');
                return;
              }
            } catch (error) {
              // Ignore check errors
            }
          }
        }, 1000);
      } else {
        // Session expired, clean up
        await clearImportedSession();
      }
    } else {
      activeSessionDiv.style.display = 'none';
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
    }
  }

  function updateSessionTimer(logoutTime) {
    const now = Date.now();
    const remaining = logoutTime - now;
    
    if (remaining <= 0) {
      sessionTimerEl.textContent = 'Expiring...';
      sessionTimerEl.style.color = '#dc3545';
      sessionTimerEl.style.fontWeight = 'bold';
      if (timerProgressBar) timerProgressBar.style.width = '0%';
      clearImportedSession();
      return;
    }
    
    const hours = Math.floor(remaining / (60 * 60 * 1000));
    const minutes = Math.floor((remaining % (60 * 60 * 1000)) / (60 * 1000));
    const seconds = Math.floor((remaining % (60 * 1000)) / 1000);
    
    let timeStr = '';
    if (hours > 0) timeStr += `${hours}h `;
    if (minutes > 0 || hours > 0) timeStr += `${minutes}m `;
    timeStr += `${seconds}s`;
    
    // Update progress bar
    const result = chrome.storage.local.get('activeSession').then((result) => {
      if (result.activeSession && result.activeSession.originalExpiration) {
        const totalDuration = result.activeSession.originalExpiration - result.activeSession.importTime;
        const elapsed = now - result.activeSession.importTime;
        const progressPercent = Math.max(0, Math.min(100, (elapsed / totalDuration) * 100));
        if (timerProgressBar) {
          timerProgressBar.style.width = `${100 - progressPercent}%`;
        }
      }
    });
    
    // Color-code based on time remaining
    const totalSeconds = Math.floor(remaining / 1000);
    if (totalSeconds <= 60) {
      // Less than 1 minute - red and blinking
      sessionTimerEl.style.color = '#dc3545';
      sessionTimerEl.style.fontWeight = 'bold';
      sessionTimerEl.style.animation = 'blink 1s infinite';
    } else if (totalSeconds <= 300) {
      // Less than 5 minutes - orange
      sessionTimerEl.style.color = '#fd7e14';
      sessionTimerEl.style.fontWeight = 'bold';
      sessionTimerEl.style.animation = 'none';
    } else {
      // More than 5 minutes - normal red
      sessionTimerEl.style.color = '#dc3545';
      sessionTimerEl.style.fontWeight = 'bold';
      sessionTimerEl.style.animation = 'none';
    }
    
    sessionTimerEl.textContent = timeStr;
  }

  async function clearImportedSession(reason = 'expired') {
    const result = await chrome.storage.local.get('activeSession');
    
    if (result.activeSession) {
      const session = result.activeSession;
      
      const reasonMessage = reason === 'revoked' ? 'Session access revoked by owner' : 'Clearing imported session...';
      showStatus(reasonMessage, 'info');
      
      // Delete all imported cookies via background script
      for (const cookie of session.cookies) {
        try {
          let cookieDomain = cookie.domain;
          if (cookieDomain.startsWith('.')) {
            cookieDomain = cookieDomain.substring(1);
          }
          
          const protocol = cookie.secure ? 'https://' : 'http://';
          const cookieUrl = protocol + cookieDomain + cookie.path;
          
          await chrome.cookies.remove({
            url: cookieUrl,
            name: cookie.name
          });
        } catch (error) {
          console.error('Failed to remove cookie:', cookie.name, error);
        }
      }
      
      // Clear storage and alarm
      await chrome.storage.local.remove('activeSession');
      
      // Clear alarm via background script
      try {
        chrome.runtime.sendMessage({ action: 'clearAutoLogoutAlarm' });
      } catch (error) {
        console.error('Error clearing alarm:', error);
      }
      
      // Hide active session indicator
      activeSessionDiv.style.display = 'none';
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
      
      const finalMessage = reason === 'revoked' 
        ? 'Session access revoked - you have been logged out' 
        : 'Session cleared - you have been logged out';
      showStatus(finalMessage, reason === 'revoked' ? 'warning' : 'success');
    }
  }

  function getExpirationMinutes(modalPrefix = '') {
    const selected = document.querySelector(`input[name="${modalPrefix}expiration"]:checked`) || 
                    document.querySelector(`input[name="${modalPrefix}Expiration"]:checked`);
    if (!selected) return 60; // Default to 1 hour
    
    if (selected.value === 'custom') {
      const valueInput = document.getElementById(`${modalPrefix}CustomValue`) || 
                        document.getElementById(`${modalPrefix}customValue`);
      const unitSelect = document.getElementById(`${modalPrefix}CustomUnit`) || 
                        document.getElementById(`${modalPrefix}customUnit`);
      
      if (!valueInput || !unitSelect) return 60;
      
      const value = parseInt(valueInput.value);
      const unit = unitSelect.value;
      
      switch(unit) {
        case 'hours':
          return value * 60;
        case 'days':
          return value * 60 * 24;
        default: // minutes
          return value;
      }
    }
    return parseInt(selected.value);
  }

  // Authentication
  loginBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    const password = passwordInput.value.trim();
    
    if (!email || !password) {
      showStatus('Please enter email and password', 'error');
      return;
    }

    try {
      showStatus('Logging in...', 'info');
      
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok) {
        currentUser = data.user;
        currentUser.token = data.token;
        await storeUser(currentUser);
        showMainSection();
        await loadUserSessions();
        showStatus('Login successful!', 'success');
        emailInput.value = '';
        passwordInput.value = '';
      } else {
        showStatus(data.error || 'Login failed', 'error');
      }
    } catch (error) {
      console.error('Login error:', error);
      showStatus('Login failed: Network error', 'error');
    }
  });

  registerBtn.addEventListener('click', async () => {
    const email = emailInput.value.trim();
    const password = passwordInput.value.trim();
    
    if (!email || !password) {
      showStatus('Please enter email and password', 'error');
      return;
    }

    if (password.length < 6) {
      showStatus('Password must be at least 6 characters', 'error');
      return;
    }

    try {
      showStatus('Creating account...', 'info');
      
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (response.ok) {
        currentUser = data.user;
        currentUser.token = data.token;
        await storeUser(currentUser);
        showMainSection();
        await loadUserSessions();
        showStatus('Account created successfully!', 'success');
        emailInput.value = '';
        passwordInput.value = '';
      } else {
        showStatus(data.error || 'Registration failed', 'error');
      }
    } catch (error) {
      console.error('Registration error:', error);
      showStatus('Registration failed: Network error', 'error');
    }
  });

  logoutBtn.addEventListener('click', async () => {
    currentUser = null;
    await clearStoredUser();
    showLoginSection();
    sessionsDropdown.innerHTML = '<option value="">Select a session...</option>';
    showStatus('Logged out successfully', 'success');
  });

  // Session management
  saveSessionBtn.addEventListener('click', async () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }

    try {
      showStatus('Extracting cookies...', 'info');
      
      // Get cookies using the same logic as before
      let allCookies = [];
      
      const exactDomainCookies = await chrome.cookies.getAll({ domain: currentDomain });
      allCookies = allCookies.concat(exactDomainCookies);
      
      const dotDomainCookies = await chrome.cookies.getAll({ domain: '.' + currentDomain });
      allCookies = allCookies.concat(dotDomainCookies);
      
      const urlCookies = await chrome.cookies.getAll({ url: currentTab.url });
      allCookies = allCookies.concat(urlCookies);
      
      const subdomains = ['www.' + currentDomain, 'm.' + currentDomain];
      for (const subdomain of subdomains) {
        try {
          const subCookies = await chrome.cookies.getAll({ domain: subdomain });
          allCookies = allCookies.concat(subCookies);
        } catch (e) {
          // Ignore errors
        }
      }
      
      // Remove duplicates
      const uniqueCookies = [];
      const seen = new Set();
      
      for (const cookie of allCookies) {
        const key = `${cookie.name}|${cookie.domain}|${cookie.path}`;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueCookies.push(cookie);
        }
      }
      
      if (uniqueCookies.length === 0) {
        showStatus('No cookies found for this domain', 'error');
        return;
      }

      // Save session to server
      const sessionData = {
        domain: currentDomain,
        url: currentTab.url,
        cookies: uniqueCookies,
        userAgent: navigator.userAgent
      };

      const response = await fetch(`${API_BASE}/sessions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentUser.token}`
        },
        body: JSON.stringify(sessionData)
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(`Session saved! (${uniqueCookies.length} cookies)`, 'success');
        await loadUserSessions();
      } else {
        showStatus(data.error || 'Failed to save session', 'error');
      }
      
    } catch (error) {
      console.error('Save session error:', error);
      showStatus('Save failed: ' + error.message, 'error');
    }
  });

  loadSessionBtn.addEventListener('click', async () => {
    const sessionId = sessionsDropdown.value;
    if (!sessionId) {
      showStatus('Please select a session to load', 'error');
      return;
    }

    try {
      showStatus('Loading session...', 'info');
      
      const response = await fetch(`${API_BASE}/sessions/${sessionId}`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const sessionData = await response.json();

      if (!response.ok) {
        throw new Error(sessionData.error || 'Failed to load session');
      }

      showStatus(`Importing ${sessionData.cookies.length} cookies...`, 'info');

      let successCount = 0;
      let errorCount = 0;

      // Import each cookie
      for (const cookie of sessionData.cookies) {
        try {
          let cookieDomain = cookie.domain;
          if (cookieDomain.startsWith('.')) {
            cookieDomain = cookieDomain.substring(1);
          }
          
          const protocol = cookie.secure ? 'https://' : 'http://';
          const cookieUrl = protocol + cookieDomain + cookie.path;

          const cookieDetails = {
            url: cookieUrl,
            name: cookie.name,
            value: cookie.value,
            path: cookie.path,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            domain: cookie.domain
          };

          if (!cookie.session && cookie.expirationDate) {
            cookieDetails.expirationDate = cookie.expirationDate;
          }

          await chrome.cookies.set(cookieDetails);
          successCount++;
        } catch (cookieError) {
          console.error('Cookie import failed:', cookie.name, cookieError);
          errorCount++;
        }
      }

      if (successCount > 0) {
        showStatus(`Session loaded! ${successCount} cookies imported${errorCount > 0 ? ` (${errorCount} failed)` : ''}`, 'success');
        
        // Navigate to the domain
        setTimeout(() => {
          chrome.tabs.update(currentTab.id, { url: sessionData.url || `https://${sessionData.domain}` });
        }, 1000);
      } else {
        throw new Error('Failed to import any cookies');
      }

    } catch (error) {
      console.error('Load session error:', error);
      showStatus('Load failed: ' + error.message, 'error');
    }
  });

  deleteSessionBtn.addEventListener('click', async () => {
    const sessionId = sessionsDropdown.value;
    if (!sessionId) {
      showStatus('Please select a session to delete', 'error');
      return;
    }

    if (!confirm('Are you sure you want to delete this session?')) {
      return;
    }

    try {
      showStatus('Deleting session...', 'info');
      
      const response = await fetch(`${API_BASE}/sessions/${sessionId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      if (response.ok) {
        showStatus('Session deleted successfully', 'success');
        await loadUserSessions();
      } else {
        const data = await response.json();
        showStatus(data.error || 'Failed to delete session', 'error');
      }

    } catch (error) {
      console.error('Delete session error:', error);
      showStatus('Delete failed: ' + error.message, 'error');
    }
  });

  // Share session functionality
  shareSessionBtn.addEventListener('click', () => {
    const sessionId = sessionsDropdown.value;
    if (!sessionId) {
      showStatus('Please select a session to share', 'error');
      return;
    }
    showShareModal();
  });

  confirmShareBtn.addEventListener('click', async () => {
    const sessionId = sessionsDropdown.value;
    const shareEmail = shareEmailInput.value.trim();
    const expirationMinutes = getExpirationMinutes('share');
    
    if (!sessionId) {
      showStatus('Please select a session to share', 'error');
      return;
    }
    
    if (!shareEmail) {
      showStatus('Please enter an email address', 'error');
      return;
    }
    
    if (!isValidEmail(shareEmail)) {
      showStatus('Please enter a valid email address', 'error');
      return;
    }

    try {
      showStatus('Sharing session...', 'info');
      
      const response = await fetch(`${API_BASE}/sessions/${sessionId}/share`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentUser.token}`
        },
        body: JSON.stringify({ 
          email: shareEmail,
          expirationMinutes: expirationMinutes
        })
      });

      const data = await response.json();

      if (response.ok) {
        showStatus('Session shared successfully!', 'success');
        hideShareModal();
      } else {
        showStatus(data.error || 'Failed to share session', 'error');
      }

    } catch (error) {
      console.error('Share session error:', error);
      showStatus('Share failed: ' + error.message, 'error');
    }
  });

  cancelShareBtn.addEventListener('click', () => {
    hideShareModal();
  });

  // Shared sessions functionality
  sharedSessionsBtn.addEventListener('click', async () => {
    showSharedSessionsModal();
    await loadSharedSessions();
  });

  closeSharedModalBtn.addEventListener('click', () => {
    hideSharedSessionsModal();
  });

  // Manage my shares functionality
  manageMySharesBtn.addEventListener('click', async () => {
    showManageMySharesModal();
    await loadMyShares();
  });

  closeManageMySharesBtn.addEventListener('click', () => {
    hideManageMySharesModal();
  });

  // Close modals when clicking outside
  shareModal.addEventListener('click', (e) => {
    if (e.target === shareModal) {
      hideShareModal();
    }
  });

  sharedSessionsModal.addEventListener('click', (e) => {
    if (e.target === sharedSessionsModal) {
      hideSharedSessionsModal();
    }
  });

  manageMySharesModal.addEventListener('click', (e) => {
    if (e.target === manageMySharesModal) {
      hideManageMySharesModal();
    }
  });

  // ACCESS REQUEST EVENT LISTENERS

  // Request access functionality (now works with friends)
  requestAccessBtn.addEventListener('click', async () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }
    await showRequestAccessFromFriendsModal();
  });

  confirmRequestBtn.addEventListener('click', async () => {
    const message = requestMessageInput.value.trim();
    
    try {
      showStatus('Sending access request...', 'info');
      
      const response = await fetch(`${API_BASE}/access-requests`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentUser.token}`
        },
        body: JSON.stringify({ 
          domain: currentDomain,
          url: currentTab.url,
          message: message || `Access request for ${currentDomain}`
        })
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        hideRequestAccessModal();
      } else {
        showStatus(data.error || 'Failed to send access request', 'error');
      }

    } catch (error) {
      console.error('Access request error:', error);
      showStatus('Request failed: ' + error.message, 'error');
    }
  });

  cancelRequestBtn.addEventListener('click', () => {
    hideRequestAccessModal();
  });

  // View requests functionality
  viewRequestsBtn.addEventListener('click', async () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }
    showViewRequestsModal();
    await loadUserRequests();
  });

  closeViewRequestsBtn.addEventListener('click', () => {
    hideViewRequestsModal();
  });

  // Manage requests functionality
  manageRequestsBtn.addEventListener('click', async () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }
    showManageRequestsModal();
    await loadIncomingRequests();
  });

  closeManageRequestsBtn.addEventListener('click', () => {
    hideManageRequestsModal();
  });

  // Close modals when clicking outside
  requestAccessModal.addEventListener('click', (e) => {
    if (e.target === requestAccessModal) {
      hideRequestAccessModal();
    }
  });

  viewRequestsModal.addEventListener('click', (e) => {
    if (e.target === viewRequestsModal) {
      hideViewRequestsModal();
    }
  });

  manageRequestsModal.addEventListener('click', (e) => {
    if (e.target === manageRequestsModal) {
      hideManageRequestsModal();
    }
  });

  // FRIENDS SYSTEM EVENT LISTENERS

  // Friends functionality
  friendsBtn.addEventListener('click', async () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }
    showFriendsModal();
    await loadFriends();
  });

  closeFriendsBtn.addEventListener('click', () => {
    hideFriendsModal();
  });

  // Add friend functionality
  addFriendBtn.addEventListener('click', () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }
    showAddFriendModal();
  });

  confirmAddFriendBtn.addEventListener('click', async () => {
    const email = friendEmailInput.value.trim();
    const message = friendRequestMessageInput.value.trim();
    
    if (!email) {
      showStatus('Please enter an email address', 'error');
      return;
    }
    
    if (!isValidEmail(email)) {
      showStatus('Please enter a valid email address', 'error');
      return;
    }

    try {
      showStatus('Sending friend request...', 'info');
      
      const response = await fetch(`${API_BASE}/friends/request`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentUser.token}`
        },
        body: JSON.stringify({ email, message })
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        hideAddFriendModal();
      } else {
        showStatus(data.error || 'Failed to send friend request', 'error');
      }

    } catch (error) {
      console.error('Friend request error:', error);
      showStatus('Request failed: ' + error.message, 'error');
    }
  });

  cancelAddFriendBtn.addEventListener('click', () => {
    hideAddFriendModal();
  });

  // Friend requests functionality
  friendRequestsBtn.addEventListener('click', async () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }
    showFriendRequestsModal();
    await loadIncomingFriendRequests();
  });

  closeFriendRequestsBtn.addEventListener('click', () => {
    hideFriendRequestsModal();
  });

  // Tab switching for friend requests
  incomingFriendRequestsTab.addEventListener('click', async () => {
    incomingFriendRequestsTab.classList.add('active');
    outgoingFriendRequestsTab.classList.remove('active');
    incomingFriendRequestsList.style.display = 'block';
    outgoingFriendRequestsList.style.display = 'none';
    await loadIncomingFriendRequests();
  });

  outgoingFriendRequestsTab.addEventListener('click', async () => {
    outgoingFriendRequestsTab.classList.add('active');
    incomingFriendRequestsTab.classList.remove('active');
    outgoingFriendRequestsList.style.display = 'block';
    incomingFriendRequestsList.style.display = 'none';
    await loadOutgoingFriendRequests();
  });

  // Request access from friends functionality
  confirmRequestFromFriendsBtn.addEventListener('click', async () => {
    const message = requestFromFriendsMessageInput.value.trim();
    const requestedExpirationMinutes = getExpirationMinutes('req');
    const selectedFriends = Array.from(friendsWithSessionsList.querySelectorAll('input[type="checkbox"]:checked'))
      .map(checkbox => parseInt(checkbox.value));
    
    if (selectedFriends.length === 0) {
      showStatus('Please select at least one friend', 'error');
      return;
    }

    try {
      showStatus('Sending access requests...', 'info');
      
      let successCount = 0;
      for (const friendId of selectedFriends) {
        try {
          const response = await fetch(`${API_BASE}/access-requests`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${currentUser.token}`
            },
            body: JSON.stringify({ 
              domain: currentDomain,
              url: currentTab.url,
              message: message || `Access request for ${currentDomain}`,
              friendId: friendId,
              requestedExpirationMinutes: requestedExpirationMinutes
            })
          });

          if (response.ok) {
            successCount++;
          }
        } catch (err) {
          console.error('Error sending request to friend:', friendId, err);
        }
      }

      if (successCount > 0) {
        showStatus(`Access requests sent to ${successCount} friend(s)`, 'success');
        hideRequestAccessFromFriendsModal();
      } else {
        showStatus('Failed to send any requests', 'error');
      }

    } catch (error) {
      console.error('Access request error:', error);
      showStatus('Request failed: ' + error.message, 'error');
    }
  });

  cancelRequestFromFriendsBtn.addEventListener('click', () => {
    hideRequestAccessFromFriendsModal();
  });

  closeRequestAccessFromFriendsBtn.addEventListener('click', () => {
    hideRequestAccessFromFriendsModal();
  });

  // Close modals when clicking outside
  friendsModal.addEventListener('click', (e) => {
    if (e.target === friendsModal) {
      hideFriendsModal();
    }
  });

  addFriendModal.addEventListener('click', (e) => {
    if (e.target === addFriendModal) {
      hideAddFriendModal();
    }
  });

  friendRequestsModal.addEventListener('click', (e) => {
    if (e.target === friendRequestsModal) {
      hideFriendRequestsModal();
    }
  });

  requestAccessFromFriendsModal.addEventListener('click', (e) => {
    if (e.target === requestAccessFromFriendsModal) {
      hideRequestAccessFromFriendsModal();
    }
  });

  // Expiration controls event listeners
  clearSessionBtn.addEventListener('click', async () => {
    if (confirm('Are you sure you want to end this session? This will log you out of the imported session.')) {
      await clearImportedSession();
    }
  });

  // Share modal expiration controls
  document.querySelectorAll('input[name="shareExpiration"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
      const customDiv = document.getElementById('shareCustomTimeDiv');
      if (e.target.value === 'custom') {
        customDiv.style.display = 'flex';
      } else {
        customDiv.style.display = 'none';
      }
    });
  });

  // Request access modal expiration controls
  document.querySelectorAll('input[name="requestExpiration"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
      const customDiv = document.getElementById('reqCustomTimeDiv');
      if (e.target.value === 'custom') {
        customDiv.style.display = 'flex';
      } else {
        customDiv.style.display = 'none';
      }
    });
  });

  async function loadUserSessions() {
    if (!currentUser) return;

    try {
      const response = await fetch(`${API_BASE}/sessions`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const sessions = await response.json();

      if (response.ok) {
        sessionsDropdown.innerHTML = '<option value="">Select a session...</option>';
        sessions.forEach(session => {
          const option = document.createElement('option');
          option.value = session.id;
          option.textContent = `${session.domain} (${new Date(session.created_at).toLocaleDateString()})`;
          sessionsDropdown.appendChild(option);
        });
      }
    } catch (error) {
      console.error('Load sessions error:', error);
    }
  }

  async function loadSharedSessions() {
    if (!currentUser) return;

    try {
      const response = await fetch(`${API_BASE}/sessions/shared`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const sharedSessions = await response.json();

      if (response.ok) {
        displaySharedSessions(sharedSessions);
      } else {
        console.error('Failed to load shared sessions:', sharedSessions.error);
      }
    } catch (error) {
      console.error('Load shared sessions error:', error);
    }
  }

  function displaySharedSessions(sessions) {
    console.log('displaySharedSessions called with:', sessions);
    console.log('sharedSessionsList element:', sharedSessionsList);
    
    if (!sharedSessionsList) {
      console.error('sharedSessionsList element not found!');
      return;
    }
    
    sharedSessionsList.innerHTML = '';
    
    if (!sessions || !Array.isArray(sessions) || sessions.length === 0) {
      console.log('No sessions to display');
      sharedSessionsList.innerHTML = '<div class="no-sessions">No shared sessions available</div>';
      return;
    }

    console.log('Displaying', sessions.length, 'shared sessions');

    sessions.forEach((session, index) => {
      console.log(`Creating session item ${index}:`, session);
      
      const sessionItem = document.createElement('div');
      sessionItem.className = 'shared-session-item';
        sessionItem.innerHTML = `
          <div class="session-info">
            <div class="session-domain">${session.domain || 'Unknown domain'}</div>
            <div class="session-meta">
              Shared by: ${session.ownerEmail || 'Unknown'}<br>
              Date: ${session.created_at ? new Date(session.created_at).toLocaleDateString() : 'Unknown date'}
            </div>
          </div>
          <div class="session-actions">
            <button class="btn btn-sm btn-primary shared-load-btn" data-session-id="${session.id}">
              Load Session
            </button>
          </div>
        `;
      sharedSessionsList.appendChild(sessionItem);
    });
    
    console.log('Finished displaying shared sessions');

      // Attach event listeners to shared session load buttons
      const loadBtns = sharedSessionsList.querySelectorAll('.shared-load-btn');
      loadBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const sessionId = btn.getAttribute('data-session-id');
          await window.loadSharedSession(sessionId);
        });
      });
  }

  async function loadMyShares() {
    if (!currentUser) return;

    try {
      console.log('Loading my shares for user:', currentUser.email);
      const response = await fetch(`${API_BASE}/sessions/my-shares`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      console.log('My shares response status:', response.status);
      const myShares = await response.json();
      console.log('My shares response data:', myShares);

      if (response.ok) {
        displayMyShares(myShares);
      } else {
        console.error('Failed to load my shares:', myShares.error);
        mySharesList.innerHTML = `<div class="no-sessions">Failed to load shares: ${myShares.error || 'Unknown error'}</div>`;
      }
    } catch (error) {
      console.error('Load my shares error:', error);
      mySharesList.innerHTML = `<div class="no-sessions">Error loading shares: ${error.message}</div>`;
    }
  }

  function displayMyShares(shares) {
    mySharesList.innerHTML = '';
    
    if (!shares || !Array.isArray(shares) || shares.length === 0) {
      mySharesList.innerHTML = '<div class="no-sessions">You haven\'t shared any sessions yet</div>';
      return;
    }

    shares.forEach((share) => {
      const shareItem = document.createElement('div');
      shareItem.className = 'shared-session-item';
      
      const statusClass = `status-${share.status}`;
      const statusText = share.status.charAt(0).toUpperCase() + share.status.slice(1);
      
      let expirationInfo = '';
      if (share.expires_at && share.status === 'active') {
        const expiresAt = new Date(share.expires_at);
        const now = new Date();
        const timeRemaining = expiresAt - now;
        
        if (timeRemaining > 0) {
          const hoursRemaining = Math.floor(timeRemaining / (1000 * 60 * 60));
          const minutesRemaining = Math.floor((timeRemaining % (1000 * 60 * 60)) / (1000 * 60));
          expirationInfo = `<br>Expires in: ${hoursRemaining}h ${minutesRemaining}m`;
        } else {
          expirationInfo = '<br>Expired';
        }
      } else if (share.status === 'permanent') {
        expirationInfo = '<br>Permanent access';
      }
      
      shareItem.innerHTML = `
        <div class="session-info">
          <div class="session-domain">${share.domain}</div>
          <div class="session-meta">
            Shared with: ${share.shared_with_email}<br>
            Shared: ${new Date(share.shared_at).toLocaleDateString()}<br>
            <span class="status-badge ${statusClass}">${statusText}</span>
            ${expirationInfo}
          </div>
        </div>
        <div class="session-actions">
          ${share.status === 'active' || share.status === 'permanent' ? `
            <button class="btn btn-sm btn-danger revoke-access-btn" 
                    data-session-id="${share.session_id}" 
                    data-email="${share.shared_with_email}">
              Revoke Access
            </button>
          ` : ''}
        </div>
      `;
      mySharesList.appendChild(shareItem);
    });

    // Attach event listeners to revoke buttons
    const revokeBtns = mySharesList.querySelectorAll('.revoke-access-btn');
    revokeBtns.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const sessionId = btn.getAttribute('data-session-id');
        const email = btn.getAttribute('data-email');
        await handleRevokeAccess(sessionId, email);
      });
    });
  }

  async function handleRevokeAccess(sessionId, email) {
    if (!confirm(`Are you sure you want to revoke access for ${email}? This will immediately log them out if they're currently using this session.`)) {
      return;
    }

    try {
      showStatus('Revoking access...', 'info');
      
      const response = await fetch(`${API_BASE}/sessions/${sessionId}/share/${email}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(`Access revoked for ${email}`, 'success');
        
        // Reload the shares list to show updated status
        await loadMyShares();
        
        // Optionally, you could also trigger a notification or 
        // implement a push notification system to immediately log out users
        
      } else {
        showStatus(data.error || 'Failed to revoke access', 'error');
      }

    } catch (error) {
      console.error('Revoke access error:', error);
      showStatus('Revoke failed: ' + error.message, 'error');
    }
  }

  // Make loadSharedSession globally accessible for onclick
  window.loadSharedSession = async (sessionId) => {
    try {
      showStatus('Loading shared session...', 'info');
      
      const response = await fetch(`${API_BASE}/sessions/shared/${sessionId}`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const sessionData = await response.json();

      if (!response.ok) {
        throw new Error(sessionData.error || 'Failed to load shared session');
      }

      console.log('Shared session data:', sessionData);

      // Check if session has expiration info and if it's expired
      if (sessionData.expiresAt) {
        const expirationTime = new Date(sessionData.expiresAt).getTime();
        const now = Date.now();
        if (now > expirationTime) {
          const expiredMins = Math.floor((now - expirationTime) / 60000);
          throw new Error(`Shared session expired ${expiredMins} minutes ago`);
        }
        const remainingMins = Math.floor((expirationTime - now) / 60000);
        console.log(`Shared session has ${remainingMins} minutes remaining until expiration`);
      }

      showStatus(`Importing ${sessionData.cookies.length} cookies...`, 'info');

      let successCount = 0;
      let errorCount = 0;
      const importedCookies = [];

      // Import each cookie (same logic as regular session loading)
      for (const cookie of sessionData.cookies) {
        try {
          let cookieDomain = cookie.domain;
          if (cookieDomain.startsWith('.')) {
            cookieDomain = cookieDomain.substring(1);
          }
          
          const protocol = cookie.secure ? 'https://' : 'http://';
          const cookieUrl = protocol + cookieDomain + cookie.path;

          const cookieDetails = {
            url: cookieUrl,
            name: cookie.name,
            value: cookie.value,
            path: cookie.path,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            domain: cookie.domain
          };

          if (!cookie.session && cookie.expirationDate) {
            cookieDetails.expirationDate = cookie.expirationDate;
          }

          const result = await chrome.cookies.set(cookieDetails);
          if (result) {
            importedCookies.push(cookie);
            successCount++;
          } else {
            throw new Error('Cookie.set returned null');
          }
        } catch (cookieError) {
          console.error('Cookie import failed:', cookie.name, cookieError);
          errorCount++;
        }
      }

      if (successCount > 0) {
        showStatus(`Shared session loaded! ${successCount} cookies imported${errorCount > 0 ? ` (${errorCount} failed)` : ''}`, 'success');
        
        // Store session info for auto-logout (if expiration is available)
        if (sessionData.expiresAt) {
          const expirationTime = new Date(sessionData.expiresAt).getTime();
          const sessionInfo = {
            sessionId: sessionId,
            domain: sessionData.domain,
            cookies: importedCookies,
            autoLogoutTime: expirationTime,
            importTime: Date.now(),
            originalExpiration: expirationTime,
            ownerEmail: sessionData.ownerEmail,
            isSharedSession: true
          };
          
          await chrome.storage.local.set({ 
            activeSession: sessionInfo 
          });
          
          // Set up auto-logout alarm
          const minutesUntilLogout = Math.ceil((expirationTime - Date.now()) / (60 * 1000));
          if (minutesUntilLogout > 0) {
            try {
              if (chrome.alarms) {
                await chrome.alarms.clear('autoLogout');
                await chrome.alarms.create('autoLogout', { 
                  delayInMinutes: minutesUntilLogout 
                });
                console.log(`Auto-logout alarm set for ${minutesUntilLogout} minutes`);
              } else {
                // Send message to background script to set the alarm
                chrome.runtime.sendMessage({
                  action: 'setAutoLogoutAlarm',
                  delayInMinutes: minutesUntilLogout
                });
              }
            } catch (alarmError) {
              console.error('Error setting alarm:', alarmError);
            }
            
            // Show active session indicator
            await checkActiveSession();
          }
        } else {
          // Handle sessions without expiration (permanent access)
          console.log('Loaded shared session without expiration - permanent access');
        }
        
        hideSharedSessionsModal();
        
        // Navigate to the domain
        setTimeout(() => {
          chrome.tabs.update(currentTab.id, { url: sessionData.url || `https://${sessionData.domain}` });
        }, 1000);
      } else {
        throw new Error('Failed to import any cookies');
      }

    } catch (error) {
      console.error('Load shared session error:', error);
      showStatus('Load failed: ' + error.message, 'error');
    }
  };

  // Modal helper functions
  function showShareModal() {
    shareModal.style.display = 'flex';
    // Focus the email input when showing modal
    const emailInput = document.getElementById('shareEmail');
    if (emailInput) {
      emailInput.focus();
    }
  }

  function hideShareModal() {
    shareModal.style.display = 'none';
    // Clear the email input when hiding
    const emailInput = document.getElementById('shareEmail');
    if (emailInput) {
      emailInput.value = '';
    }
  }

  function showSharedSessionsModal() {
    sharedSessionsModal.style.display = 'flex';
  }

  function hideSharedSessionsModal() {
    sharedSessionsModal.style.display = 'none';
  }

  function showManageMySharesModal() {
    manageMySharesModal.style.display = 'flex';
  }

  function hideManageMySharesModal() {
    manageMySharesModal.style.display = 'none';
  }

  // ACCESS REQUEST MODAL FUNCTIONS

  function showRequestAccessModal() {
    requestDomainInput.value = currentDomain;
    requestAccessModal.style.display = 'flex';
    requestMessageInput.focus();
  }

  function hideRequestAccessModal() {
    requestAccessModal.style.display = 'none';
    requestMessageInput.value = '';
  }

  function showViewRequestsModal() {
    viewRequestsModal.style.display = 'flex';
  }

  function hideViewRequestsModal() {
    viewRequestsModal.style.display = 'none';
  }

  function showManageRequestsModal() {
    manageRequestsModal.style.display = 'flex';
  }

  function hideManageRequestsModal() {
    manageRequestsModal.style.display = 'none';
  }

  // LOAD REQUESTS FUNCTIONS

  async function loadUserRequests() {
    if (!currentUser) return;

    try {
      const response = await fetch(`${API_BASE}/access-requests/outgoing`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const requests = await response.json();

      if (response.ok) {
        displayUserRequests(requests);
      } else {
        console.error('Failed to load user requests:', requests.error);
        viewRequestsList.innerHTML = '<div class="no-requests">Failed to load requests</div>';
      }
    } catch (error) {
      console.error('Load user requests error:', error);
      viewRequestsList.innerHTML = '<div class="no-requests">Error loading requests</div>';
    }
  }

  async function loadIncomingRequests() {
    if (!currentUser) return;

    try {
      const response = await fetch(`${API_BASE}/access-requests/incoming`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const requests = await response.json();

      if (response.ok) {
        displayIncomingRequests(requests);
      } else {
        console.error('Failed to load incoming requests:', requests.error);
        manageRequestsList.innerHTML = '<div class="no-requests">Failed to load requests</div>';
      }
    } catch (error) {
      console.error('Load incoming requests error:', error);
      manageRequestsList.innerHTML = '<div class="no-requests">Error loading requests</div>';
    }
  }

  function displayUserRequests(requests) {
    viewRequestsList.innerHTML = '';
    
    if (!requests || !Array.isArray(requests) || requests.length === 0) {
      viewRequestsList.innerHTML = '<div class="no-requests">No access requests found</div>';
      return;
    }

    requests.forEach(request => {
      const requestItem = document.createElement('div');
      requestItem.className = 'request-item';
      
      const statusClass = `status-${request.status}`;
      const statusText = request.status.charAt(0).toUpperCase() + request.status.slice(1);
      
      requestItem.innerHTML = `
        <div class="request-info">
          <div class="request-domain">${request.domain}</div>
          <div class="request-meta">
            To: ${request.ownerEmail}<br>
            Sent: ${new Date(request.created_at).toLocaleDateString()}<br>
            <span class="status-badge ${statusClass}">${statusText}</span>
          </div>
          ${request.message ? `<div class="request-message">"${request.message}"</div>` : ''}
        </div>
      `;
      
      viewRequestsList.appendChild(requestItem);
    });
  }

  function displayIncomingRequests(requests) {
    manageRequestsList.innerHTML = '';
    
    if (!requests || !Array.isArray(requests) || requests.length === 0) {
      manageRequestsList.innerHTML = '<div class="no-requests">No incoming access requests</div>';
      return;
    }

    requests.forEach(request => {
      const requestItem = document.createElement('div');
      requestItem.className = 'request-item';
      
      const isPending = request.status === 'pending';
      const statusClass = `status-${request.status}`;
      const statusText = request.status.charAt(0).toUpperCase() + request.status.slice(1);
      
      requestItem.innerHTML = `
        <div class="request-info">
          <div class="request-domain">${request.domain}</div>
          <div class="request-meta">
            From: ${request.requesterEmail}<br>
            Received: ${new Date(request.created_at).toLocaleDateString()}<br>
            Sessions: ${request.sessionCount || 0}<br>
            <span class="status-badge ${statusClass}">${statusText}</span>
          </div>
          ${request.message ? `<div class="request-message">"${request.message}"</div>` : ''}
        </div>
        <div class="request-actions">
          ${isPending ? `
            <button class="btn btn-success approve-btn" data-request-id="${request.id}">
              Approve
            </button>
            <button class="btn btn-danger deny-btn" data-request-id="${request.id}">
              Deny
            </button>
          ` : ''}
        </div>
      `;
      
      manageRequestsList.appendChild(requestItem);
    });

    // Attach event listeners to approve/deny buttons
    const approveBtns = manageRequestsList.querySelectorAll('.approve-btn');
    const denyBtns = manageRequestsList.querySelectorAll('.deny-btn');

    approveBtns.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const requestId = btn.getAttribute('data-request-id');
        await handleApproveRequest(requestId);
      });
    });

    denyBtns.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const requestId = btn.getAttribute('data-request-id');
        await handleDenyRequest(requestId);
      });
    });
  }

  async function handleApproveRequest(requestId) {
    try {
      showStatus('Approving request...', 'info');
      
      const response = await fetch(`${API_BASE}/access-requests/${requestId}/approve`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        await loadIncomingRequests(); // Refresh the list
      } else {
        showStatus(data.error || 'Failed to approve request', 'error');
      }

    } catch (error) {
      console.error('Approve request error:', error);
      showStatus('Approve failed: ' + error.message, 'error');
    }
  }

  async function handleDenyRequest(requestId) {
    try {
      showStatus('Denying request...', 'info');
      
      const response = await fetch(`${API_BASE}/access-requests/${requestId}/deny`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        await loadIncomingRequests(); // Refresh the list
      } else {
        showStatus(data.error || 'Failed to deny request', 'error');
      }

    } catch (error) {
      console.error('Deny request error:', error);
      showStatus('Deny failed: ' + error.message, 'error');
    }
  }

  // FRIENDS SYSTEM HELPER FUNCTIONS

  function showFriendsModal() {
    friendsModal.style.display = 'flex';
  }

  function hideFriendsModal() {
    friendsModal.style.display = 'none';
  }

  function showAddFriendModal() {
    addFriendModal.style.display = 'flex';
    friendEmailInput.focus();
  }

  function hideAddFriendModal() {
    addFriendModal.style.display = 'none';
    friendEmailInput.value = '';
    friendRequestMessageInput.value = '';
  }

  function showFriendRequestsModal() {
    friendRequestsModal.style.display = 'flex';
  }

  function hideFriendRequestsModal() {
    friendRequestsModal.style.display = 'none';
  }

  async function showRequestAccessFromFriendsModal() {
    requestFromFriendsDomainInput.value = currentDomain;
    await loadFriendsWithSessions();
    requestAccessFromFriendsModal.style.display = 'flex';
  }

  function hideRequestAccessFromFriendsModal() {
    requestAccessFromFriendsModal.style.display = 'none';
    requestFromFriendsMessageInput.value = '';
    // Uncheck all checkboxes
    friendsWithSessionsList.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
  }

  async function loadFriends() {
    if (!currentUser) return;

    try {
      const response = await fetch(`${API_BASE}/friends`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const friends = await response.json();

      if (response.ok) {
        displayFriends(friends);
      } else {
        console.error('Failed to load friends:', friends.error);
        friendsList.innerHTML = '<div class="no-friends">Failed to load friends</div>';
      }
    } catch (error) {
      console.error('Load friends error:', error);
      friendsList.innerHTML = '<div class="no-friends">Error loading friends</div>';
    }
  }

  function displayFriends(friends) {
    friendsList.innerHTML = '';
    
    if (!friends || !Array.isArray(friends) || friends.length === 0) {
      friendsList.innerHTML = '<div class="no-friends">No friends yet. Add some friends to start sharing sessions!</div>';
      return;
    }

    friends.forEach(friend => {
      const friendItem = document.createElement('div');
      friendItem.className = 'friend-item';
      
      friendItem.innerHTML = `
        <div class="friend-info">
          <div class="friend-email">${friend.friendemail}</div>
          <div class="friend-meta">
            Friends since: ${new Date(friend.friendssince).toLocaleDateString()}
          </div>
        </div>
        <div class="friend-actions">
          <button class="btn btn-danger remove-friend-btn" data-friend-id="${friend.friendid}">
            Remove
          </button>
        </div>
      `;
      
      friendsList.appendChild(friendItem);
    });

    // Attach event listeners to remove friend buttons
    const removeBtns = friendsList.querySelectorAll('.remove-friend-btn');
    removeBtns.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const friendId = btn.getAttribute('data-friend-id');
        if (confirm('Are you sure you want to remove this friend?')) {
          await handleRemoveFriend(friendId);
        }
      });
    });
  }

  async function loadIncomingFriendRequests() {
    if (!currentUser) return;

    try {
      const response = await fetch(`${API_BASE}/friends/requests/incoming`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const requests = await response.json();

      if (response.ok) {
        displayIncomingFriendRequests(requests);
      } else {
        console.error('Failed to load incoming friend requests:', requests.error);
        incomingFriendRequestsList.innerHTML = '<div class="no-requests">Failed to load requests</div>';
      }
    } catch (error) {
      console.error('Load incoming friend requests error:', error);
      incomingFriendRequestsList.innerHTML = '<div class="no-requests">Error loading requests</div>';
    }
  }

  async function loadOutgoingFriendRequests() {
    if (!currentUser) return;

    try {
      const response = await fetch(`${API_BASE}/friends/requests/outgoing`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const requests = await response.json();

      if (response.ok) {
        displayOutgoingFriendRequests(requests);
      } else {
        console.error('Failed to load outgoing friend requests:', requests.error);
        outgoingFriendRequestsList.innerHTML = '<div class="no-requests">Failed to load requests</div>';
      }
    } catch (error) {
      console.error('Load outgoing friend requests error:', error);
      outgoingFriendRequestsList.innerHTML = '<div class="no-requests">Error loading requests</div>';
    }
  }

  function displayIncomingFriendRequests(requests) {
    incomingFriendRequestsList.innerHTML = '';
    
    if (!requests || !Array.isArray(requests) || requests.length === 0) {
      incomingFriendRequestsList.innerHTML = '<div class="no-requests">No incoming friend requests</div>';
      return;
    }

    requests.forEach(request => {
      const requestItem = document.createElement('div');
      requestItem.className = 'request-item';
      
      requestItem.innerHTML = `
        <div class="request-info">
          <div class="request-domain">${request.senderemail}</div>
          <div class="request-meta">
            Received: ${new Date(request.created_at).toLocaleDateString()}
          </div>
          ${request.message ? `<div class="request-message">"${request.message}"</div>` : ''}
        </div>
        <div class="request-actions">
          <button class="btn btn-success accept-friend-btn" data-request-id="${request.id}">
            Accept
          </button>
          <button class="btn btn-danger decline-friend-btn" data-request-id="${request.id}">
            Decline
          </button>
        </div>
      `;
      
      incomingFriendRequestsList.appendChild(requestItem);
    });

    // Attach event listeners
    const acceptBtns = incomingFriendRequestsList.querySelectorAll('.accept-friend-btn');
    const declineBtns = incomingFriendRequestsList.querySelectorAll('.decline-friend-btn');

    acceptBtns.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const requestId = btn.getAttribute('data-request-id');
        await handleAcceptFriendRequest(requestId);
      });
    });

    declineBtns.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        const requestId = btn.getAttribute('data-request-id');
        await handleDeclineFriendRequest(requestId);
      });
    });
  }

  function displayOutgoingFriendRequests(requests) {
    outgoingFriendRequestsList.innerHTML = '';
    
    if (!requests || !Array.isArray(requests) || requests.length === 0) {
      outgoingFriendRequestsList.innerHTML = '<div class="no-requests">No outgoing friend requests</div>';
      return;
    }

    requests.forEach(request => {
      const requestItem = document.createElement('div');
      requestItem.className = 'request-item';
      
      const statusClass = `status-${request.status}`;
      const statusText = request.status.charAt(0).toUpperCase() + request.status.slice(1);
      
      requestItem.innerHTML = `
        <div class="request-info">
          <div class="request-domain">${request.receiveremail}</div>
          <div class="request-meta">
            Sent: ${new Date(request.created_at).toLocaleDateString()}<br>
            <span class="status-badge ${statusClass}">${statusText}</span>
          </div>
          ${request.message ? `<div class="request-message">"${request.message}"</div>` : ''}
        </div>
      `;
      
      outgoingFriendRequestsList.appendChild(requestItem);
    });
  }

  async function loadFriendsWithSessions() {
    if (!currentUser) return;

    try {
      // First get all friends
      const friendsResponse = await fetch(`${API_BASE}/friends`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const friends = await friendsResponse.json();

      if (!friendsResponse.ok) {
        throw new Error('Failed to load friends');
      }

      // Filter friends who have sessions for current domain
      const friendsWithSessions = [];
      for (const friend of friends) {
        try {
          // This is a simplified approach - in a real app you'd want a dedicated endpoint
          // For now, we'll show all friends and let the backend handle the filtering
          friendsWithSessions.push({
            ...friend,
            sessionCount: '?' // We don't know the exact count without additional API call
          });
        } catch (err) {
          console.error('Error checking friend sessions:', err);
        }
      }

      displayFriendsWithSessions(friendsWithSessions);

    } catch (error) {
      console.error('Load friends with sessions error:', error);
      friendsWithSessionsList.innerHTML = '<div class="no-friends-with-sessions">Error loading friends</div>';
    }
  }

  function displayFriendsWithSessions(friends) {
    friendsWithSessionsList.innerHTML = '';
    
    if (!friends || !Array.isArray(friends) || friends.length === 0) {
      friendsWithSessionsList.innerHTML = '<div class="no-friends-with-sessions">No friends available. Add some friends first!</div>';
      return;
    }

    friends.forEach(friend => {
      const friendItem = document.createElement('div');
      friendItem.className = 'friend-selection-item';
      
      friendItem.innerHTML = `
        <input type="checkbox" value="${friend.friendid}" id="friend-${friend.friendid}">
        <div class="friend-selection-info">
          <div class="friend-selection-email">${friend.friendemail}</div>
          <div class="friend-selection-sessions">Will check if they have sessions for ${currentDomain}</div>
        </div>
      `;
      
      friendsWithSessionsList.appendChild(friendItem);

      // Make the whole item clickable
      friendItem.addEventListener('click', (e) => {
        if (e.target.type !== 'checkbox') {
          const checkbox = friendItem.querySelector('input[type="checkbox"]');
          checkbox.checked = !checkbox.checked;
        }
      });
    });
  }

  async function handleAcceptFriendRequest(requestId) {
    try {
      showStatus('Accepting friend request...', 'info');
      
      const response = await fetch(`${API_BASE}/friends/requests/${requestId}/accept`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        await loadIncomingFriendRequests(); // Refresh the list
      } else {
        showStatus(data.error || 'Failed to accept friend request', 'error');
      }

    } catch (error) {
      console.error('Accept friend request error:', error);
      showStatus('Accept failed: ' + error.message, 'error');
    }
  }

  async function handleDeclineFriendRequest(requestId) {
    try {
      showStatus('Declining friend request...', 'info');
      
      const response = await fetch(`${API_BASE}/friends/requests/${requestId}/decline`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        await loadIncomingFriendRequests(); // Refresh the list
      } else {
        showStatus(data.error || 'Failed to decline friend request', 'error');
      }

    } catch (error) {
      console.error('Decline friend request error:', error);
      showStatus('Decline failed: ' + error.message, 'error');
    }
  }

  async function handleRemoveFriend(friendId) {
    try {
      showStatus('Removing friend...', 'info');
      
      const response = await fetch(`${API_BASE}/friends/${friendId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        await loadFriends(); // Refresh the list
      } else {
        showStatus(data.error || 'Failed to remove friend', 'error');
      }

    } catch (error) {
      console.error('Remove friend error:', error);
      showStatus('Remove failed: ' + error.message, 'error');
    }
  }

  function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  function showStatus(message, type) {
    status.textContent = message;
    status.className = `status ${type}`;
    status.style.display = 'block';
    
    if (type === 'success') {
      setTimeout(() => {
        status.style.display = 'none';
      }, 3000);
    }
  }
});