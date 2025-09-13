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

  // Approve request elements
  const approveRequestModal = document.getElementById('approveRequestModal');
  const approveRequesterEmailInput = document.getElementById('approveRequesterEmail');
  const approveDomainInput = document.getElementById('approveDomain');
  const approveMessageInput = document.getElementById('approveMessage');
  const confirmApproveBtn = document.getElementById('confirmApproveBtn');
  const cancelApproveBtn = document.getElementById('cancelApproveBtn');

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

  // Initialize moved to end to avoid blocking listener bindings

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
        // Session is still active
        sessionDomainEl.textContent = session.domain;
        activeSessionDiv.style.display = 'block';
        
        // Update timer
        updateSessionTimer(session.autoLogoutTime);
        
        // Set interval to update timer
        if (timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(() => {
          updateSessionTimer(session.autoLogoutTime);
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

  async function clearImportedSession() {
    const result = await chrome.storage.local.get('activeSession');
    
    if (result.activeSession) {
      const session = result.activeSession;
      
      showStatus('Clearing imported session...', 'info');
      
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
      
      // Friendlier message when auto-logout or manual end occurs
      showStatus('Shared session ended. Cookies cleared.', 'success');
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
  if (sharedSessionsBtn) {
    sharedSessionsBtn.addEventListener('click', async () => {
      showSharedSessionsModal();
      await loadSharedSessions();
    });
  }

  closeSharedModalBtn.addEventListener('click', () => {
    hideSharedSessionsModal();
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

  // ACCESS REQUEST EVENT LISTENERS

  // Request access functionality (now works with friends)
  requestAccessBtn.addEventListener('click', async () => {
    if (!currentUser) {
      showStatus('Please login first', 'error');
      return;
    }
    showRequestAccessModal();
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
        // Handle specific error codes
        if (data.code === 'NO_FRIENDS_WITH_SESSIONS') {
          showStatus('No friends have sessions for this domain. You can:\n1. Add friends who use this site\n2. Use "Request Access from Friends" to send targeted requests', 'error');
        } else if (data.code === 'REQUESTS_ALREADY_EXIST') {
          showStatus('You already have pending requests for this domain with your friends', 'error');
        } else {
          showStatus(data.error || 'Failed to send access request', 'error');
        }
      }

    } catch (error) {
      console.error('Access request error:', error);
      if (error.message.includes('Failed to fetch')) {
        showStatus('Cannot connect to server. Please check if the backend is running on http://localhost:3000', 'error');
      } else {
        showStatus('Request failed: ' + error.message, 'error');
      }
    }
  });

  cancelRequestBtn.addEventListener('click', () => {
    hideRequestAccessModal();
  });

  // Switch to friends request flow
  document.addEventListener('click', async (e) => {
    if (e.target && e.target.id === 'switchToFriendsRequestBtn') {
      e.preventDefault();
      hideRequestAccessModal();
      await showRequestAccessFromFriendsModal();
    }
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

  // Approve request modal handlers
  confirmApproveBtn.addEventListener('click', async () => {
    const requestId = approveRequestModal.getAttribute('data-request-id');
    const expirationMinutes = getExpirationMinutes('approve');
    
    try {
      showStatus('Approving request...', 'info');
      
      const response = await fetch(`${API_BASE}/access-requests/${requestId}/approve`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentUser.token}`
        },
        body: JSON.stringify({
          expirationMinutes: expirationMinutes
        })
      });

      const data = await response.json();

      if (response.ok) {
        showStatus(data.message, 'success');
        hideApproveRequestModal();
        await loadIncomingRequests(); // Refresh the list
      } else {
        showStatus(data.error || 'Failed to approve request', 'error');
      }

    } catch (error) {
      console.error('Approve request error:', error);
      if (error.message.includes('Failed to fetch')) {
        showStatus('Cannot connect to server. Please check if the backend is running.', 'error');
      } else {
        showStatus('Approve failed: ' + error.message, 'error');
      }
    }
  });

  cancelApproveBtn.addEventListener('click', () => {
    hideApproveRequestModal();
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

  approveRequestModal.addEventListener('click', (e) => {
    if (e.target === approveRequestModal) {
      hideApproveRequestModal();
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

  // Approve request modal expiration controls
  document.querySelectorAll('input[name="approveExpiration"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
      const customDiv = document.getElementById('approveCustomTimeDiv');
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

  async function displaySharedSessions(sessions) {
    const listEl = document.getElementById('sharedSessionsTabList') || sharedSessionsList;
    if (!listEl) { console.error('shared sessions list element not found'); return; }
    const store = await chrome.storage.local.get('hiddenSharedSessions');
    const hidden = store.hiddenSharedSessions || [];

    // Helper to parse potentially timezone-less timestamps
    const toDate = (val) => {
      if (!val) return null;
      let d = new Date(val);
      if (isNaN(d)) {
        const iso = typeof val === 'string' ? (val.includes('T') ? val : val.replace(' ', 'T')) : val;
        d = new Date(iso + 'Z');
      }
      return isNaN(d) ? null : d;
    };

    listEl.innerHTML = '';

    // First, auto-hide expired shares if we have expiration info
    const notExpired = Array.isArray(sessions) ? sessions.filter(s => {
      if (s && (s.expiration_minutes || s.expirationMinutes) && (s.shared_at || s.sharedAt)) {
        const minutes = Number(s.expiration_minutes ?? s.expirationMinutes);
        const sharedAt = toDate(s.shared_at ?? s.sharedAt);
        if (sharedAt && minutes > 0) {
          const expiresAt = sharedAt.getTime() + minutes * 60 * 1000;
          return Date.now() < expiresAt;
        }
      }
      return true; // keep if we can't determine
    }) : [];

    // Apply user's manual hidden list
    const filtered = notExpired.filter(s => !hidden.includes(String(s.id)));
    if (filtered.length === 0) {
      listEl.innerHTML = '<div class="no-sessions">No shared sessions available</div>';
      return;
    }

    filtered.forEach((session) => {
      const sessionItem = document.createElement('div');
      sessionItem.className = 'shared-session-item';
      sessionItem.innerHTML = `
        <div class="session-info">
          <div class="session-domain">${session.domain || 'Unknown domain'}</div>
          <div class="session-meta">
            Shared by: ${session.ownerEmail || 'Unknown'}<br>
            ${session.shared_at ? `Shared: ${formatDate(session.shared_at)}` : (session.created_at ? `Date: ${formatDate(session.created_at)}` : 'Date: -')}
          </div>
        </div>
        <div class="session-actions">
          <button class="btn btn-sm btn-primary shared-load-btn" data-session-id="${session.id}">Load</button>
          <button class="btn btn-sm btn-outline hide-shared-btn" data-session-id="${session.id}">Hide</button>
        </div>`;
      listEl.appendChild(sessionItem);
    });

    // Attach events
    listEl.querySelectorAll('.shared-load-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const sessionId = btn.getAttribute('data-session-id');
        await window.loadSharedSession(sessionId);
      });
    });
    listEl.querySelectorAll('.hide-shared-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const id = String(btn.getAttribute('data-session-id'));
        const cur = (await chrome.storage.local.get('hiddenSharedSessions')).hiddenSharedSessions || [];
        if (!cur.includes(id)) cur.push(id);
        await chrome.storage.local.set({ hiddenSharedSessions: cur });
        await loadSharedSessions();
      });
    });
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
      console.log('DEBUG: Received session data:', sessionData);

      if (!response.ok) {
        throw new Error(sessionData.error || 'Failed to load shared session');
      }

      showStatus(`Importing ${sessionData.cookies.length} cookies...`, 'info');

      let successCount = 0;
      let errorCount = 0;

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

          await chrome.cookies.set(cookieDetails);
          successCount++;
        } catch (cookieError) {
          console.error('Cookie import failed:', cookie.name, cookieError);
          errorCount++;
        }
      }

      if (successCount > 0) {
        showStatus(`Shared session loaded! ${successCount} cookies imported${errorCount > 0 ? ` (${errorCount} failed)` : ''}`, 'success');
        
        // Set up the timer if expiration info is available
        if (sessionData.expiresAt) {
          console.log('DEBUG: Setting up timer with expiresAt:', sessionData.expiresAt);
          const expiresAt = new Date(sessionData.expiresAt);
          const autoLogoutTime = expiresAt.getTime();
          const importTime = Date.now();
          
          console.log('DEBUG: Timer setup - autoLogoutTime:', autoLogoutTime, 'importTime:', importTime, 'difference:', autoLogoutTime - importTime);
          
          // Store active session with timer information
          const activeSession = {
            domain: sessionData.domain,
            url: sessionData.url,
            cookies: sessionData.cookies,
            autoLogoutTime: autoLogoutTime,
            importTime: importTime,
            originalExpiration: autoLogoutTime,
            expirationMinutes: sessionData.expirationMinutes || 60
          };
          
          console.log('DEBUG: Storing activeSession:', activeSession);
          await chrome.storage.local.set({ activeSession });
          
          // Set up background alarm for auto-logout
          chrome.runtime.sendMessage({
            action: 'setAutoLogoutAlarm',
            delayInMinutes: Math.ceil((autoLogoutTime - importTime) / (60 * 1000))
          });
          
          // Start the timer display
          console.log('DEBUG: Calling checkActiveSession to start timer...');
          await checkActiveSession();
        } else {
          console.log('DEBUG: No expiresAt found in sessionData:', sessionData);
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

  async function showApproveRequestModal(requestId) {
    // Get the request details first
    try {
      const response = await fetch(`${API_BASE}/access-requests/incoming`, {
        headers: {
          'Authorization': `Bearer ${currentUser.token}`
        }
      });

      const requests = await response.json();
      const request = requests.find(r => r.id == requestId);
      
      if (!request) {
        showStatus('Request not found', 'error');
        return;
      }

      // Populate the modal with request details
      approveRequesterEmailInput.value = request.requesteremail;
      approveDomainInput.value = request.domain;
      approveMessageInput.value = request.message || 'No message provided';
      
      // Show requested duration
      const requestedMinutes = request.requested_expiration_minutes || 60;
      let requestedDurationText = '';
      if (requestedMinutes < 60) {
        requestedDurationText = `${requestedMinutes} minutes`;
      } else if (requestedMinutes < 1440) {
        requestedDurationText = `${Math.round(requestedMinutes / 60)} hours`;
      } else {
        requestedDurationText = `${Math.round(requestedMinutes / 1440)} days`;
      }
      
      const requestedDurationSpan = document.getElementById('requestedDuration');
      if (requestedDurationSpan) {
        requestedDurationSpan.textContent = requestedDurationText;
      }
      
      // Store the request ID for later use
      approveRequestModal.setAttribute('data-request-id', requestId);
      
      // Show the modal
      approveRequestModal.style.display = 'flex';
      
    } catch (error) {
      console.error('Error loading request details:', error);
      showStatus('Failed to load request details', 'error');
    }
  }

  function hideApproveRequestModal() {
    approveRequestModal.style.display = 'none';
    // Reset form
    approveRequesterEmailInput.value = '';
    approveDomainInput.value = '';
    approveMessageInput.value = '';
    // Reset radio buttons to default (1 hour)
    document.getElementById('approveExp1hour').checked = true;
    document.getElementById('approveCustomTimeDiv').style.display = 'none';
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
            From: ${request.requesterEmail || '-'}<br>
            Received: ${formatDate(request.created_at || request.responded_at)}<br>
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
          <button class="btn btn-secondary delete-access-request-btn" data-request-id="${request.id}">Delete</button>
        </div>
      `;
      
      manageRequestsList.appendChild(requestItem);
    });

    // Attach event listeners to approve/deny buttons
    const approveBtns = manageRequestsList.querySelectorAll('.approve-btn');
    const denyBtns = manageRequestsList.querySelectorAll('.deny-btn');
    const deleteBtns = manageRequestsList.querySelectorAll('.delete-access-request-btn');

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

    deleteBtns.forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        const requestId = btn.getAttribute('data-request-id');
        await handleDeleteAccessRequest(requestId);
      });
    });
  }

  async function handleApproveRequest(requestId) {
    // Show the approve modal instead of immediately approving
    await showApproveRequestModal(requestId);
  }

  async function handleDenyRequest(requestId) {
    try {
      showStatus('Denying request...', 'info');
      
      const response = await fetch(`${API_BASE}/access-requests/${requestId}/deny`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
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
      if (error.message.includes('Failed to fetch')) {
        showStatus('Cannot connect to server. Please check if the backend is running.', 'error');
      } else {
        showStatus('Deny failed: ' + error.message, 'error');
      }
    }
  }

  async function handleDeleteAccessRequest(requestId) {
    try {
      if (!confirm('Delete this request?')) return;
      showStatus('Deleting request...', 'info');
      let response = await fetch(`${API_BASE}/access-requests/${requestId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${currentUser.token}`,
          'Cache-Control': 'no-cache'
        }
      });
      // Fallback if DELETE endpoint is not available
      if (!response.ok && response.status === 404) {
        response = await fetch(`${API_BASE}/access-requests/${requestId}/delete`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${currentUser.token}`,
            'Cache-Control': 'no-cache'
          }
        });
      }
      const data = await response.json().catch(() => ({}));
      if (response.ok) {
        showStatus(data.message || 'Request deleted', 'success');
        await loadIncomingRequests();
      } else {
        showStatus(data.error || `Delete failed (${response.status})`, 'error');
      }
    } catch (error) {
      console.error('Delete request error:', error);
      showStatus('Delete failed: ' + error.message, 'error');
    }
  }

  // Utility: robust date formatter for timestamps from backend
  function formatDate(input) {
    if (!input) return '-';
    const tryParse = (v) => { const d = new Date(v); return isNaN(d.getTime()) ? null : d; };
    let d = tryParse(input);
    if (!d && typeof input === 'string') {
      const iso = input.includes('T') ? input : input.replace(' ', 'T');
      d = tryParse(/Z|[\+\-]\d{2}:?\d{2}$/.test(iso) ? iso : iso + 'Z');
    }
    return d ? d.toLocaleDateString() : '-';
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
        displayFriendsDropdown(friends);
      } else {
        console.error('Failed to load friends:', friends.error);
        friendsList.innerHTML = '<div class="no-friends">Failed to load friends</div>';
        displayFriendsDropdown([]);
      }
    } catch (error) {
      console.error('Load friends error:', error);
      friendsList.innerHTML = '<div class="no-friends">Error loading friends</div>';
      displayFriendsDropdown([]);
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

  // Also render the lightweight friends dropdown in Friends tab
  function displayFriendsDropdown(friends) {
    const wrap = document.getElementById('friendsDropdownList');
    const badge = document.getElementById('friendsCountBadge');
    if (!wrap || !badge) return;
    wrap.innerHTML = '';
    const list = Array.isArray(friends) ? friends : [];
    badge.textContent = String(list.length);
    if (list.length === 0) {
      wrap.innerHTML = '<div class="no-friends">No friends yet. Add some friends to start sharing sessions!</div>';
      return;
    }
    list.forEach(f => {
      const email = f.friendemail || f.email || 'Unknown';
      const initial = email.charAt(0).toUpperCase();
      const row = document.createElement('div');
      row.className = 'friend-row';
      row.innerHTML = `
        <div style="display:flex; align-items:center; min-width:0;">
          <span class="avatar">${initial}</span>
          <div style="min-width:0;">
            <div class="friend-name">${email}</div>
            <div class="meta">Friend</div>
          </div>
        </div>
        <div>
          <button class="btn btn-sm btn-outline" data-email="${email}">Message</button>
        </div>`;
      wrap.appendChild(row);
    });
  }

  // Tab switching
  const tabBtnSessions = document.getElementById('tabBtnSessions');
  const tabBtnShared = document.getElementById('tabBtnShared');
  const tabBtnFriends = document.getElementById('tabBtnFriends');
  const tabSessions = document.getElementById('tabSessions');
  const tabShared = document.getElementById('tabShared');
  const tabFriends = document.getElementById('tabFriends');

  function setActiveTab(name) {
    [tabBtnSessions, tabBtnShared, tabBtnFriends].forEach(b => b && b.classList.remove('active'));
    [tabSessions, tabShared, tabFriends].forEach(c => c && c.classList.remove('active'));
    [tabSessions, tabShared, tabFriends].forEach(c => { if (c) c.style.display = 'none'; });
    if (name === 'sessions' && tabSessions) {
      tabBtnSessions && tabBtnSessions.classList.add('active');
      tabSessions.classList.add('active');
      tabSessions.style.display = 'block';
    } else if (name === 'shared' && tabShared) {
      tabBtnShared && tabBtnShared.classList.add('active');
      tabShared.classList.add('active');
      tabShared.style.display = 'block';
      loadSharedSessions();
    } else if (name === 'friends' && tabFriends) {
      tabBtnFriends && tabBtnFriends.classList.add('active');
      tabFriends.classList.add('active');
      tabFriends.style.display = 'block';
      loadFriends();
    }
  }

  if (tabBtnSessions && tabBtnShared && tabBtnFriends) {
    tabBtnSessions.addEventListener('click', () => setActiveTab('sessions'));
    tabBtnShared.addEventListener('click', () => setActiveTab('shared'));
    tabBtnFriends.addEventListener('click', () => setActiveTab('friends'));
  }
  const mainTabs = document.getElementById('mainTabs');
  if (mainTabs) {
    mainTabs.addEventListener('click', (e) => {
      const btn = e.target.closest('.tab-btn');
      if (!btn) return;
      const tab = btn.dataset.tab || (btn.id === 'tabBtnShared' ? 'shared' : btn.id === 'tabBtnFriends' ? 'friends' : 'sessions');
      setActiveTab(tab);
    });
  }
  // Extra safety: delegate on document as well in case events don't bubble to #mainTabs
  document.addEventListener('click', (e) => {
    const btn = e.target.closest && e.target.closest('.tab-btn');
    if (!btn) return;
    const tab = btn.dataset.tab || (btn.id === 'tabBtnShared' ? 'shared' : btn.id === 'tabBtnFriends' ? 'friends' : 'sessions');
    setActiveTab(tab);
  });
  // Ensure default tab state
  setActiveTab('sessions');

  // Kick off initialization (after listeners are bound)
  try {
    await init();
  } catch (e) {
    console.error('Init error:', e);
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
