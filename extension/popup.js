// Updated extension popup script with account-based session sharing
// Helper function to format dates consistently
function formatDate(dateStr, includeTime = true) {
  if (!dateStr) return 'N/A';
  const options = {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
  };
  if (includeTime) {
    options.hour = '2-digit';
    options.minute = '2-digit';
  }
  return new Date(dateStr).toLocaleString('en-US', options);
}

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

    // Manage shares elements
    const manageSharesBtn = document.getElementById('manageSharesBtn');
    const manageSharesModal = document.getElementById('manageSharesModal');
    const manageSharesList = document.getElementById('manageSharesList');
    const closeManageSharesBtn = document.getElementById('closeManageSharesBtn');

  // Share session elements
  const shareSessionBtn = document.getElementById('shareSessionBtn');
  const shareModal = document.getElementById('shareModal');
  const shareEmailInput = document.getElementById('shareEmail');
  const shareexpirationInput = document.getElementById('shareexpiration');
  const confirmShareBtn = document.getElementById('confirmShareBtn');
  const cancelShareBtn = document.getElementById('cancelShareBtn');

  // Shared sessions elements
  const sharedSessionsBtn = document.getElementById('sharedSessionsBtn');
  const sharedSessionsModal = document.getElementById('sharedSessionsModal');
  const sharedSessionsList = document.getElementById('sharedSessionsList');
  const closeSharedModalBtn = document.getElementById('closeSharedModalBtn');

  // Friends elements
  const friendsBtn = document.getElementById('friendsBtn');
  const friendsModal = document.getElementById('friendsModal');
  const friendsList = document.getElementById('friendsList');
  const closeFriendsBtn = document.getElementById('closeFriendsBtn');

  // Access Request elements
  const requestAccessBtn = document.getElementById('requestAccessBtn');
  const requestAccessModal = document.getElementById('requestAccessModal');
  const requestDomainInput = document.getElementById('requestDomain');
  const requestMessage = document.getElementById('requestMessage');
  const confirmRequestBtn = document.getElementById('confirmRequestBtn');
  const cancelRequestBtn = document.getElementById('cancelRequestBtn');

  // View Requests elements
  const viewRequestsBtn = document.getElementById('viewRequestsBtn');
  const viewRequestsModal = document.getElementById('viewRequestsModal');
  const viewRequestsList = document.getElementById('viewRequestsList');
  const closeViewRequestsBtn = document.getElementById('closeViewRequestsBtn');

  // Manage Requests elements
  const manageRequestsBtn = document.getElementById('manageRequestsBtn');
  const manageRequestsModal = document.getElementById('manageRequestsModal');
  const manageRequestsList = document.getElementById('manageRequestsList');
  const closeManageRequestsBtn = document.getElementById('closeManageRequestsBtn');

  // Request Access from Friends elements
  const requestAccessFromFriendsModal = document.getElementById('requestAccessFromFriendsModal');
  const requestFromFriendsDomain = document.getElementById('requestFromFriendsDomain');
  const requestFromFriendsMessage = document.getElementById('requestFromFriendsMessage');
  const friendsWithSessionsList = document.getElementById('friendsWithSessionsList');
  const confirmRequestFromFriendsBtn = document.getElementById('confirmRequestFromFriendsBtn');
  const cancelRequestFromFriendsBtn = document.getElementById('cancelRequestFromFriendsBtn');
  const closeRequestAccessFromFriendsBtn = document.getElementById('closeRequestAccessFromFriendsBtn');

  // Add Friend elements
  const addFriendBtn = document.getElementById('addFriendBtn');
  const addFriendModal = document.getElementById('addFriendModal');
  const friendEmail = document.getElementById('friendEmail');
  const friendRequestMessage = document.getElementById('friendRequestMessage');
  const confirmAddFriendBtn = document.getElementById('confirmAddFriendBtn');
  const cancelAddFriendBtn = document.getElementById('cancelAddFriendBtn');

  // Friend Requests elements
  const friendRequestsBtn = document.getElementById('friendRequestsBtn');
  const friendRequestsModal = document.getElementById('friendRequestsModal');
  const closeFriendRequestsBtn = document.getElementById('closeFriendRequestsBtn');
  const incomingFriendRequestsTab = document.getElementById('incomingFriendRequestsTab');
  const outgoingFriendRequestsTab = document.getElementById('outgoingFriendRequestsTab');
  const incomingFriendRequestsList = document.getElementById('incomingFriendRequestsList');
  const outgoingFriendRequestsList = document.getElementById('outgoingFriendRequestsList');

  const API_BASE = 'http://localhost:3000/api'; // Replace with your server URL
  let currentTab = null;
  let currentDomain = '';
  let currentUser = null;

  // Initialize
  await init();

  async function init() {
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
            httpOnly: cookie.httpOnly
          };

          // Handle __Host- cookies specially - they cannot have a domain attribute
          if (!cookie.name.startsWith('__Host-')) {
            cookieDetails.domain = cookie.domain;
          }

          // Handle __Secure- and __Host- cookies - they must be secure
          if (cookie.name.startsWith('__Secure-') || cookie.name.startsWith('__Host-')) {
            cookieDetails.secure = true;
            // Use https for secure cookies
            cookieDetails.url = cookieUrl.replace('http://', 'https://');
          }

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
      const expirationValue = shareexpirationInput.value;
      let expiration = null;
      if (expirationValue) {
        expiration = new Date(expirationValue).toISOString();
      }
    
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
          body: JSON.stringify({ email: shareEmail, expiration: expiration })
        });

      const data = await response.json();

      if (response.ok) {
        showStatus('Session shared successfully!', 'success');
        hideShareModal();
          shareexpirationInput.value = '';
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
          option.textContent = `${session.domain} (${formatDate(session.created_at)})`;
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
      const sessionItem = document.createElement('div');
      sessionItem.className = 'shared-session-item';

      // Format expiration in EST
      // Timer logic
      let countdownId = `countdown-${session.id}`;
      let expiration = session.expiration;
      let expDate = expiration ? new Date(expiration) : null;

      sessionItem.innerHTML = `
        <div class="session-info">
          <div class="session-domain">${session.domain || 'Unknown domain'}</div>
          <div class="session-meta">
            Shared by: ${session.owneremail || 'Unknown'}<br>
            expiration: ${expiration ? formatDate(expiration) + ' EST' : 'No expiration'}<br>
            <span class="countdown" id="${countdownId}"></span>
          </div>
        </div>
        <div class="session-actions">
          <button class="btn btn-sm btn-primary shared-load-btn" data-session-id="${session.id}">
            Load Session
          </button>
          <button class="btn btn-sm btn-danger shared-delete-btn" data-session-id="${session.id}">
            Delete
          </button>
        </div>
      `;
      sharedSessionsList.appendChild(sessionItem);

      // Countdown timer
      if (expDate) {
        function updateCountdown() {
          const now = new Date();
          let diff = expDate - now;
          if (diff <= 0) {
            document.getElementById(countdownId).textContent = 'Expired';
            sessionItem.style.display = 'none'; // Hide expired
            return;
          }
          let hours = Math.floor(diff / (1000 * 60 * 60));
          let minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
          let seconds = Math.floor((diff % (1000 * 60)) / 1000);
          document.getElementById(countdownId).textContent = `Time left: ${hours}h ${minutes}m ${seconds}s`;
        }
        updateCountdown();
        setInterval(updateCountdown, 1000);
      }

      // Delete button event
      const deleteBtn = sessionItem.querySelector('.shared-delete-btn');
      if (deleteBtn) {
        deleteBtn.addEventListener('click', async () => {
          if (!confirm('Are you sure you want to remove your access to this shared session?')) return;
          try {
            const response = await fetch(`${API_BASE}/sessions/shared/${session.id}`, {
              method: 'DELETE',
              headers: {
                'Authorization': `Bearer ${currentUser.token}`
              }
            });
            const data = await response.json();
            if (response.ok) {
              showStatus('Access to shared session removed', 'success');
              sessionItem.style.display = 'none';
            } else {
              showStatus(data.error || 'Failed to remove access', 'error');
            }
          } catch (error) {
            showStatus('Error removing access to shared session', 'error');
          }
        });
      }
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
            httpOnly: cookie.httpOnly
          };

          // Handle __Host- cookies specially - they cannot have a domain attribute
          if (!cookie.name.startsWith('__Host-')) {
            cookieDetails.domain = cookie.domain;
          }

          // Handle __Secure- and __Host- cookies - they must be secure
          if (cookie.name.startsWith('__Secure-') || cookie.name.startsWith('__Host-')) {
            cookieDetails.secure = true;
            // Use https for secure cookies
            cookieDetails.url = cookieUrl.replace('http://', 'https://');
          }

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

    function showManageSharesModal() {
      manageSharesModal.style.display = 'flex';
    }

    function hideManageSharesModal() {
      manageSharesModal.style.display = 'none';
    }

  function showSharedSessionsModal() {
    sharedSessionsModal.style.display = 'flex';
  }

  function hideSharedSessionsModal() {
    sharedSessionsModal.style.display = 'none';
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

    // Manage Shares functionality
    manageSharesBtn.addEventListener('click', async () => {
      const sessionId = sessionsDropdown.value;
      if (!sessionId) {
        showStatus('Please select a session to manage shares', 'error');
        return;
      }
      showManageSharesModal();
      await loadSessionShares(sessionId);
    });

    closeManageSharesBtn.addEventListener('click', () => {
      hideManageSharesModal();
    });

    manageSharesModal.addEventListener('click', (e) => {
      if (e.target === manageSharesModal) {
        hideManageSharesModal();
      }
    });

    async function loadSessionShares(sessionId) {
      if (!currentUser) return;
      try {
        manageSharesList.innerHTML = '<div class="no-sessions">Loading shared users...</div>';
        const response = await fetch(`${API_BASE}/sessions/${sessionId}/shares`, {
          headers: {
            'Authorization': `Bearer ${currentUser.token}`
          }
        });
        const shares = await response.json();
        if (response.ok) {
          displaySessionShares(sessionId, shares);
        } else {
          manageSharesList.innerHTML = `<div class="no-sessions">${shares.error || 'Failed to load shared users'}</div>`;
        }
      } catch (error) {
        manageSharesList.innerHTML = `<div class="no-sessions">Error loading shared users</div>`;
      }
    }

    function displaySessionShares(sessionId, shares) {
      manageSharesList.innerHTML = '';
      if (!shares || !Array.isArray(shares) || shares.length === 0) {
        manageSharesList.innerHTML = '<div class="no-sessions">No users have access to this session</div>';
        return;
      }
      function toESTString(dateStr) {
        if (!dateStr) return '';
        return new Date(dateStr).toLocaleString('en-US', { timeZone: 'America/New_York', hour12: false });
      }

      function toDatetimeLocalValue(dateStr) {
        if (!dateStr) return '';
        const est = new Date(new Date(dateStr).toLocaleString('en-US', { timeZone: 'America/New_York' }));
        const pad = n => n.toString().padStart(2, '0');
        return `${est.getFullYear()}-${pad(est.getMonth()+1)}-${pad(est.getDate())}T${pad(est.getHours())}:${pad(est.getMinutes())}`;
      }

      shares.forEach((share, idx) => {
        const item = document.createElement('div');
        item.className = 'shared-session-item';
        const estSharedAt = toESTString(share.shared_at);
        const estexpiration = toESTString(share.expiration);
          item.innerHTML = `
            <div class="session-info">
              <div class="session-domain">${share.email}</div>
              <div class="session-meta">
                Shared at: ${estSharedAt || 'Unknown'} <span class="shared-at-est">EST</span><br>
                expiration: <input type="datetime-local" class="expiration-input" data-email="${share.email}" value="${share.expiration ? toDatetimeLocalValue(share.expiration) : ''}">
                <span class="expiration-est">(EST: ${estexpiration || 'N/A'})</span>
                <button class="btn btn-sm btn-outline update-expiration-btn" data-email="${share.email}" data-session-id="${sessionId}">Update</button>
              </div>
            </div>
            <div class="session-actions">
              <button class="btn btn-sm btn-danger revoke-share-btn" data-email="${share.email}" data-session-id="${sessionId}">Revoke</button>
            </div>
          `;
        manageSharesList.appendChild(item);
      });
      // Attach event listeners
      const revokeBtns = manageSharesList.querySelectorAll('.revoke-share-btn');
      revokeBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const email = btn.getAttribute('data-email');
          const sessionId = btn.getAttribute('data-session-id');
          if (!confirm(`Revoke access for ${email}?`)) return;
          await revokeSessionShare(sessionId, email);
          await loadSessionShares(sessionId);
        });
      });
        // Attach event listeners for expiration update
        const updateBtns = manageSharesList.querySelectorAll('.update-expiration-btn');
        updateBtns.forEach(btn => {
          btn.addEventListener('click', async (e) => {
            const email = btn.getAttribute('data-email');
            const sessionId = btn.getAttribute('data-session-id');
            const input = manageSharesList.querySelector(`.expiration-input[data-email='${email}']`);
            const expirationValue = input.value;
            if (!expirationValue) {
              showStatus('Please select an expiration date/time', 'error');
              return;
            }
            const expiration = new Date(expirationValue).toISOString();
            await updateSessionShareexpiration(sessionId, email, expiration);
            await loadSessionShares(sessionId);
          });
        });
    }

      async function updateSessionShareexpiration(sessionId, email, expiration) {
        try {
          showStatus(`Updating expiration for ${email}...`, 'info');
          const response = await fetch(`${API_BASE}/sessions/${sessionId}/share`, {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${currentUser.token}`
            },
            body: JSON.stringify({ email, expiration })
          });
          const data = await response.json();
          if (response.ok) {
            showStatus(`expiration updated for ${email}`, 'success');
          } else {
            showStatus(data.error || 'Failed to update expiration', 'error');
          }
        } catch (error) {
          showStatus('Error updating expiration', 'error');
        }
      }

    async function revokeSessionShare(sessionId, email) {
      try {
        showStatus(`Revoking access for ${email}...`, 'info');
        const response = await fetch(`${API_BASE}/sessions/${sessionId}/share`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${currentUser.token}`
          },
          body: JSON.stringify({ email })
        });
        const data = await response.json();
        if (response.ok) {
          showStatus(`Access revoked for ${email}`, 'success');
        } else {
          showStatus(data.error || 'Failed to revoke access', 'error');
        }
      } catch (error) {
        showStatus('Error revoking access', 'error');
      }
    }

    // Friends functionality
    friendsBtn.addEventListener('click', async () => {
      showFriendsModal();
      await loadFriendsList();
    });

    addFriendBtn.addEventListener('click', () => {
      showAddFriendModal();
    });

    friendRequestsBtn.addEventListener('click', async () => {
      showFriendRequestsModal();
      await loadFriendRequests();
    });

    closeFriendsBtn.addEventListener('click', () => {
      hideFriendsModal();
    });

    cancelAddFriendBtn.addEventListener('click', () => {
      hideAddFriendModal();
    });

    closeFriendRequestsBtn.addEventListener('click', () => {
      hideFriendRequestsModal();
    });

    // Tab switching in friend requests modal
    incomingFriendRequestsTab.addEventListener('click', () => {
      incomingFriendRequestsTab.classList.add('active');
      outgoingFriendRequestsTab.classList.remove('active');
      incomingFriendRequestsList.style.display = 'block';
      outgoingFriendRequestsList.style.display = 'none';
    });

    outgoingFriendRequestsTab.addEventListener('click', () => {
      outgoingFriendRequestsTab.classList.add('active');
      incomingFriendRequestsTab.classList.remove('active');
      outgoingFriendRequestsList.style.display = 'block';
      incomingFriendRequestsList.style.display = 'none';
    });

    // Send friend request
    confirmAddFriendBtn.addEventListener('click', async () => {
      const email = friendEmail.value.trim();
      const message = friendRequestMessage.value.trim();

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
          showStatus('Friend request sent successfully!', 'success');
          hideAddFriendModal();
          friendEmail.value = '';
          friendRequestMessage.value = '';
        } else {
          showStatus(data.error || 'Failed to send friend request', 'error');
        }
      } catch (error) {
        showStatus('Error sending friend request', 'error');
      }
    });

    // Load friends list
    async function loadFriendsList() {
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
          showStatus(friends.error || 'Failed to load friends list', 'error');
        }
      } catch (error) {
        showStatus('Error loading friends list', 'error');
      }
    }

    // Display friends
    function displayFriends(friends) {
      friendsList.innerHTML = '';

      if (!friends || !Array.isArray(friends) || friends.length === 0) {
        friendsList.innerHTML = '<div class="no-friends">No friends yet</div>';
        return;
      }

      friends.forEach(friend => {
        const friendItem = document.createElement('div');
        friendItem.className = 'friend-item';
        friendItem.innerHTML = `
          <div class="friend-info">
            <div class="friend-email">${friend.friendemail}</div>
            <div class="friend-meta">
              Friends since: ${formatDate(friend.friendssince, false)}
            </div>
          </div>
          <div class="friend-actions">
            <button class="btn btn-sm btn-danger remove-friend-btn" data-friend-id="${friend.friendid}">Remove</button>
          </div>
        `;
        friendsList.appendChild(friendItem);
      });

      // Add event listeners to remove buttons
      const removeBtns = friendsList.querySelectorAll('.remove-friend-btn');
      removeBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const friendId = btn.getAttribute('data-friend-id');
          if (!confirm('Are you sure you want to remove this friend?')) return;
          await removeFriend(friendId);
          await loadFriendsList();
        });
      });
    }

    // Load friend requests
    async function loadFriendRequests() {
      if (!currentUser) return;

      try {
        // Load incoming requests
        const incomingResponse = await fetch(`${API_BASE}/friends/requests/incoming`, {
          headers: {
            'Authorization': `Bearer ${currentUser.token}`
          }
        });
        const incomingRequests = await incomingResponse.json();

        // Load outgoing requests
        const outgoingResponse = await fetch(`${API_BASE}/friends/requests/outgoing`, {
          headers: {
            'Authorization': `Bearer ${currentUser.token}`
          }
        });
        const outgoingRequests = await outgoingResponse.json();

        displayIncomingFriendRequests(incomingRequests);
        displayOutgoingFriendRequests(outgoingRequests);
      } catch (error) {
        showStatus('Error loading friend requests', 'error');
      }
    }

    // Display incoming friend requests
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
              Sent: ${formatDate(request.created_at)}
            </div>
            <div class="request-message">${request.message || 'No message'}</div>
          </div>
          <div class="request-actions">
            <button class="btn btn-sm btn-success accept-request-btn" data-request-id="${request.id}">Accept</button>
            <button class="btn btn-sm btn-danger decline-request-btn" data-request-id="${request.id}">Decline</button>
          </div>
        `;
        incomingFriendRequestsList.appendChild(requestItem);
      });

      // Add event listeners to accept/decline buttons
      const acceptBtns = incomingFriendRequestsList.querySelectorAll('.accept-request-btn');
      const declineBtns = incomingFriendRequestsList.querySelectorAll('.decline-request-btn');

      acceptBtns.forEach(btn => {
        btn.addEventListener('click', async () => {
          const requestId = btn.getAttribute('data-request-id');
          await acceptFriendRequest(requestId);
          await loadFriendRequests();
        });
      });

      declineBtns.forEach(btn => {
        btn.addEventListener('click', async () => {
          const requestId = btn.getAttribute('data-request-id');
          await declineFriendRequest(requestId);
          await loadFriendRequests();
        });
      });
    }

    // Display outgoing friend requests
    function displayOutgoingFriendRequests(requests) {
      outgoingFriendRequestsList.innerHTML = '';

      if (!requests || !Array.isArray(requests) || requests.length === 0) {
        outgoingFriendRequestsList.innerHTML = '<div class="no-requests">No outgoing friend requests</div>';
        return;
      }

      requests.forEach(request => {
        const requestItem = document.createElement('div');
        requestItem.className = 'request-item';
        requestItem.innerHTML = `
          <div class="request-info">
            <div class="request-domain">${request.receiveremail}</div>
            <div class="request-meta">
              Sent: ${new Date(request.created_at).toLocaleDateString()}<br>
              Status: <span class="status-badge status-${request.status}">${request.status}</span>
            </div>
            <div class="request-message">${request.message || 'No message'}</div>
          </div>
        `;
        outgoingFriendRequestsList.appendChild(requestItem);
      });
    }

    // Accept friend request
    async function acceptFriendRequest(requestId) {
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
          showStatus('Friend request accepted!', 'success');
          await loadFriendsList();
        } else {
          showStatus(data.error || 'Failed to accept friend request', 'error');
        }
      } catch (error) {
        showStatus('Error accepting friend request', 'error');
      }
    }

    // Decline friend request
    async function declineFriendRequest(requestId) {
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
          showStatus('Friend request declined', 'success');
        } else {
          showStatus(data.error || 'Failed to decline friend request', 'error');
        }
      } catch (error) {
        showStatus('Error declining friend request', 'error');
      }
    }

    // Remove friend
    async function removeFriend(friendId) {
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
          showStatus('Friend removed successfully', 'success');
        } else {
          showStatus(data.error || 'Failed to remove friend', 'error');
        }
      } catch (error) {
        showStatus('Error removing friend', 'error');
      }
    }

    // Modal helper functions for friends features
    function showFriendsModal() {
      friendsModal.style.display = 'flex';
    }

    function hideFriendsModal() {
      friendsModal.style.display = 'none';
    }

    function showAddFriendModal() {
      addFriendModal.style.display = 'flex';
      friendEmail.focus();
    }

    function hideAddFriendModal() {
      addFriendModal.style.display = 'none';
      friendEmail.value = '';
      friendRequestMessage.value = '';
    }

    function showFriendRequestsModal() {
      friendRequestsModal.style.display = 'flex';
      // Always show incoming tab first
      incomingFriendRequestsTab.click();
    }

    function hideFriendRequestsModal() {
      friendRequestsModal.style.display = 'none';
    }

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

    // Access Request functionality
    requestAccessBtn.addEventListener('click', () => {
      requestDomainInput.value = currentDomain;
      showRequestAccessFromFriendsModal();
      loadFriendsWithSessions();
    });

    viewRequestsBtn.addEventListener('click', () => {
      showViewRequestsModal();
      loadOutgoingRequests();
    });

    manageRequestsBtn.addEventListener('click', () => {
      showManageRequestsModal();
      loadIncomingRequests();
    });

    // Modal close buttons
    cancelRequestBtn.addEventListener('click', () => {
      hideRequestAccessModal();
    });

    closeViewRequestsBtn.addEventListener('click', () => {
      hideViewRequestsModal();
    });

    closeManageRequestsBtn.addEventListener('click', () => {
      hideManageRequestsModal();
    });

    cancelRequestFromFriendsBtn.addEventListener('click', () => {
      hideRequestAccessFromFriendsModal();
    });

    closeRequestAccessFromFriendsBtn.addEventListener('click', () => {
      hideRequestAccessFromFriendsModal();
    });

    // Load friends with sessions for current domain
    async function loadFriendsWithSessions() {
      try {
        const friendsResponse = await fetch(`${API_BASE}/friends`, {
          headers: {
            'Authorization': `Bearer ${currentUser.token}`
          }
        });
        const friends = await friendsResponse.json();

        if (friendsResponse.ok) {
          displayFriendsWithSessions(friends);
        } else {
          showStatus(friends.error || 'Failed to load friends list', 'error');
        }
      } catch (error) {
        showStatus('Error loading friends list', 'error');
      }
    }

    function displayFriendsWithSessions(friends) {
      friendsWithSessionsList.innerHTML = '';

      if (!friends || !Array.isArray(friends) || friends.length === 0) {
        friendsWithSessionsList.innerHTML = '<div class="no-friends-with-sessions">No friends found</div>';
        return;
      }

      friends.forEach(friend => {
        const friendItem = document.createElement('div');
        friendItem.className = 'friend-selection-item';
        friendItem.innerHTML = `
          <input type="checkbox" id="friend-${friend.friendid}" value="${friend.friendid}">
          <div class="friend-selection-info">
            <div class="friend-selection-email">${friend.friendemail}</div>
          </div>
        `;
        friendsWithSessionsList.appendChild(friendItem);
      });
    }

    // Send access request to selected friends
    confirmRequestFromFriendsBtn.addEventListener('click', async () => {
      const selectedCheckboxes = friendsWithSessionsList.querySelectorAll('input[type="checkbox"]:checked');
      const selectedFriendIds = Array.from(selectedCheckboxes).map(cb => cb.value);

      if (selectedFriendIds.length === 0) {
        showStatus('Please select at least one friend', 'error');
        return;
      }

      const message = requestFromFriendsMessage.value.trim();
      const domain = requestFromFriendsDomain.value;

      try {
        showStatus('Sending access requests...', 'info');
        
        const promises = selectedFriendIds.map(friendId => 
          fetch(`${API_BASE}/access-requests`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${currentUser.token}`
            },
            body: JSON.stringify({
              domain,
              message,
              friendId
            })
          })
        );

        const responses = await Promise.all(promises);
        const results = await Promise.all(responses.map(r => r.json()));

        const successCount = results.filter(r => !r.error).length;
        if (successCount > 0) {
          showStatus(`Access requests sent to ${successCount} friend(s)!`, 'success');
          hideRequestAccessFromFriendsModal();
          requestFromFriendsMessage.value = '';
        } else {
          showStatus('Failed to send access requests', 'error');
        }
      } catch (error) {
        showStatus('Error sending access requests', 'error');
      }
    });

    // Load outgoing access requests
    async function loadOutgoingRequests() {
      try {
        const response = await fetch(`${API_BASE}/access-requests/outgoing`, {
          headers: {
            'Authorization': `Bearer ${currentUser.token}`
          }
        });

        const requests = await response.json();

        if (response.ok) {
          displayOutgoingRequests(requests);
        } else {
          showStatus(requests.error || 'Failed to load outgoing requests', 'error');
        }
      } catch (error) {
        showStatus('Error loading outgoing requests', 'error');
      }
    }

    // Display outgoing access requests
    function displayOutgoingRequests(requests) {
      viewRequestsList.innerHTML = '';

      if (!requests || !Array.isArray(requests) || requests.length === 0) {
        viewRequestsList.innerHTML = '<div class="no-requests">No outgoing access requests</div>';
        return;
      }

      requests.forEach(request => {
        const requestItem = document.createElement('div');
        requestItem.className = 'request-item';
        requestItem.innerHTML = `
          <div class="request-info">
            <div class="request-domain">${request.domain}</div>
            <div class="request-meta">
              Requested from: ${request.ownerEmail}<br>
              Sent: ${new Date(request.created_at).toLocaleDateString()}<br>
              Status: <span class="status-badge status-${request.status}">${request.status}</span>
            </div>
            <div class="request-message">${request.message || 'No message'}</div>
          </div>
        `;
        viewRequestsList.appendChild(requestItem);
      });
    }

    // Load incoming access requests
    async function loadIncomingRequests() {
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
          showStatus(requests.error || 'Failed to load incoming requests', 'error');
        }
      } catch (error) {
        showStatus('Error loading incoming requests', 'error');
      }
    }

    // Display incoming access requests
    function displayIncomingRequests(requests) {
      manageRequestsList.innerHTML = '';

      if (!requests || !Array.isArray(requests) || requests.length === 0) {
        manageRequestsList.innerHTML = '<div class="no-requests">No incoming access requests</div>';
        return;
      }

      requests.forEach(request => {
        const requestItem = document.createElement('div');
        requestItem.className = 'request-item';
        requestItem.innerHTML = `
          <div class="request-info">
            <div class="request-domain">${request.domain}</div>
            <div class="request-meta">
              From: ${request.requesteremail}<br>
              Requested: ${new Date(request.created_at).toLocaleDateString()}<br>
              Your sessions: ${request.sessioncount}
            </div>
            <div class="request-message">${request.message || 'No message'}</div>
          </div>
          <div class="request-actions">
            <button class="btn btn-sm btn-success approve-request-btn" data-request-id="${request.id}">Approve</button>
            <button class="btn btn-sm btn-danger deny-request-btn" data-request-id="${request.id}">Deny</button>
          </div>
        `;
        manageRequestsList.appendChild(requestItem);
      });

      // Add event listeners to approve/deny buttons
      const approveBtns = manageRequestsList.querySelectorAll('.approve-request-btn');
      const denyBtns = manageRequestsList.querySelectorAll('.deny-request-btn');

      approveBtns.forEach(btn => {
        btn.addEventListener('click', async () => {
          const requestId = btn.getAttribute('data-request-id');
          await approveAccessRequest(requestId);
          await loadIncomingRequests();
        });
      });

      denyBtns.forEach(btn => {
        btn.addEventListener('click', async () => {
          const requestId = btn.getAttribute('data-request-id');
          await denyAccessRequest(requestId);
          await loadIncomingRequests();
        });
      });
    }

    // Approve access request
    async function approveAccessRequest(requestId) {
      try {
        showStatus('Approving access request...', 'info');
        const response = await fetch(`${API_BASE}/access-requests/${requestId}/approve`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${currentUser.token}`
          }
        });

        const data = await response.json();

        if (response.ok) {
          showStatus(`Access request approved! ${data.sessionsShared} session(s) shared`, 'success');
        } else {
          showStatus(data.error || 'Failed to approve access request', 'error');
        }
      } catch (error) {
        showStatus('Error approving access request', 'error');
      }
    }

    // Deny access request
    async function denyAccessRequest(requestId) {
      try {
        showStatus('Denying access request...', 'info');
        const response = await fetch(`${API_BASE}/access-requests/${requestId}/deny`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${currentUser.token}`
          }
        });

        const data = await response.json();

        if (response.ok) {
          showStatus('Access request denied', 'success');
        } else {
          showStatus(data.error || 'Failed to deny access request', 'error');
        }
      } catch (error) {
        showStatus('Error denying access request', 'error');
      }
    }

    // Modal helper functions for access requests
    function showRequestAccessModal() {
      requestAccessModal.style.display = 'flex';
      requestDomainInput.value = currentDomain;
    }

    function hideRequestAccessModal() {
      requestAccessModal.style.display = 'none';
      requestMessage.value = '';
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

    function showRequestAccessFromFriendsModal() {
      requestAccessFromFriendsModal.style.display = 'flex';
      requestFromFriendsDomain.value = currentDomain;
    }

    function hideRequestAccessFromFriendsModal() {
      requestAccessFromFriendsModal.style.display = 'none';
      requestFromFriendsMessage.value = '';
    }

    // Click outside to close modals
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

    requestAccessFromFriendsModal.addEventListener('click', (e) => {
      if (e.target === requestAccessFromFriendsModal) {
        hideRequestAccessFromFriendsModal();
      }
    });
});