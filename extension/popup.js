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
        body: JSON.stringify({ email: shareEmail })
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