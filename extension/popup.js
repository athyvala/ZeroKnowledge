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