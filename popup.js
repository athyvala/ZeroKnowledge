document.addEventListener('DOMContentLoaded', async () => {
  const exportBtn = document.getElementById('exportBtn');
  const importBtn = document.getElementById('importBtn');
  const fileInput = document.getElementById('fileInput');
  const status = document.getElementById('status');
  const domainEl = document.getElementById('currentDomain');
  const activeSessionDiv = document.getElementById('activeSession');
  const sessionDomainEl = document.getElementById('sessionDomain');
  const sessionTimerEl = document.getElementById('sessionTimer');
  const clearSessionBtn = document.getElementById('clearSessionBtn');
  const customTimeDiv = document.getElementById('customTimeDiv');
  const customValueInput = document.getElementById('customValue');
  const customUnitSelect = document.getElementById('customUnit');

  let currentTab = null;
  let currentDomain = '';
  let timerInterval = null;

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

  // Check for active imported sessions
  checkActiveSession();

  // Handle expiration radio buttons
  document.querySelectorAll('input[name="expiration"]').forEach(radio => {
    radio.addEventListener('change', (e) => {
      if (e.target.value === 'custom') {
        customTimeDiv.style.display = 'flex';
      } else {
        customTimeDiv.style.display = 'none';
      }
    });
  });

  // Get selected expiration time in minutes
  function getExpirationMinutes() {
    const selected = document.querySelector('input[name="expiration"]:checked');
    if (selected.value === 'custom') {
      const value = parseInt(customValueInput.value);
      const unit = customUnitSelect.value;
      
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

  // Export session
  exportBtn.addEventListener('click', async () => {
    try {
      showStatus('Extracting cookies...', 'info');
      
      // Get cookies in multiple ways to catch all variations
      let allCookies = [];
      
      // Method 1: Exact domain
      const exactDomainCookies = await chrome.cookies.getAll({ domain: currentDomain });
      allCookies = allCookies.concat(exactDomainCookies);
      
      // Method 2: With leading dot (for subdomain cookies)
      const dotDomainCookies = await chrome.cookies.getAll({ domain: '.' + currentDomain });
      allCookies = allCookies.concat(dotDomainCookies);
      
      // Method 3: Get all cookies for the URL
      const urlCookies = await chrome.cookies.getAll({ url: currentTab.url });
      allCookies = allCookies.concat(urlCookies);
      
      // Method 4: Check common subdomains
      const subdomains = ['www.' + currentDomain, 'm.' + currentDomain];
      for (const subdomain of subdomains) {
        try {
          const subCookies = await chrome.cookies.getAll({ domain: subdomain });
          allCookies = allCookies.concat(subCookies);
        } catch (e) {
          // Ignore errors for subdomains that don't exist
        }
      }
      
      // Remove duplicates based on name+domain+path
      const uniqueCookies = [];
      const seen = new Set();
      
      for (const cookie of allCookies) {
        const key = `${cookie.name}|${cookie.domain}|${cookie.path}`;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueCookies.push(cookie);
        }
      }
      
      console.log('Found cookies:', uniqueCookies);
      
      if (uniqueCookies.length === 0) {
        showStatus('No cookies found for this domain. Try refreshing the page first.', 'error');
        return;
      }

      const expirationMinutes = getExpirationMinutes();
      const expirationTime = Date.now() + (expirationMinutes * 60 * 1000);

      const sessionData = {
        domain: currentDomain,
        url: currentTab.url,
        cookies: uniqueCookies,
        timestamp: Date.now(),
        autoLogoutAfter: expirationMinutes, // in minutes
        autoLogoutTime: expirationTime, // absolute timestamp
        userAgent: navigator.userAgent,
        version: '2.0' // Version to track feature compatibility
      };

      // Create and download file
      const blob = new Blob([JSON.stringify(sessionData, null, 2)], {
        type: 'application/json'
      });
      
      const downloadUrl = URL.createObjectURL(blob);
      const filename = `${currentDomain}_session_${new Date().getTime()}.session`;
      
      await chrome.downloads.download({
        url: downloadUrl,
        filename: filename,
        saveAs: true
      });

      const hours = Math.floor(expirationMinutes / 60);
      const mins = expirationMinutes % 60;
      const timeStr = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
      
      showStatus(`Session exported! (${uniqueCookies.length} cookies, expires in ${timeStr})`, 'success');
      
    } catch (error) {
      console.error('Export error:', error);
      showStatus('Export failed: ' + error.message, 'error');
    }
  });

  // Import session
  importBtn.addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      showStatus('Reading session file...', 'info');
      
      const text = await file.text();
      let sessionData;
      
      try {
        sessionData = JSON.parse(text);
      } catch (parseError) {
        console.error('JSON parse error:', parseError);
        throw new Error('Invalid JSON in session file');
      }
      
      console.log('Imported session data:', sessionData);

      // Validate session data
      if (!sessionData.domain || !sessionData.cookies || !Array.isArray(sessionData.cookies)) {
        console.error('Missing required fields:', {
          hasDomain: !!sessionData.domain,
          hasCookies: !!sessionData.cookies,
          cookiesIsArray: Array.isArray(sessionData.cookies)
        });
        throw new Error('Invalid session file format');
      }

      // Check if session has auto-logout time and if it's expired
      if (sessionData.autoLogoutTime) {
        const now = Date.now();
        if (now > sessionData.autoLogoutTime) {
          const expiredMins = Math.floor((now - sessionData.autoLogoutTime) / 60000);
          throw new Error(`Session expired ${expiredMins} minutes ago`);
        }
        const remainingMins = Math.floor((sessionData.autoLogoutTime - now) / 60000);
        console.log(`Session has ${remainingMins} minutes remaining`);
      }

      showStatus(`Importing ${sessionData.cookies.length} cookies for ${sessionData.domain}...`, 'info');

      let successCount = 0;
      let errorCount = 0;
      const importedCookies = [];

      // Import each cookie
      for (const cookie of sessionData.cookies) {
        try {
          // Create the cookie URL - handle domain variations
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

          // Handle domain properly
          if (cookie.domain.startsWith('.')) {
            cookieDetails.domain = cookie.domain;
          } else {
            cookieDetails.domain = cookie.domain;
          }

          // Set expiration if not a session cookie
          if (!cookie.session && cookie.expirationDate) {
            cookieDetails.expirationDate = cookie.expirationDate;
          }

          console.log('Setting cookie:', cookieDetails);
          const result = await chrome.cookies.set(cookieDetails);
          if (result) {
            importedCookies.push(cookie);
            successCount++;
          } else {
            throw new Error('Cookie.set returned null');
          }
        } catch (cookieError) {
          console.error('Cookie import failed:', cookie.name, cookieError.message, cookie);
          errorCount++;
        }
      }

      if (successCount > 0) {
        showStatus(`Session imported! ${successCount} cookies loaded${errorCount > 0 ? ` (${errorCount} failed)` : ''}`, 'success');
        
        // Store session info for auto-logout (only if autoLogoutTime exists and is valid)
        if (sessionData.autoLogoutTime && sessionData.autoLogoutTime > Date.now()) {
          const sessionInfo = {
            domain: sessionData.domain,
            cookies: importedCookies,
            autoLogoutTime: sessionData.autoLogoutTime,
            importTime: Date.now()
          };
          
          await chrome.storage.local.set({ 
            activeSession: sessionInfo 
          });
          
          // Set up auto-logout alarm - check if chrome.alarms is available
          const minutesUntilLogout = Math.ceil((sessionData.autoLogoutTime - Date.now()) / (60 * 1000));
          if (minutesUntilLogout > 0) {
            try {
              if (chrome.alarms) {
                await chrome.alarms.clear('autoLogout'); // Clear any existing alarm first
                await chrome.alarms.create('autoLogout', { 
                  delayInMinutes: minutesUntilLogout 
                });
                console.log(`Auto-logout alarm set for ${minutesUntilLogout} minutes`);
              } else {
                console.warn('Chrome alarms API not available');
                // Send message to background script to set the alarm
                chrome.runtime.sendMessage({
                  action: 'setAutoLogoutAlarm',
                  delayInMinutes: minutesUntilLogout
                });
              }
            } catch (alarmError) {
              console.error('Error setting alarm:', alarmError);
              // Continue anyway - session is imported but auto-logout might not work
            }
            
            // Show active session indicator
            checkActiveSession();
          }
        } else if (!sessionData.version || sessionData.version !== '2.0') {
          // Handle old format sessions without auto-logout
          console.log('Imported legacy session without auto-logout feature');
        }
        
        // Optionally navigate to the domain
        setTimeout(() => {
          chrome.tabs.update(currentTab.id, { url: sessionData.url || `https://${sessionData.domain}` });
        }, 1000);
      } else {
        throw new Error('Failed to import any cookies');
      }

    } catch (error) {
      console.error('Import error:', error);
      showStatus('Import failed: ' + error.message, 'error');
    }

    // Reset file input
    fileInput.value = '';
  });

  // Check for active imported session
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

  // Update session timer display
  function updateSessionTimer(logoutTime) {
    const now = Date.now();
    const remaining = logoutTime - now;
    
    if (remaining <= 0) {
      sessionTimerEl.textContent = 'Expiring...';
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
    
    sessionTimerEl.textContent = timeStr;
  }

  // Clear imported session
  async function clearImportedSession() {
    const result = await chrome.storage.local.get('activeSession');
    
    if (result.activeSession) {
      const session = result.activeSession;
      
      showStatus('Clearing imported session...', 'info');
      
      // Delete all imported cookies
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
      
      // Try to clear alarm - wrapped in try-catch
      try {
        if (chrome.alarms) {
          await chrome.alarms.clear('autoLogout');
        } else {
          // Send message to background to clear alarm
          chrome.runtime.sendMessage({ action: 'clearAutoLogoutAlarm' });
        }
      } catch (alarmError) {
        console.error('Error clearing alarm:', alarmError);
      }
      
      // Hide active session indicator
      activeSessionDiv.style.display = 'none';
      if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
      }
      
      showStatus('Session cleared - you have been logged out', 'success');
    }
  }

  // Clear session button
  clearSessionBtn.addEventListener('click', async () => {
    if (confirm('Are you sure you want to end this session? This will log you out of the imported session.')) {
      await clearImportedSession();
    }
  });

  function showStatus(message, type) {
    status.textContent = message;
    status.className = `status ${type}`;
    status.style.display = 'block';
    
    if (type == 'success') {  // Changed from === to ==
      setTimeout(() => {
        status.style.display = 'none';
      }, 3000);
    }
  }
});