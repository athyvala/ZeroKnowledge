document.addEventListener('DOMContentLoaded', async () => {
  const exportBtn = document.getElementById('exportBtn');
  const importBtn = document.getElementById('importBtn');
  const fileInput = document.getElementById('fileInput');
  const status = document.getElementById('status');
  const domainEl = document.getElementById('currentDomain');
  
  // AI elements
  const aiToggle = document.getElementById('aiToggle');
  const aiStatus = document.getElementById('aiStatus');
  const testAiBtn = document.getElementById('testAiBtn');

  let currentTab = null;
  let currentDomain = '';

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

  // Initialize AI status with retry logic
  await initializeAIStatusWithRetry();

  // Helper function to send message with retry and better error handling
  async function sendMessageWithRetry(message, maxRetries = 5) {
    for (let i = 0; i < maxRetries; i++) {
      try {
        console.log(`Attempt ${i + 1}: Sending message:`, message);
        const response = await chrome.tabs.sendMessage(currentTab.id, message);
        console.log('Response received:', response);
        return response;
      } catch (error) {
        console.warn(`Attempt ${i + 1} failed:`, error.message);
        
        if (i === maxRetries - 1) {
          throw error;
        }
        
        // Progressive backoff: wait longer each time
        const waitTime = (i + 1) * 500;
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }
  }

  // AI Toggle
  aiToggle.addEventListener('change', async () => {
    try {
      await chrome.storage.local.set({ aiEnabled: aiToggle.checked });
      
      try {
        const response = await sendMessageWithRetry({
          action: 'toggleAI',
          enabled: aiToggle.checked
        });
        
        if (response && response.success) {
          updateAIStatus(aiToggle.checked ? 'enabled' : 'disabled');
          showStatus(`AI Protection ${aiToggle.checked ? 'enabled' : 'disabled'}`, 'success');
        } else {
          showStatus('AI toggle partially successful (settings saved)', 'warning');
        }
      } catch (error) {
        console.error('Failed to communicate with content script:', error);
        showStatus('AI setting saved - please refresh the page to activate', 'warning');
      }
    } catch (error) {
      console.error('Failed to save AI setting:', error);
      showStatus('Failed to save AI setting', 'error');
    }
  });

  // Test AI button
  testAiBtn.addEventListener('click', async () => {
    try {
      showStatus('Testing AI on current page...', 'info');
      testAiBtn.disabled = true;
      
      const response = await sendMessageWithRetry({
        action: 'testAI'
      });
      
      if (response) {
        const { maskedCount, status: aiStatusInfo } = response;
        showStatus(`AI Test Complete: ${maskedCount || 0} items masked`, 'success');
        if (aiStatusInfo) {
          updateAIStatusFromInfo(aiStatusInfo);
        }
      } else {
        showStatus('AI test completed but no response received', 'warning');
      }
    } catch (error) {
      console.error('AI test failed:', error);
      showStatus('AI test failed - content script may not be ready. Try refreshing the page.', 'error');
    } finally {
      testAiBtn.disabled = false;
    }
  });

  async function initializeAIStatusWithRetry() {
    try {
      // Load AI enabled state
      const result = await chrome.storage.local.get(['aiEnabled']);
      aiToggle.checked = result.aiEnabled !== false; // Default to true
      
      // Try to get AI status from content script with retry
      try {
        const response = await sendMessageWithRetry({
          action: 'getAIStatus'
        }, 3); // Only 3 retries for initial status
        
        if (response) {
          updateAIStatusFromInfo(response);
          
          // If there's an error in the response, show it
          if (response.error) {
            showStatus(`AI Status: ${response.error}`, 'warning');
          }
        } else {
          updateAIStatus('initializing');
        }
      } catch (error) {
        console.warn('Content script communication failed:', error);
        updateAIStatus('loading');
        
        // Show helpful message with more detail
        if (error.message.includes('Receiving end does not exist')) {
          showStatus('Content script not loaded - refresh the page to activate AI protection', 'warning');
        } else {
          showStatus('Extension loading - refresh page if needed', 'info');
        }
      }
    } catch (error) {
      console.error('Failed to initialize AI status:', error);
      updateAIStatus('error');
    }
  }

  function updateAIStatusFromInfo(statusInfo) {
    if (statusInfo.loading) {
      updateAIStatus('loading');
    } else if (!statusInfo.enabled) {
      updateAIStatus('disabled');
    } else if (statusInfo.modelLoaded) {
      updateAIStatus('online');
    } else if (statusInfo.error) {
      updateAIStatus('error');
    } else {
      updateAIStatus('patterns-only');
    }
  }

  function updateAIStatus(status) {
    const indicator = aiStatus.querySelector('.status-indicator');
    const text = aiStatus.querySelector('span');
    
    switch (status) {
      case 'online':
        indicator.className = 'status-indicator status-online';
        text.textContent = 'AI Protection Active (Enhanced)';
        break;
      case 'patterns-only':
        indicator.className = 'status-indicator status-online';
        text.textContent = 'AI Protection Active (Pattern-based)';
        break;
      case 'loading':
        indicator.className = 'status-indicator status-loading';
        text.textContent = 'Loading AI model...';
        break;
      case 'disabled':
        indicator.className = 'status-indicator status-offline';
        text.textContent = 'AI Protection Disabled';
        break;
      case 'error':
        indicator.className = 'status-indicator status-offline';
        text.textContent = 'AI Protection Error';
        break;
      default:
        indicator.className = 'status-indicator status-loading';
        text.textContent = 'Initializing...';
    }
  }

  // Export session (existing code - unchanged)
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

      const sessionData = {
        domain: currentDomain,
        url: currentTab.url,
        cookies: uniqueCookies,
        timestamp: Date.now(),
        expires: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
        userAgent: navigator.userAgent,
        aiProtection: aiToggle.checked // Include AI protection status
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

      showStatus(`Session exported! (${uniqueCookies.length} cookies)`, 'success');
      
    } catch (error) {
      console.error('Export error:', error);
      showStatus('Export failed: ' + error.message, 'error');
    }
  });

  // Import session (existing code - unchanged)
  importBtn.addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      showStatus('Reading session file...', 'info');
      
      const text = await file.text();
      const sessionData = JSON.parse(text);

      // Validate session data
      if (!sessionData.domain || !sessionData.cookies || !Array.isArray(sessionData.cookies)) {
        throw new Error('Invalid session file format');
      }

      // Check if expired
      if (sessionData.expires && Date.now() > sessionData.expires) {
        throw new Error('Session has expired');
      }

      // Show AI protection status if available
      if (sessionData.aiProtection) {
        showStatus(`Importing ${sessionData.cookies.length} cookies for ${sessionData.domain} (AI Protected)`, 'info');
      } else {
        showStatus(`Importing ${sessionData.cookies.length} cookies for ${sessionData.domain}`, 'info');
      }

      let successCount = 0;
      let errorCount = 0;

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
          await chrome.cookies.set(cookieDetails);
          successCount++;
        } catch (cookieError) {
          console.error('Cookie import failed:', cookie.name, cookieError.message, cookie);
          errorCount++;
        }
      }

      if (successCount > 0) {
        showStatus(`Session imported! ${successCount} cookies loaded${errorCount > 0 ? ` (${errorCount} failed)` : ''}`, 'success');
        
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