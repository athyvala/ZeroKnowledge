document.addEventListener('DOMContentLoaded', async () => {
  const exportBtn = document.getElementById('exportBtn');
  const importBtn = document.getElementById('importBtn');
  const fileInput = document.getElementById('fileInput');
  const status = document.getElementById('status');
  const domainEl = document.getElementById('currentDomain');

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

      const sessionData = {
        domain: currentDomain,
        url: currentTab.url,
        cookies: uniqueCookies,
        timestamp: Date.now(),
        expires: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
        userAgent: navigator.userAgent
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
      const sessionData = JSON.parse(text);

      // Validate session data
      if (!sessionData.domain || !sessionData.cookies || !Array.isArray(sessionData.cookies)) {
        throw new Error('Invalid session file format');
      }

      // Check if expired
      if (sessionData.expires && Date.now() > sessionData.expires) {
        throw new Error('Session has expired');
      }

      showStatus(`Importing ${sessionData.cookies.length} cookies for ${sessionData.domain}...`, 'info');

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