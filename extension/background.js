// Background service worker for Session Manager
// Handles background tasks including auto-logout functionality and session expiration

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('Session Manager extension installed');
    
    // Set default settings
    chrome.storage.local.set({
      settings: {
        autoSync: false,
        syncInterval: 300000, // 5 minutes
        maxSessions: 50
      }
    });
  } else if (details.reason === 'update') {
    console.log('Session Manager extension updated');
  }
});

// Handle alarm for auto-logout and session expiration
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'autoLogout') {
    console.log('Auto-logout timer triggered');
    
    // Get the active session
    const result = await chrome.storage.local.get('activeSession');
    
    if (result.activeSession) {
      const session = result.activeSession;
      
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
          
          console.log('Removed cookie:', cookie.name);
        } catch (error) {
          console.error('Failed to remove cookie:', cookie.name, error);
        }
      }
      
      // Clear the stored session
      await chrome.storage.local.remove('activeSession');
      
      // Show notification if permission is granted
      try {
        await chrome.notifications.create('sessionExpired', {
          type: 'basic',
          iconUrl: 'icons/icon128.png',
          title: 'Session Expired',
          message: `You have been logged out of ${session.domain}`,
          priority: 2
        });
      } catch (notifError) {
        console.log('Notification permission not granted or error:', notifError);
      }
      
      console.log('Session cleared for domain:', session.domain);
    }
  }
  
  // Handle periodic cleanup of expired shared sessions
  if (alarm.name === 'cleanupExpiredSessions') {
    console.log('Running periodic cleanup of expired sessions');
    await cleanupExpiredSharedSessions();
  }
});

// Check for expired sessions on startup
chrome.runtime.onStartup.addListener(async () => {
  console.log('Session Manager extension started');
  
  const result = await chrome.storage.local.get('activeSession');
  
  if (result.activeSession) {
    const session = result.activeSession;
    const now = Date.now();
    
    if (now >= session.autoLogoutTime) {
      // Session already expired, clean it up
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
          console.error('Failed to remove expired cookie:', error);
        }
      }
      
      await chrome.storage.local.remove('activeSession');
      chrome.alarms.clear('autoLogout');
    } else {
      // Reset the alarm for remaining time
      const minutesRemaining = Math.ceil((session.autoLogoutTime - now) / (60 * 1000));
      chrome.alarms.create('autoLogout', { 
        delayInMinutes: minutesRemaining 
      });
    }
  }
  
  // Set up periodic cleanup (every 30 minutes)
  chrome.alarms.create('cleanupExpiredSessions', {
    delayInMinutes: 30,
    periodInMinutes: 30
  });
});

// Cleanup expired shared sessions
async function cleanupExpiredSharedSessions() {
  try {
    const { currentUser } = await chrome.storage.local.get('currentUser');
    if (!currentUser) return;
    
    const API_BASE = 'http://localhost:3000/api'; // Should match popup.js
    
    const response = await fetch(`${API_BASE}/sessions/cleanup-expired`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${currentUser.token}`
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('Cleanup completed:', data);
    }
  } catch (error) {
    console.error('Error during cleanup:', error);
  }
}

// Optional: Auto-sync functionality (can be enabled in settings)
let syncInterval = null;

chrome.storage.local.get(['settings', 'user'], (result) => {
  if (result.settings?.autoSync && result.user?.token) {
    startAutoSync(result.settings.syncInterval || 300000);
  }
});

function startAutoSync(interval) {
  if (syncInterval) {
    clearInterval(syncInterval);
  }
  
  syncInterval = setInterval(async () => {
    try {
      // Get current active tab
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0]) {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;
        
        // Only sync if on a valid domain (not chrome:// pages etc.)
        if (domain && !domain.startsWith('chrome') && !domain.startsWith('moz-extension')) {
          // This would trigger a background sync
          // Implementation would depend on your specific needs
          console.log('Auto-sync trigger for domain:', domain);
        }
      }
    } catch (error) {
      console.error('Auto-sync error:', error);
    }
  }, interval);
}

function stopAutoSync() {
  if (syncInterval) {
    clearInterval(syncInterval);
    syncInterval = null;
  }
}

// Listen for storage changes to update auto-sync settings
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (namespace === 'local') {
    if (changes.settings?.newValue?.autoSync) {
      chrome.storage.local.get(['user'], (result) => {
        if (result.user?.token) {
          startAutoSync(changes.settings.newValue.syncInterval || 300000);
        }
      });
    } else if (changes.settings?.newValue?.autoSync === false) {
      stopAutoSync();
    }
    
    // Stop auto-sync if user logs out
    if (changes.user && !changes.user.newValue) {
      stopAutoSync();
    }
  }
});

// Handle any background cookie operations and new expiration features
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getCookies') {
    chrome.cookies.getAll({ domain: request.domain }, (cookies) => {
      sendResponse({ cookies: cookies });
    });
    return true; // Keep message channel open for async response
  }
  
  if (request.action === 'setCookies') {
    const promises = request.cookies.map(cookie => {
      return new Promise((resolve) => {
        chrome.cookies.set(cookie, (result) => {
          resolve(result);
        });
      });
    });
    
    Promise.all(promises).then(results => {
      sendResponse({ success: true, results: results });
    });
    return true;
  }
  
  if (request.action === 'checkActiveSession') {
    chrome.storage.local.get('activeSession', (result) => {
      sendResponse({ activeSession: result.activeSession });
    });
    return true;
  }
  
  // Set auto-logout alarm
  if (request.action === 'setAutoLogoutAlarm') {
    chrome.alarms.create('autoLogout', { 
      delayInMinutes: request.delayInMinutes 
    });
    sendResponse({ success: true });
    return true;
  }
  
  // Clear auto-logout alarm
  if (request.action === 'clearAutoLogoutAlarm') {
    chrome.alarms.clear('autoLogout');
    sendResponse({ success: true });
    return true;
  }
  
  // Revoke domain access (clear cookies for revoked sessions)
  if (request.action === 'revokeDomainAccess') {
    revokeDomainAccess(request.domain, request.cookies).then(() => {
      sendResponse({ success: true });
    }).catch(error => {
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }
  
  // Start/stop auto-sync
  if (request.action === 'startAutoSync') {
    startAutoSync(request.interval);
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'stopAutoSync') {
    stopAutoSync();
    sendResponse({ success: true });
    return true;
  }
  
  if (request.action === 'getStatus') {
    sendResponse({ 
      autoSyncActive: syncInterval !== null,
      extensionActive: true 
    });
    return true;
  }
});

// Revoke access by clearing cookies for a specific domain
async function revokeDomainAccess(domain, cookiesToRemove) {
  console.log(`Revoking access to ${domain}, removing ${cookiesToRemove.length} cookies`);
  
  for (const cookie of cookiesToRemove) {
    try {
      let cookieDomain = cookie.domain;
      if (cookieDomain.startsWith('.') && cookieDomain.length > 1) {
        cookieDomain = cookieDomain.substring(1);
      }
      
      const protocol = cookie.secure ? 'https://' : 'http://';
      const cookieUrl = protocol + cookieDomain + cookie.path;
      
      await chrome.cookies.remove({
        url: cookieUrl,
        name: cookie.name
      });
      
      console.log('Removed revoked cookie:', cookie.name);
    } catch (error) {
      console.error('Failed to remove revoked cookie:', cookie.name, error);
    }
  }
  
  // Show notification about revocation
  try {
    await chrome.notifications.create('accessRevoked', {
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Access Revoked',
      message: `Your access to ${domain} has been revoked`,
      priority: 1
    });
  } catch (notifError) {
    console.log('Notification permission not granted or error:', notifError);
  }
}