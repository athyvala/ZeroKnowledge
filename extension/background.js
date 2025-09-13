// Background script for Session Manager extension

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

// Handle extension startup
chrome.runtime.onStartup.addListener(() => {
  console.log('Session Manager extension started');
});

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
          console.log('Auto-sync triggered for domain:', domain);
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

// Handle messages from popup or content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case 'startAutoSync':
      if (request.interval) {
        startAutoSync(request.interval);
        sendResponse({ success: true });
      }
      break;
      
    case 'stopAutoSync':
      stopAutoSync();
      sendResponse({ success: true });
      break;
      
    case 'getStatus':
      sendResponse({ 
        autoSyncActive: syncInterval !== null,
        extensionActive: true 
      });
      break;
      
    default:
      sendResponse({ error: 'Unknown action' });
  }
  
  return true; // Keep message channel open for async response
});

// background.js - Handles auto-logout functionality
chrome.runtime.onInstalled.addListener(() => {
  console.log('Session Manager extension installed');
});

// Handle alarm events for auto-logout
chrome.alarms.onAlarm.addListener(async (alarm) => {
  console.log('Alarm triggered:', alarm.name);
  
  if (alarm.name === 'autoLogout') {
    await performAutoLogout();
  }
});

// Handle messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Background received message:', request);
  
  if (request.action === 'setAutoLogoutAlarm') {
    chrome.alarms.create('autoLogout', { 
      delayInMinutes: request.delayInMinutes 
    });
    console.log(`Auto-logout alarm set for ${request.delayInMinutes} minutes`);
    sendResponse({ success: true });
  } else if (request.action === 'clearAutoLogoutAlarm') {
    chrome.alarms.clear('autoLogout');
    console.log('Auto-logout alarm cleared');
    sendResponse({ success: true });
  }
  
  return true; // Will respond asynchronously
});

// Perform auto-logout when alarm triggers
async function performAutoLogout() {
  console.log('Performing auto-logout...');
  
  try {
    // Get active session info
    const result = await chrome.storage.local.get('activeSession');
    
    if (result.activeSession) {
      const session = result.activeSession;
      console.log('Clearing active session for domain:', session.domain);
      
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
      
      // Clear the active session from storage
      await chrome.storage.local.remove('activeSession');
      console.log('Active session cleared from storage');
      
      // Show notification to user
      if (chrome.notifications) {
        chrome.notifications.create('sessionExpired', {
          type: 'basic',
          iconUrl: 'icon48.png', // Make sure you have this icon file
          title: 'Session Expired',
          message: `Your imported session for ${session.domain} has expired and you have been automatically logged out.`
        });
      }
      
    } else {
      console.log('No active session found');
    }
    
  } catch (error) {
    console.error('Error during auto-logout:', error);
  }
}

// Clean up expired sessions on startup
chrome.runtime.onStartup.addListener(async () => {
  console.log('Extension starting up, checking for expired sessions...');
  
  try {
    // Check for expired active session
    const result = await chrome.storage.local.get('activeSession');
    if (result.activeSession) {
      const session = result.activeSession;
      if (session.autoLogoutTime && Date.now() > session.autoLogoutTime) {
        console.log('Found expired active session, cleaning up...');
        await performAutoLogout();
      } else if (session.autoLogoutTime) {
        // Session is still valid, set up alarm for remaining time
        const minutesUntilLogout = Math.ceil((session.autoLogoutTime - Date.now()) / (60 * 1000));
        if (minutesUntilLogout > 0) {
          chrome.alarms.create('autoLogout', { 
            delayInMinutes: minutesUntilLogout 
          });
          console.log(`Re-established auto-logout alarm for ${minutesUntilLogout} minutes`);
        }
      }
    }
    
    // Clean up expired offline sessions
    const offlineResult = await chrome.storage.local.get(['offlineSessions']);
    if (offlineResult.offlineSessions) {
      const offlineSessions = offlineResult.offlineSessions;
      const now = Date.now();
      let hasExpiredSessions = false;
      
      for (const [id, session] of Object.entries(offlineSessions)) {
        if (session.autoLogoutTime && now > session.autoLogoutTime) {
          console.log(`Cleaning up expired offline session: ${session.domain}`);
          delete offlineSessions[id];
          hasExpiredSessions = true;
        }
      }
      
      if (hasExpiredSessions) {
        await chrome.storage.local.set({ offlineSessions });
        console.log('Cleaned up expired offline sessions');
      }
    }
    
  } catch (error) {
    console.error('Error during startup cleanup:', error);
  }
});

// Handle notification clicks
if (chrome.notifications) {
  chrome.notifications.onClicked.addListener((notificationId) => {
    if (notificationId === 'sessionExpired') {
      // Close the notification
      chrome.notifications.clear(notificationId);
    }
  });
}

// Periodic cleanup of expired sessions (every 5 minutes)
// Periodic cleanup of expired sessions (every 1 minute)
chrome.alarms.create('periodicCleanup', { periodInMinutes: 1 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'periodicCleanup') {
    await cleanupExpiredSessions();
  }
});

async function cleanupExpiredSessions() {
  try {
    // Clean up expired offline sessions
    const result = await chrome.storage.local.get(['offlineSessions', 'sharedSessions']);
    const now = Date.now();

    // Consistent expiration logic: compare expiration as UTC ISO string (matches popup.js/server.js)
    if (result.offlineSessions) {
      const offlineSessions = result.offlineSessions;
      let hasExpiredSessions = false;
      for (const [id, session] of Object.entries(offlineSessions)) {
        if (session.autoLogoutTime && now > session.autoLogoutTime) {
          delete offlineSessions[id];
          hasExpiredSessions = true;
        }
      }
      if (hasExpiredSessions) {
        await chrome.storage.local.set({ offlineSessions });
        console.log('Periodic cleanup: Removed expired offline sessions');
      }
    }

    // Clean up expired shared sessions
    if (result.sharedSessions) {
      const sharedSessions = result.sharedSessions;
      let hasExpiredShared = false;
      for (const [id, session] of Object.entries(sharedSessions)) {
        // Consistent with popup.js/server.js: expiration is ISO string, compare as UTC
        if (session.expiration && Date.parse(session.expiration) < now) {
          // Delete all cookies for the domain
          try {
            const cookies = await chrome.cookies.getAll({ domain: session.domain });
            for (const cookie of cookies) {
              let cookieDomain = cookie.domain;
              if (cookieDomain.startsWith('.')) {
                cookieDomain = cookieDomain.substring(1);
              }
              const protocol = cookie.secure ? 'https://' : 'http://';
              const cookieUrl = protocol + cookieDomain + cookie.path;
              await chrome.cookies.remove({ url: cookieUrl, name: cookie.name });
            }
            console.log(`Deleted cookies for expired shared session: ${session.domain}`);
          } catch (err) {
            console.error('Error deleting cookies for expired shared session:', session.domain, err);
          }
          // Remove session from sharedSessions
          delete sharedSessions[id];
          hasExpiredShared = true;
        }
      }
      if (hasExpiredShared) {
        await chrome.storage.local.set({ sharedSessions });
        console.log('Periodic cleanup: Removed expired shared sessions');
      }
    }

    // Check if active session has expired
    const activeResult = await chrome.storage.local.get('activeSession');
    if (activeResult.activeSession) {
      const session = activeResult.activeSession;
      if (session.autoLogoutTime && now > session.autoLogoutTime) {
        console.log('Periodic cleanup: Active session expired, performing logout');
        await performAutoLogout();
      }
    }
  } catch (error) {
    console.error('Error during periodic cleanup:', error);
  }
}

// Handle tab updates to check for domain changes
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Only proceed if the URL has changed and it's a complete load
  if (changeInfo.status === 'complete' && changeInfo.url) {
    try {
      const result = await chrome.storage.local.get('activeSession');
      if (result.activeSession) {
        const session = result.activeSession;
        const newUrl = new URL(tab.url);
        const newDomain = newUrl.hostname;
        
        // If user navigated away from the session domain, show warning
        if (session.domain !== newDomain && 
            !newDomain.endsWith('.' + session.domain) && 
            !session.domain.endsWith('.' + newDomain)) {
          
          if (chrome.notifications) {
            chrome.notifications.create('domainWarning', {
              type: 'basic',
              iconUrl: 'icon48.png',
              title: 'Session Domain Changed',
              message: `You have an active session for ${session.domain} but are now on ${newDomain}. The session will remain active.`
            });
          }
        }
      }
    } catch (error) {
      // Ignore errors from invalid URLs or other tab update issues
      console.log('Tab update check error (non-critical):', error.message);
    }
  }
});