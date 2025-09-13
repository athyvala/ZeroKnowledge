// Background service worker for Session Sharer
// Handles background tasks including auto-logout functionality

chrome.runtime.onInstalled.addListener(() => {
  console.log('Session Sharer extension installed');
});

// Handle alarm for auto-logout
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
      chrome.notifications.create('sessionExpired', {
        type: 'basic',
        iconUrl: 'icon128.png', // You'll need to add an icon
        title: 'Session Expired',
        message: `You have been logged out of ${session.domain}`,
        priority: 2
      });
      
      console.log('Session cleared for domain:', session.domain);
    }
  }
});

// Check for expired sessions on startup
chrome.runtime.onStartup.addListener(async () => {
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
});

// Handle any background cookie operations if needed
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
});