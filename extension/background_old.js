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