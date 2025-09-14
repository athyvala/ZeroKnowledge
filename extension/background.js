// Background service worker for Session Sharer
// This handles any background tasks if needed

chrome.runtime.onInstalled.addListener(() => {
  console.log('Session Sharer extension installed');
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
});