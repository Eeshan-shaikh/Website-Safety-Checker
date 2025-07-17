// Background script for URL Safety Checker

// Base URL for API - replace with your application URL after deployment
const API_BASE_URL = window.location.origin || 'https://your-app-url.replit.app';

// Endpoints
const CHECK_URL_ENDPOINT = '/api/check-url';

// Cache for URL check results (to avoid repeated API calls)
const urlCache = new Map();

// Function to check a URL's safety
async function checkUrlSafety(url) {
  try {
    // Check cache first
    if (urlCache.has(url)) {
      const cachedResult = urlCache.get(url);
      
      // Only use cache if it's recent (less than 30 minutes old)
      const cacheAge = Date.now() - cachedResult.timestamp;
      if (cacheAge < 30 * 60 * 1000) { // 30 minutes in milliseconds
        return cachedResult.data;
      }
    }
    
    // Make API request
    const response = await fetch(`${API_BASE_URL}${CHECK_URL_ENDPOINT}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    });
    
    if (!response.ok) {
      throw new Error(`API request failed with status ${response.status}`);
    }
    
    const data = await response.json();
    
    // Cache the result
    urlCache.set(url, {
      data,
      timestamp: Date.now()
    });
    
    return data;
  } catch (error) {
    console.error('Error checking URL safety:', error);
    return { 
      error: true, 
      message: 'Failed to check URL safety. Please try again later.' 
    };
  }
}

// Handle messages from popup and content scripts
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'checkUrl') {
    // Use async function to check URL
    checkUrlSafety(message.url)
      .then(result => {
        sendResponse(result);
      })
      .catch(error => {
        console.error('Error in checkUrl action:', error);
        sendResponse({ 
          error: true, 
          message: 'An error occurred while checking the URL' 
        });
      });
    
    // Return true to indicate we will send a response asynchronously
    return true;
  }
});

// Check URL safety when navigating to a new page
chrome.webNavigation?.onBeforeNavigate?.addListener(async (details) => {
  // Only check main frame navigations (not iframes, etc.)
  if (details.frameId !== 0) return;
  
  // Get the URL being navigated to
  const url = details.url;
  
  // Skip checking for non-HTTP URLs
  if (!url.startsWith('http')) return;
  
  // Skip checking for the API URL itself to avoid infinite loops
  if (url.startsWith(API_BASE_URL)) return;
  
  try {
    // Check the safety of the URL
    const result = await checkUrlSafety(url);
    
    // If the URL is unsafe and the result indicates a high threat level,
    // send a message to the content script to show a warning
    if (result && !result.is_safe && 
        (result.threat_level === 'High' || result.threat_level === 'Critical')) {
        
      // Get the tab that's navigating
      const tab = await chrome.tabs.get(details.tabId);
      
      // Check if we should warn based on user preferences
      const shouldWarn = await getShouldWarnPreference(url);
      
      if (shouldWarn) {
        // Send message to show warning in the content script
        chrome.tabs.sendMessage(details.tabId, {
          action: 'showWarning',
          data: result
        });
      }
    }
  } catch (error) {
    console.error('Error checking URL during navigation:', error);
  }
});

// Helper function to check if we should warn based on user preferences
async function getShouldWarnPreference(url) {
  try {
    // Extract domain
    const domain = new URL(url).hostname;
    
    // Check if the user has chosen to ignore warnings for this domain
    const key = `ignored_warning_${domain}`;
    const result = await chrome.storage.local.get(key);
    
    // If user has chosen to ignore, don't warn
    if (result[key]) {
      return false;
    }
    
    // Get global protection level setting (default to high)
    const settings = await chrome.storage.local.get('protection_level');
    const protectionLevel = settings.protection_level || 'high';
    
    // Always warn on high protection
    return true;
  } catch (error) {
    console.error('Error getting warning preferences:', error);
    // Default to warning if there's an error
    return true;
  }
}