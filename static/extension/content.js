// Content script for URL Safety Checker

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'showWarning') {
    showSafetyWarning(message.data);
  }
});

// Function to create and display a safety warning overlay
function showSafetyWarning(safetyData) {
  // Check if a warning overlay already exists
  if (document.getElementById('url-safety-warning-overlay')) {
    return;
  }
  
  // Save the original content of the page
  const originalContent = document.body.innerHTML;
  
  // Create the warning overlay
  const overlay = document.createElement('div');
  overlay.id = 'url-safety-warning-overlay';
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: #f44336;
    color: white;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    z-index: 999999;
    padding: 2rem;
    font-family: Arial, sans-serif;
    text-align: center;
  `;
  
  // Prepare threat information
  let threatInfo = '';
  if (safetyData.threats && safetyData.threats.length > 0) {
    threatInfo = '<ul style="text-align: left; max-width: 600px; margin: 0 auto;">';
    safetyData.threats.forEach(threat => {
      threatInfo += `<li><strong>${threat.type}:</strong> ${threat.description}</li>`;
    });
    threatInfo += '</ul>';
  }
  
  // Create content for the warning
  overlay.innerHTML = `
    <div style="max-width: 800px;">
      <h1 style="font-size: 2rem; margin-bottom: 1rem;">⚠️ Warning: Potentially Unsafe Website</h1>
      <p style="font-size: 1.2rem; margin-bottom: 1.5rem;">
        Our URL Safety Checker has detected that this website might be unsafe to visit.
      </p>
      <div style="background-color: rgba(0,0,0,0.2); padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem;">
        <p><strong>URL:</strong> ${safetyData.url}</p>
        <p><strong>Safety Score:</strong> ${safetyData.reputation_score}/100</p>
        <p><strong>Threat Level:</strong> ${safetyData.threat_level}</p>
        ${threatInfo ? `<h3>Detected Threats:</h3>${threatInfo}` : ''}
      </div>
      <div style="display: flex; justify-content: center; gap: 1rem;">
        <button id="safety-back-button" style="padding: 0.75rem 1.5rem; background-color: white; color: #111; border: none; border-radius: 4px; font-weight: bold; cursor: pointer;">
          Go Back (Recommended)
        </button>
        <button id="safety-proceed-button" style="padding: 0.75rem 1.5rem; background-color: transparent; color: white; border: 2px solid white; border-radius: 4px; font-weight: bold; cursor: pointer;">
          Proceed Anyway (Not Recommended)
        </button>
      </div>
    </div>
  `;
  
  // Add to the page
  document.body.innerHTML = '';
  document.body.appendChild(overlay);
  
  // Add event listeners for the buttons
  document.getElementById('safety-back-button').addEventListener('click', () => {
    window.history.back();
  });
  
  document.getElementById('safety-proceed-button').addEventListener('click', () => {
    // Remove the overlay and restore the original content
    overlay.remove();
    document.body.innerHTML = originalContent;
    
    // Store the user's decision for this domain
    const domain = new URL(safetyData.url).hostname;
    chrome.storage.local.set({
      [`ignored_warning_${domain}`]: true
    });
  });
}

// Check if there are any unsafe links on the page and add visual indicators
function checkPageLinks() {
  // Get all links on the page
  const links = document.querySelectorAll('a[href]');
  
  // Skip if no links
  if (links.length === 0) return;
  
  // Batch process links
  const urlsToCheck = Array.from(links)
    .map(link => link.href)
    .filter(url => url.startsWith('http')); // Only check HTTP/HTTPS URLs
  
  // Skip if no valid URLs to check
  if (urlsToCheck.length === 0) return;
  
  // Deduplicate URLs
  const uniqueUrls = [...new Set(urlsToCheck)];
  
  // Check the URLs in batches to avoid overwhelming the API
  const BATCH_SIZE = 10;
  for (let i = 0; i < uniqueUrls.length; i += BATCH_SIZE) {
    const batch = uniqueUrls.slice(i, i + BATCH_SIZE);
    
    // Check each URL in the batch
    batch.forEach(url => {
      chrome.runtime.sendMessage(
        { action: 'checkUrl', url },
        (result) => {
          if (!result || result.error) return;
          
          // Find all links with this URL and add indicators if unsafe
          if (!result.is_safe) {
            const unsafeLinks = document.querySelectorAll(`a[href="${url}"]`);
            unsafeLinks.forEach(link => {
              // Add a red border to indicate unsafe link
              link.style.border = '1px solid red';
              link.style.boxShadow = '0 0 5px rgba(255, 0, 0, 0.5)';
              
              // Add a warning tooltip
              link.title = `Warning: Potentially unsafe link (Score: ${result.reputation_score}/100)`;
              
              // Add a click handler to confirm before navigating
              link.addEventListener('click', (e) => {
                if (!confirm(`This link has been flagged as potentially unsafe with a score of ${result.reputation_score}/100. Do you want to proceed?`)) {
                  e.preventDefault();
                }
              });
              
              // Add a small warning icon
              const warningIcon = document.createElement('span');
              warningIcon.textContent = ' ⚠️';
              warningIcon.style.color = 'red';
              link.appendChild(warningIcon);
            });
          }
        }
      );
    });
  }
}

// Run the link checker after the page has loaded
window.addEventListener('load', () => {
  // Wait a bit for dynamic content to load before checking links
  setTimeout(checkPageLinks, 1500);
});