// Popup script for URL Safety Checker extension

// DOM elements
const urlInput = document.getElementById('urlInput');
const checkButton = document.getElementById('checkButton');
const loadingElement = document.getElementById('loading');
const resultElement = document.getElementById('result');
const dashboardLink = document.getElementById('dashboardLink');

// Set the dashboard link to the main app
dashboardLink.addEventListener('click', () => {
  chrome.tabs.create({ url: 'https://your-app-url.replit.app/dashboard' });
});

// Function to handle URL checking
async function checkUrl() {
  const url = urlInput.value.trim();
  
  // Validate URL input
  if (!url) {
    showError('Please enter a URL to check');
    return;
  }
  
  // Add http:// prefix if missing
  let normalizedUrl = url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    normalizedUrl = 'http://' + url;
  }
  
  // Show loading state
  loadingElement.style.display = 'block';
  resultElement.style.display = 'none';
  
  // Request URL safety check from background script
  chrome.runtime.sendMessage(
    { action: 'checkUrl', url: normalizedUrl },
    handleResponse
  );
}

// Function to handle the API response
function handleResponse(response) {
  // Hide loading state
  loadingElement.style.display = 'none';
  
  // Handle error cases
  if (!response || response.error) {
    showError(response?.message || 'Failed to check URL safety. Please try again.');
    return;
  }
  
  // Format and display the result
  showResult(response);
}

// Function to show error message
function showError(message) {
  resultElement.className = 'result unsafe';
  resultElement.innerHTML = `<p style="color: #dc3545"><strong>Error:</strong> ${message}</p>`;
  resultElement.style.display = 'block';
}

// Function to display the result
function showResult(data) {
  // Determine result class based on safety
  const resultClass = data.is_safe ? 'safe' : 'unsafe';
  const scoreColor = getScoreColor(data.reputation_score);
  
  // Build result HTML
  let resultHTML = `
    <h3 style="margin-top: 0;">${data.is_safe ? '✅ URL appears to be safe' : '⚠️ URL may be unsafe'}</h3>
    <p><strong>URL:</strong> ${data.url}</p>
    
    <div class="score-container">
      <div class="info-row">
        <span>Safety Score:</span>
        <strong style="color: ${scoreColor}">${data.reputation_score}/100</strong>
      </div>
      <div class="progress-bar">
        <div class="progress-value" style="width: ${data.reputation_score}%; background-color: ${scoreColor}"></div>
      </div>
    </div>
    
    <div class="info-row">
      <span>Threat Level:</span>
      <strong style="color: ${getThreatLevelColor(data.threat_level)}">${data.threat_level}</strong>
    </div>
  `;
  
  // Add threat information if available
  if (data.threats && data.threats.length > 0) {
    resultHTML += '<div class="threats"><h4>Detected Threats:</h4>';
    
    data.threats.forEach(threat => {
      resultHTML += `
        <div class="threat-item">
          <div class="threat-title" style="color: ${getSeverityColor(threat.severity)}">
            ${threat.type} (${threat.severity} Risk)
          </div>
          <p style="margin: 0;">${threat.description}</p>
        </div>
      `;
    });
    
    resultHTML += '</div>';
  }
  
  // Set the result
  resultElement.className = `result ${resultClass}`;
  resultElement.innerHTML = resultHTML;
  resultElement.style.display = 'block';
}

// Helper function to get color for safety score
function getScoreColor(score) {
  if (score >= 80) return '#28a745'; // Green
  if (score >= 60) return '#ffc107'; // Yellow
  return '#dc3545'; // Red
}

// Helper function to get color for threat level
function getThreatLevelColor(level) {
  switch (level) {
    case 'Low': return '#28a745'; // Green
    case 'Medium': return '#ffc107'; // Yellow
    case 'High': return '#dc3545'; // Red
    case 'Critical': return '#721c24'; // Dark red
    default: return '#6c757d'; // Gray
  }
}

// Helper function to get color for severity
function getSeverityColor(severity) {
  switch (severity) {
    case 'Low': return '#17a2b8'; // Blue
    case 'Medium': return '#ffc107'; // Yellow
    case 'High': return '#dc3545'; // Red
    default: return '#6c757d'; // Gray
  }
}

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
  // Set up button click handler
  checkButton.addEventListener('click', checkUrl);
  
  // Allow pressing Enter in input field
  urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') checkUrl();
  });
  
  // Get the current tab's URL and fill in the input
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0 && tabs[0].url) {
      urlInput.value = tabs[0].url;
      
      // Check the current tab's URL automatically
      checkUrl();
    }
  } catch (error) {
    console.error('Error getting current tab:', error);
  }
});