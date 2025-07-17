// Confirm before clearing history
function confirmClearHistory() {
    return confirm("Are you sure you want to clear your URL check history? This action cannot be undone.");
}

// Initialize tooltips, popovers, and UI behaviors
document.addEventListener('DOMContentLoaded', function() {
    // Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Bootstrap popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Add copy to clipboard functionality
    document.querySelectorAll('.copy-url').forEach(function(button) {
        button.addEventListener('click', function() {
            var url = this.getAttribute('data-url');
            navigator.clipboard.writeText(url).then(function() {
                // Show tooltip or notification
                var tooltip = new bootstrap.Tooltip(button, {
                    title: 'Copied!',
                    trigger: 'manual'
                });
                tooltip.show();
                setTimeout(function() {
                    tooltip.hide();
                }, 1000);
            });
        });
    });
    
    // URL input validation
    validateURLInput();
    
    // Auto-fill URL input from the query parameter
    const urlParams = new URLSearchParams(window.location.search);
    const urlParam = urlParams.get('url');
    if (urlParam) {
        const urlInput = document.getElementById('url-input');
        if (urlInput) {
            urlInput.value = urlParam;
            // Switch to single URL tab if URL parameter is present
            const singleCheckTab = document.getElementById('single-check-tab');
            if (singleCheckTab) {
                const tabInstance = new bootstrap.Tab(singleCheckTab);
                tabInstance.show();
            }
        }
    }
    
    // Bulk URL textarea validation
    const bulkUrlsTextarea = document.getElementById('bulk-urls');
    if (bulkUrlsTextarea) {
        const bulkSubmitBtn = bulkUrlsTextarea.closest('form').querySelector('button[type="submit"]');
        
        bulkUrlsTextarea.addEventListener('input', function() {
            if (bulkUrlsTextarea.value.trim() === '') {
                bulkSubmitBtn.disabled = true;
            } else {
                bulkSubmitBtn.disabled = false;
            }
        });
        
        // Initial check
        if (bulkUrlsTextarea.value.trim() === '') {
            bulkSubmitBtn.disabled = true;
        }
    }
    
    // Add animation to results section
    const resultSection = document.querySelector('.card.threat-card');
    if (resultSection) {
        resultSection.classList.add('animate__animated', 'animate__fadeIn');
    }
    
    // Add "check again" functionality to history items
    document.querySelectorAll('.history-check-again').forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const url = this.getAttribute('data-url');
            const urlInput = document.getElementById('url-input');
            if (urlInput) {
                urlInput.value = url;
                // Switch to the single check tab
                const singleCheckTab = document.getElementById('single-check-tab');
                if (singleCheckTab) {
                    const tabInstance = new bootstrap.Tab(singleCheckTab);
                    tabInstance.show();
                }
                // Scroll to the input
                urlInput.scrollIntoView({ behavior: 'smooth' });
                // Focus on the input
                urlInput.focus();
            }
        });
    });
});

// Validate URL format in the input field
function validateURLInput() {
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
        const submitButton = urlInput.closest('form').querySelector('button[type="submit"]');
        
        urlInput.addEventListener('input', function() {
            if (urlInput.value.trim() === '') {
                submitButton.disabled = true;
            } else {
                submitButton.disabled = false;
            }
        });
        
        // Initial check
        if (urlInput.value.trim() === '') {
            submitButton.disabled = true;
        }
    }
}

// Handle tab switching
function switchTab(tabId) {
    const tab = document.getElementById(tabId);
    if (tab) {
        const tabInstance = new bootstrap.Tab(tab);
        tabInstance.show();
    }
}
