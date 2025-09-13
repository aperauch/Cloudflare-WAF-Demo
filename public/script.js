// Global state
let testStats = {
    total: 0,
    blocked: 0,
    allowed: 0
};

// DOM elements
const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');
const resultsSection = document.getElementById('results-section');
const resultCard = document.getElementById('result-card');

// Counter elements
const totalCounter = document.getElementById('total-counter');
const blockedCounter = document.getElementById('blocked-counter');
const allowedCounter = document.getElementById('allowed-counter');

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    initializeTabs();
    initializeForms();
    loadExamplePayloads();
    updateCounters();
});

// Tab functionality
function initializeTabs() {
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            switchTab(tabId);
        });
    });
}

function switchTab(tabId) {
    // Update tab buttons - remove active class and add it to clicked button
    tabButtons.forEach(btn => {
        btn.classList.remove('active');
        btn.classList.remove('bg-white', 'text-cf-blue', 'shadow-lg');
        btn.classList.add('bg-white/10', 'text-white');
    });
    const activeButton = document.querySelector(`[data-tab="${tabId}"]`);
    activeButton.classList.add('active');
    activeButton.classList.remove('bg-white/10', 'text-white');
    activeButton.classList.add('bg-white', 'text-cf-blue', 'shadow-lg');
    
    // Update tab content - hide all tabs and show selected one
    tabContents.forEach(content => {
        content.classList.add('hidden');
        content.classList.remove('block');
    });
    const activeTab = document.getElementById(tabId);
    activeTab.classList.remove('hidden');
    activeTab.classList.add('block');
    
    // Hide results when switching tabs
    resultsSection.style.display = 'none';
}

// Form initialization
function initializeForms() {
    // XSS Form
    const xssForm = document.getElementById('xss-form');
    xssForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const payload = document.getElementById('xss-payload').value;
        const context = document.getElementById('xss-context').value;
        testAttack('xss', { payload, context });
    });

    // SQL Injection Form
    const sqliForm = document.getElementById('sqli-form');
    sqliForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const payload = document.getElementById('sqli-payload').value;
        const type = document.getElementById('sqli-type').value;
        testAttack('sqli', { payload, type });
    });

    // RCE Form
    const rceForm = document.getElementById('rce-form');
    rceForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const payload = document.getElementById('rce-payload').value;
        const method = document.getElementById('rce-method').value;
        testAttack('rce', { payload, method });
    });
}

// Load example payloads into forms
function loadExamplePayloads() {
    const examples = {
        xss: [
            '<script>alert("XSS Test")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>',
            '"><script>alert("XSS")</script>'
        ],
        sqli: [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM users--",
            "admin'--",
            "1' OR 1=1#"
        ],
        rce: [
            '; ls -la',
            '$(whoami)',
            '`cat /etc/passwd`',
            '| id',
            '&& uname -a'
        ]
    };

    // Add click handlers to all code elements in example payload sections
    document.querySelectorAll('code').forEach(code => {
        // Check if this code element is in an example payloads section
        const isExamplePayload = code.closest('.space-y-3') && code.classList.contains('hover:bg-cf-blue');
        
        if (isExamplePayload) {
            code.addEventListener('click', () => {
                // Find the parent tab content to determine which tab we're in
                const tabContent = code.closest('.tab-content');
                const tabId = tabContent.id;
                const payloadField = document.getElementById(`${tabId}-payload`);
                if (payloadField) {
                    payloadField.value = code.textContent;
                    payloadField.focus();
                    // Add visual feedback
                    code.classList.add('bg-cf-blue', 'text-white');
                    setTimeout(() => {
                        code.classList.remove('bg-cf-blue', 'text-white');
                    }, 200);
                }
            });
        }
    });
}

// Test attack function
async function testAttack(attackType, data) {
    if (!data.payload.trim()) {
        showError('Please enter a payload to test');
        return;
    }

    const button = document.querySelector(`#${attackType}-form button[type="submit"]`);
    const originalText = button.innerHTML;
    const originalPayload = data.payload;
    
    // Show loading state
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing...';
    button.disabled = true;

    try {
        // First, test by making a direct request to the vulnerable endpoint
        // This is what WAF should intercept and block
        let wafBlocked = false;
        let wafResponse = null;
        
        try {
            const vulnerableUrl = `/vulnerable?q=${encodeURIComponent(data.payload)}`;
            const wafTestResponse = await fetch(vulnerableUrl);
            
            // Check if response is from Cloudflare WAF (blocked)
            const responseText = await wafTestResponse.text();
            if (responseText.includes('Cloudflare') && responseText.includes('blocked')) {
                wafBlocked = true;
                wafResponse = 'BLOCKED by Cloudflare WAF';
            } else {
                // Parse JSON response from our app
                wafResponse = JSON.parse(responseText);
            }
        } catch (error) {
            // If fetch fails, might be blocked
            wafBlocked = true;
            wafResponse = 'Request blocked or failed';
        }
        
        // Also send to the app endpoint for analysis
        const appResponse = await fetch(`/api/test/${attackType}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data)
        });

        const result = await appResponse.json();
        
        // Add WAF test results to the response
        result.wafBlocked = wafBlocked;
        result.wafResponse = wafResponse;
        
        if (result.success) {
            // Compare submitted payload with received payload
            const payloadsMatch = originalPayload === result.receivedPayload;
            
            // Determine result type based on WAF blocking and maliciousness
            let resultType = 'allowed'; // Default: green (good)
            let wafStatus = 'ALLOWED';
            let reason = 'Payload passed through unmodified';
            
            if (result.wafBlocked) {
                if (result.isMalicious) {
                    // Malicious payload was blocked by WAF - this is good (green)
                    resultType = 'blocked-good';
                    wafStatus = 'BLOCKED';
                    reason = 'Malicious payload was BLOCKED by Cloudflare WAF';
                } else {
                    // Non-malicious payload was blocked - neutral (yellow/orange)
                    resultType = 'modified-neutral';
                    wafStatus = 'BLOCKED';
                    reason = 'Benign payload was blocked by WAF (potential false positive)';
                }
            } else if (result.isMalicious) {
                // Malicious payload passed through unchanged - this is bad (red)
                resultType = 'allowed-bad';
                wafStatus = 'ALLOWED';
                reason = 'Malicious payload ALLOWED through - WAF not blocking this attack';
            }
            
            // Create enhanced result with comparison
            const enhancedResult = {
                ...result,
                originalPayload: originalPayload,
                payloadsMatch: payloadsMatch,
                wafStatus: wafStatus,
                resultType: resultType,
                wafAnalysis: {
                    blocked: !payloadsMatch,
                    reason: reason,
                    confidence: payloadsMatch ? 0 : 95
                }
            };
            
            displayResult(enhancedResult);
            updateStats(result.wafBlocked); // WAF blocked = true if Cloudflare blocked the request
        } else {
            showError(result.error || 'Test failed');
        }
    } catch (error) {
        console.error('Error testing attack:', error);
        showError('Network error occurred. Please try again.');
    } finally {
        // Reset button
        button.innerHTML = originalText;
        button.disabled = false;
    }
}

// Helper function to get proper attack type names
function getAttackTypeName(attackType) {
    const names = {
        'xss': 'XSS',
        'sqli': 'SQL Injection',
        'rce': 'Remote Code Execution'
    };
    return names[attackType] || attackType;
}

// Display test results
function displayResult(result) {
    const resultStatus = document.getElementById('result-status');
    const resultTimestamp = document.getElementById('result-timestamp');
    const resultAttackType = document.getElementById('result-attack-type');
    const resultPayload = document.getElementById('result-payload');
    const resultWafStatus = document.getElementById('result-waf-status');
    const resultResponse = document.getElementById('result-response');

    // Set status and colors based on result type
    switch (result.resultType) {
        case 'blocked-good':
            resultStatus.innerHTML = '<i class="fas fa-shield-alt"></i> BLOCKED';
            resultStatus.className = 'result-status text-green-700 font-bold';
            resultCard.className = 'result-card bg-green-50 border-2 border-green-200';
            break;
        case 'modified-neutral':
            resultStatus.innerHTML = '<i class="fas fa-exclamation-circle"></i> MODIFIED';
            resultStatus.className = 'result-status text-yellow-700 font-bold';
            resultCard.className = 'result-card bg-yellow-50 border-2 border-yellow-200';
            break;
        case 'allowed-bad':
            resultStatus.innerHTML = '<i class="fas fa-times-circle"></i> ALLOWED';
            resultStatus.className = 'result-status text-red-700 font-bold';
            resultCard.className = 'result-card bg-red-50 border-2 border-red-200';
            break;
        default: // 'allowed' - benign payload allowed through
            resultStatus.innerHTML = '<i class="fas fa-check-circle"></i> ALLOWED';
            resultStatus.className = 'result-status text-green-700 font-bold';
            resultCard.className = 'result-card bg-green-50 border-2 border-green-200';
    }

    // Set content
    resultTimestamp.textContent = new Date(result.timestamp).toLocaleString();
    resultAttackType.textContent = result.attackType;
    resultPayload.textContent = result.originalPayload || result.submittedPayload;
    
    resultWafStatus.innerHTML = `<span class="font-semibold">${result.wafStatus}</span>`;

    // Format response details showing payload comparison
    const responseText = `Submitted Payload: ${result.originalPayload || result.submittedPayload}
Received Payload: ${result.receivedPayload}
Payloads Match: ${result.payloadsMatch ? 'Yes' : 'No'}

Analysis: ${result.wafAnalysis ? result.wafAnalysis.reason : 'Payload comparison completed'}

${result.payloadsMatch 
    ? 'The payload reached the server unmodified, indicating no WAF filtering occurred.'
    : 'The payload was modified or blocked, indicating WAF protection is active.'}`;

    resultResponse.textContent = responseText;

    // Show results section
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Update statistics
function updateStats(wasBlocked) {
    testStats.total++;
    if (wasBlocked) {
        testStats.blocked++;
    } else {
        testStats.allowed++;
    }
    updateCounters();
}

// Update counter displays
function updateCounters() {
    totalCounter.textContent = testStats.total;
    blockedCounter.textContent = testStats.blocked;
    allowedCounter.textContent = testStats.allowed;
}

// Show error message
function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'error-message';
    errorDiv.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;
    
    // Insert at top of container
    const container = document.querySelector('.container');
    container.insertBefore(errorDiv, container.firstChild);
    
    // Remove after 5 seconds
    setTimeout(() => {
        errorDiv.remove();
    }, 5000);
}

// Utility function to copy payload to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showSuccess('Payload copied to clipboard!');
    }).catch(() => {
        showError('Failed to copy to clipboard');
    });
}

// Show success message
function showSuccess(message) {
    const successDiv = document.createElement('div');
    successDiv.className = 'success-message';
    successDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
    
    const container = document.querySelector('.container');
    container.insertBefore(successDiv, container.firstChild);
    
    setTimeout(() => {
        successDiv.remove();
    }, 3000);
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + Enter to submit current form
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const activeTab = document.querySelector('.tab-content:not(.hidden)');
        const form = activeTab ? activeTab.querySelector('form') : null;
        if (form) {
            e.preventDefault();
            form.dispatchEvent(new Event('submit', { bubbles: true }));
        }
    }
    
    // Tab switching with Ctrl/Cmd + 1/2/3
    if ((e.ctrlKey || e.metaKey) && ['1', '2', '3'].includes(e.key)) {
        e.preventDefault();
        const tabs = ['xss', 'sqli', 'rce'];
        const tabIndex = parseInt(e.key) - 1;
        if (tabs[tabIndex]) {
            switchTab(tabs[tabIndex]);
        }
    }
});

// Auto-resize textareas
document.querySelectorAll('textarea').forEach(textarea => {
    textarea.addEventListener('input', function() {
        this.style.height = 'auto';
        this.style.height = this.scrollHeight + 'px';
    });
});

// Add tooltips for better UX
function addTooltips() {
    const tooltips = {
        'xss-context': 'Choose where the XSS payload would be injected in a real application',
        'sqli-type': 'Select the type of SQL injection technique to simulate',
        'rce-method': 'Choose the method of code execution to test'
    };

    Object.entries(tooltips).forEach(([id, text]) => {
        const element = document.getElementById(id);
        if (element) {
            element.title = text;
        }
    });
}

// Initialize tooltips when DOM is ready
document.addEventListener('DOMContentLoaded', addTooltips);
