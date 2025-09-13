// Global state
let testStats = {
    total: 0,
    passed: 0,
    failed: 0,
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
const passedCounter = document.getElementById('passed-counter');
const failedCounter = document.getElementById('failed-counter');
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
        // Test by making a direct request to the vulnerable endpoint
        // This is what WAF should intercept and block
        let wafBlocked = false;
        let wafResponse = null;
        let httpStatus = null;
        let testPassed = false;

        try {
            const vulnerableUrl = `/vulnerable?q=${encodeURIComponent(data.payload)}&_t=${Date.now()}`;
            console.log('Testing URL:', vulnerableUrl);
            const wafTestResponse = await fetch(vulnerableUrl);
            httpStatus = wafTestResponse.status;
            console.log('Response status:', wafTestResponse.status);
            console.log('Response headers:', Array.from(wafTestResponse.headers.entries()));

            if (wafTestResponse.status === 403) {
                // 403 Forbidden indicates WAF blocked the request
                wafBlocked = true;
                const responseText = await wafTestResponse.text();
                if (responseText.includes('Cloudflare') || responseText.includes('blocked') || responseText.includes('Sorry, you have been blocked')) {
                    wafResponse = 'BLOCKED by Cloudflare WAF (403 Forbidden)';
                } else {
                    wafResponse = 'BLOCKED by Web Application Firewall (403 Forbidden)';
                }
            } else if (wafTestResponse.status === 200) {
                // 200 OK means request went through to the server
                wafBlocked = false;
                try {
                    wafResponse = await wafTestResponse.json();
                } catch {
                    const responseText = await wafTestResponse.text();
                    wafResponse = { message: 'Server response received', responseText: responseText.substring(0, 200) };
                }
            } else {
                // Other status codes (500, 404, etc.)
                wafBlocked = true;
                wafResponse = `Request failed with status ${wafTestResponse.status}`;
            }
        } catch (error) {
            // Network error, CORS error, or connection refused
            wafBlocked = true;
            wafResponse = `Network error: ${error.message}`;
            httpStatus = 'ERROR';
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
        result.httpStatus = httpStatus;

        if (result.success) {
            // Determine if this is a pass or fail based on maliciousness and WAF response
            let resultType = 'unknown';
            let wafStatus = wafBlocked ? 'BLOCKED' : 'ALLOWED';
            let reason = '';

            if (result.isMalicious) {
                // For malicious payloads, WAF should block them
                if (wafBlocked) {
                    // PASS: Malicious payload was correctly blocked
                    resultType = 'test-pass';
                    testPassed = true;
                    reason = `✅ TEST PASSED: Malicious ${result.attackType} payload was correctly BLOCKED by WAF`;
                } else {
                    // FAIL: Malicious payload was allowed through
                    resultType = 'test-fail';
                    testPassed = false;
                    reason = `❌ TEST FAILED: Malicious ${result.attackType} payload was incorrectly ALLOWED through WAF`;
                }
            } else {
                // For non-malicious payloads, WAF should generally allow them
                if (!wafBlocked) {
                    // PASS: Non-malicious payload was allowed
                    resultType = 'test-pass';
                    testPassed = true;
                    reason = `✅ TEST PASSED: Non-malicious payload was correctly ALLOWED through WAF`;
                } else {
                    // NEUTRAL: Non-malicious payload was blocked (could be false positive)
                    resultType = 'test-neutral';
                    testPassed = null; // Neither pass nor fail
                    reason = `⚠️ FALSE POSITIVE: Non-malicious payload was BLOCKED by WAF (may be overly strict)`;
                }
            }

            // Create enhanced result with clear pass/fail status
            const enhancedResult = {
                ...result,
                originalPayload: originalPayload,
                wafStatus: wafStatus,
                resultType: resultType,
                testPassed: testPassed,
                httpStatus: httpStatus,
                wafAnalysis: {
                    blocked: wafBlocked,
                    reason: reason,
                    confidence: 95,
                    recommendation: result.isMalicious ?
                        (wafBlocked ? 'WAF is working correctly for this attack type' : 'Consider enabling stricter WAF rules for this attack type') :
                        (wafBlocked ? 'Consider reviewing WAF rules to reduce false positives' : 'WAF allows legitimate traffic as expected')
                }
            };

            displayResult(enhancedResult);
            updateStats(testPassed, result.isMalicious);
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
        case 'test-pass':
            resultStatus.innerHTML = '<i class="fas fa-check-circle"></i> TEST PASSED';
            resultStatus.className = 'result-status text-green-700 font-bold text-2xl';
            resultCard.className = 'result-card bg-green-50 border-2 border-green-300 rounded-lg p-6';
            break;
        case 'test-fail':
            resultStatus.innerHTML = '<i class="fas fa-times-circle"></i> TEST FAILED';
            resultStatus.className = 'result-status text-red-700 font-bold text-2xl';
            resultCard.className = 'result-card bg-red-50 border-2 border-red-300 rounded-lg p-6';
            break;
        case 'test-neutral':
            resultStatus.innerHTML = '<i class="fas fa-exclamation-triangle"></i> FALSE POSITIVE';
            resultStatus.className = 'result-status text-yellow-700 font-bold text-2xl';
            resultCard.className = 'result-card bg-yellow-50 border-2 border-yellow-300 rounded-lg p-6';
            break;
        default:
            resultStatus.innerHTML = '<i class="fas fa-question-circle"></i> UNKNOWN';
            resultStatus.className = 'result-status text-gray-700 font-bold text-2xl';
            resultCard.className = 'result-card bg-gray-50 border-2 border-gray-300 rounded-lg p-6';
    }

    // Set content
    resultTimestamp.textContent = new Date(result.timestamp).toLocaleString();
    resultAttackType.textContent = result.attackType;
    resultPayload.textContent = result.originalPayload || result.submittedPayload;

    // Enhanced WAF status with HTTP status
    const statusColor = result.wafStatus === 'BLOCKED' ? 'text-red-600' : 'text-green-600';
    resultWafStatus.innerHTML = `<span class="font-semibold ${statusColor}">${result.wafStatus}</span> <span class="text-gray-500">(HTTP ${result.httpStatus})</span>`;

    // Enhanced response details with clear pass/fail information
    const maliciousStatus = result.isMalicious ? '🚨 MALICIOUS' : '✅ BENIGN';
    const payloadAnalysis = result.isMalicious
        ? 'This payload contains known attack patterns and should be blocked by a properly configured WAF.'
        : 'This payload appears benign and should typically be allowed through a properly configured WAF.';

    const responseText = `WAF TEST RESULT: ${result.wafAnalysis.reason}

HTTP STATUS: ${result.httpStatus}
PAYLOAD TYPE: ${maliciousStatus}
WAF STATUS: ${result.wafStatus}

SUBMITTED PAYLOAD:
${result.originalPayload || result.submittedPayload}

PAYLOAD ANALYSIS:
${payloadAnalysis}

${result.isMalicious && result.matchedPattern ? `DETECTED ATTACK PATTERN: ${result.matchedPattern}` : ''}

WAF ANALYSIS:
${result.wafAnalysis.reason}

RECOMMENDATION:
${result.wafAnalysis.recommendation}

${result.wafResponse && typeof result.wafResponse === 'string' ? `WAF RESPONSE: ${result.wafResponse}` : ''}`;

    resultResponse.textContent = responseText;

    // Show results section
    resultsSection.style.display = 'block';
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

// Update statistics
function updateStats(testPassed, wasMalicious) {
    testStats.total++;

    // Track pass/fail status
    if (testPassed === true) {
        testStats.passed++;
    } else if (testPassed === false) {
        testStats.failed++;
    }

    // Track blocked/allowed for WAF effectiveness
    // For malicious payloads: blocked = good, allowed = bad
    // For benign payloads: allowed = good, blocked = false positive
    if (wasMalicious) {
        if (testPassed === true) {
            testStats.blocked++; // Malicious was correctly blocked
        } else if (testPassed === false) {
            testStats.allowed++; // Malicious was incorrectly allowed
        }
    } else {
        if (testPassed === true) {
            testStats.allowed++; // Benign was correctly allowed
        } else if (testPassed === null) {
            testStats.blocked++; // Benign was blocked (false positive)
        }
    }

    updateCounters();
}

// Update counter displays
function updateCounters() {
    totalCounter.textContent = testStats.total;
    passedCounter.textContent = testStats.passed;
    failedCounter.textContent = testStats.failed;
    blockedCounter.textContent = testStats.blocked;
    allowedCounter.textContent = testStats.allowed;
}

// Show error message
function showError(message) {
    const errorDiv = document.createElement('div');
    errorDiv.className = 'bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4 flex items-center gap-3';
    errorDiv.innerHTML = `<i class="fas fa-exclamation-circle"></i> ${message}`;

    // Insert at top of main container
    const container = document.querySelector('.max-w-6xl') || document.body;
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
    successDiv.className = 'bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4 flex items-center gap-3';
    successDiv.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;

    const container = document.querySelector('.max-w-6xl') || document.body;
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
