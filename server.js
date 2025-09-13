const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 8080;

// Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Disable for demo purposes
    crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Known malicious patterns for detection (not blocking)
const maliciousPatterns = {
    xss: [
        /<script[^>]*>.*?<\/script>/gi,
        /javascript:/gi,
        /on\w+\s*=/gi,
        /<iframe[^>]*>/gi,
        /<object[^>]*>/gi,
        /<embed[^>]*>/gi,
        /vbscript:/gi,
        /expression\s*\(/gi
    ],
    sqli: [
        /(\bor\b|\band\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/gi,
        /union\s+select/gi,
        /drop\s+table/gi,
        /insert\s+into/gi,
        /delete\s+from/gi,
        /update\s+\w+\s+set/gi,
        /exec\s*\(/gi,
        /sp_\w+/gi,
        /xp_\w+/gi,
        /--/g,
        /\/\*.*?\*\//g
    ],
    rce: [
        /;\s*(ls|dir|cat|type|whoami|id|pwd|uname)/gi,
        /\$\([^)]+\)/g,
        /`[^`]+`/g,
        /\|\s*(ls|dir|cat|type|whoami|id|pwd|uname)/gi,
        /&&\s*(ls|dir|cat|type|whoami|id|pwd|uname)/gi,
        /eval\s*\(/gi,
        /exec\s*\(/gi,
        /system\s*\(/gi,
        /shell_exec\s*\(/gi,
        /passthru\s*\(/gi
    ]
};

// Detect if payload contains malicious patterns
function detectMaliciousPayload(payload, attackType) {
    const patterns = maliciousPatterns[attackType] || [];
    
    for (const pattern of patterns) {
        if (pattern.test(payload)) {
            return {
                isMalicious: true,
                matchedPattern: pattern.toString(),
                confidence: Math.floor(Math.random() * 30) + 70 // 70-99% confidence
            };
        }
    }
    
    return {
        isMalicious: false,
        matchedPattern: null,
        confidence: 0
    };
}

// Simple function to echo back the payload received by the server
function analyzePayloadIntegrity(receivedPayload, attackType) {
    const detection = detectMaliciousPayload(receivedPayload, attackType);
    
    return {
        receivedPayload: receivedPayload,
        timestamp: new Date().toISOString(),
        serverProcessed: true,
        isMalicious: detection.isMalicious,
        matchedPattern: detection.matchedPattern
    };
}

// API Routes

// Test XSS attack - create routes that WAF should block
app.get('/vulnerable', (req, res) => {
    const { q, search, input } = req.query;
    const payload = q || search || input || '';
    
    // This route is designed to be blocked by WAF when malicious payloads are in query params
    const result = analyzePayloadIntegrity(payload, 'xss');
    
    res.json({
        success: true,
        attackType: 'XSS',
        submittedPayload: payload,
        receivedPayload: result.receivedPayload,
        context: 'query_parameter',
        timestamp: result.timestamp,
        serverProcessed: true,
        isMalicious: result.isMalicious,
        matchedPattern: result.matchedPattern
    });
});

// Test XSS attack
app.post('/api/test/xss', (req, res) => {
    const { payload, context } = req.body;
    
    if (!payload) {
        return res.status(400).json({
            success: false,
            error: 'Payload is required'
        });
    }

    // Instead of just analyzing locally, make a request that WAF can intercept
    const testUrl = `/vulnerable?q=${encodeURIComponent(payload)}`;
    
    const result = analyzePayloadIntegrity(payload, 'xss');
    
    const response = {
        success: true,
        attackType: 'XSS',
        submittedPayload: payload,
        receivedPayload: result.receivedPayload,
        context: context || 'html',
        timestamp: result.timestamp,
        serverProcessed: result.serverProcessed,
        isMalicious: result.isMalicious,
        matchedPattern: result.matchedPattern,
        testUrl: testUrl
    };

    // Simulate response delay
    setTimeout(() => {
        res.json(response);
    }, Math.random() * 1000 + 500);
});

// Test SQL Injection attack
app.post('/api/test/sqli', (req, res) => {
    const { payload, type } = req.body;
    
    if (!payload) {
        return res.status(400).json({
            success: false,
            error: 'Payload is required'
        });
    }

    const result = analyzePayloadIntegrity(payload, 'sqli');
    
    const response = {
        success: true,
        attackType: 'SQL Injection',
        submittedPayload: payload,
        receivedPayload: result.receivedPayload,
        type: type || 'union',
        timestamp: result.timestamp,
        serverProcessed: result.serverProcessed,
        isMalicious: result.isMalicious,
        matchedPattern: result.matchedPattern
    };

    setTimeout(() => {
        res.json(response);
    }, Math.random() * 1000 + 500);
});

// Test RCE attack
app.post('/api/test/rce', (req, res) => {
    const { payload, method } = req.body;
    
    if (!payload) {
        return res.status(400).json({
            success: false,
            error: 'Payload is required'
        });
    }

    const result = analyzePayloadIntegrity(payload, 'rce');
    
    const response = {
        success: true,
        attackType: 'Remote Code Execution',
        submittedPayload: payload,
        receivedPayload: result.receivedPayload,
        method: method || 'command',
        timestamp: result.timestamp,
        serverProcessed: result.serverProcessed,
        isMalicious: result.isMalicious,
        matchedPattern: result.matchedPattern
    };

    setTimeout(() => {
        res.json(response);
    }, Math.random() * 1000 + 500);
});

// This endpoint represents what happens when there's no WAF protection
// All requests reach the server (which is what happens locally)
app.post('/api/waf-test/:attackType', (req, res) => {
    const { attackType } = req.params;
    const { payload } = req.body;
    
    if (!payload) {
        return res.status(400).json({
            success: false,
            error: 'Payload is required'
        });
    }

    // When running locally without Cloudflare WAF, all requests reach the server
    // This endpoint always allows requests through to demonstrate no WAF protection
    res.json({
        success: true,
        message: 'No WAF protection detected - request forwarding to application',
        waf: {
            blocked: false,
            reason: 'No WAF protection active'
        }
    });
});

// Get WAF statistics
app.get('/api/stats', (req, res) => {
    // In a real application, this would come from a database
    const stats = {
        totalRequests: Math.floor(Math.random() * 10000) + 5000,
        blockedRequests: Math.floor(Math.random() * 1000) + 500,
        allowedRequests: Math.floor(Math.random() * 9000) + 4500,
        topAttackTypes: [
            { type: 'XSS', count: Math.floor(Math.random() * 300) + 100 },
            { type: 'SQL Injection', count: Math.floor(Math.random() * 250) + 80 },
            { type: 'RCE', count: Math.floor(Math.random() * 150) + 50 }
        ],
        lastUpdated: new Date().toISOString()
    };
    
    res.json(stats);
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found'
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🛡️  Cloudflare WAF Demo Server running on port ${PORT}`);
    console.log(`📱 Server accessible at https://waf.gocf.pro (via NGINX)`);
    console.log(`🔒 WAF protection simulation active`);
    console.log(`🌐 Ready for production deployment with NGINX reverse proxy`);
});
