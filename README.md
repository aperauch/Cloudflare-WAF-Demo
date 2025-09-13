# 🛡️ Cloudflare WAF Demo App

An interactive web application for demonstrating and learning about Cloudflare Web Application Firewall (WAF) protection against common web attacks. This educational tool helps security professionals, developers, and students understand how WAF protection works in real-world scenarios.

## ✨ Features

### Attack Simulation
- **🔥 XSS Attack Testing**: Cross-Site Scripting attack vectors with multiple payload examples
- **💉 SQL Injection Testing**: Database injection attack patterns and techniques  
- **⚡ RCE Attack Testing**: Remote Code Execution attack simulation
- **📊 Real-time Analysis**: Instant feedback on payload blocking/modification status

### User Experience
- **🎨 Modern UI**: Beautiful Tailwind CSS interface with responsive design
- **🔄 Interactive Tabs**: Easy switching between attack types
- **📱 Mobile Friendly**: Works seamlessly on desktop and mobile devices
- **⌨️ Keyboard Shortcuts**: Ctrl/Cmd + 1/2/3 for tab switching, Ctrl/Cmd + Enter to submit

### Educational Content
- **📚 Attack Explanations**: Detailed information about each attack type
- **💡 Example Payloads**: Click-to-use example attacks for learning
- **🎯 Context Selection**: Choose injection contexts (URL, form, header, etc.)
- **📈 Protection Dashboard**: Visual statistics of blocked vs allowed requests

## 🚀 Quick Start

1. **Install dependencies:**
   ```bash
   npm install
   ```

2. **Start the server:**
   ```bash
   npm start
   ```

3. **Open your browser:**
   Navigate to `http://localhost:3000`

## 📖 How It Works

### Testing Logic
The app compares submitted payloads with received payloads to determine WAF effectiveness:

- 🟢 **BLOCKED-GOOD**: Malicious payload blocked/modified (WAF working correctly)
- 🟡 **MODIFIED-NEUTRAL**: Benign payload modified (potential false positive)
- 🔴 **ALLOWED-BAD**: Malicious payload passed unchanged (security risk)
- ✅ **ALLOWED**: Benign payload passed unchanged (normal behavior)

### Usage Steps
1. **Select Attack Type**: Choose XSS, SQL Injection, or RCE from the tabs
2. **Choose Context**: Select where the attack would be injected (URL, form, etc.)
3. **Enter Payload**: Type your test payload or click an example to auto-fill
4. **Test Attack**: Click "Test Attack" to submit and analyze results
5. **Review Results**: Check the color-coded analysis and protection status

## 🔧 Development

### Project Structure
```
WAF/
├── server.js              # Express backend with API endpoints
├── package.json           # Dependencies and scripts
├── public/
│   ├── index.html        # Main HTML with Tailwind CSS
│   └── script.js         # Frontend JavaScript logic
└── README.md             # This file
```

### Available Scripts
- `npm start` - Start the production server
- `npm run dev` - Start with nodemon for development

## ⚠️ Important Security Notes

- **Educational Use Only**: This tool is designed for learning and authorized testing
- **Controlled Environments**: Only use in environments you own or have explicit permission to test
- **Responsible Disclosure**: Report any real vulnerabilities through proper channels
- **No Malicious Use**: Do not use against systems without authorization

## 🌐 Cloudflare WAF Configuration

For optimal demonstration, configure your Cloudflare zone with:

### Essential Rules
- ✅ **WAF Managed Rules**: Enable Cloudflare's managed ruleset
- ✅ **OWASP Core Rule Set**: Activate comprehensive protection
- ✅ **Rate Limiting**: Prevent abuse and DoS attacks

### Advanced Configuration
- 🔧 **Custom Rules**: Create specific rules for your application
- 📊 **Analytics**: Monitor attack patterns and false positives
- 🎯 **Exception Rules**: Whitelist legitimate traffic patterns

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve this educational tool.

## 📄 License

This project is for educational purposes. Use responsibly and in accordance with applicable laws and regulations.
