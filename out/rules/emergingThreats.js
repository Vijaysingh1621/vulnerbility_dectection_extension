"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectEmergingThreats = void 0;
const findLineNumber_1 = require("../utils/findLineNumber");
function detectEmergingThreats(code) {
    const issues = [];
    // SSRF Detection
    if (/fetch\(['"`]http/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'fetch'),
            message: 'Validate URLs used in fetch requests to prevent SSRF attacks.',
        });
    }
    // Hardcoded Secrets
    if (/['"`](apiKey|password)['"`]:/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'apiKey'),
            message: 'Avoid hardcoding sensitive information like API keys or passwords.',
        });
    }
    // 1. API Abuse and Misuse
    if (/fetch\(.+\)/.test(code) && !/validateAPIKey/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'fetch'),
            message: 'Ensure API calls validate API keys and rate limits to prevent abuse.',
        });
    }
    // 2. Insecure Use of AI/ML Models
    if (/predict\(.+\)/.test(code) && !/validateInput/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'predict'),
            message: 'Validate inputs to AI/ML models to prevent poisoning or adversarial attacks.',
        });
    }
    // 3. Cloud Misconfiguration
    if (/aws\.S3/.test(code) && !/acl: "private"/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'aws.S3'),
            message: 'Ensure cloud storage buckets have proper ACL configurations to avoid public exposure.',
        });
    }
    // 4. Lack of Zero Trust Architecture
    if (/req\.headers\['authorization'\]/.test(code) && !/checkPermissions/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'authorization'),
            message: 'Implement zero trust principles by verifying all requests explicitly.',
        });
    }
    // 5. Container Vulnerabilities
    if (/docker\.run/.test(code) && /:latest/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'docker.run'),
            message: 'Avoid using the "latest" tag in containers. Use specific versions to prevent vulnerabilities.',
        });
    }
    // 6. IoT Device Insecurity
    if (/connectDevice\(.+\)/.test(code) && !/encrypt/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'connectDevice'),
            message: 'Ensure IoT device communication is encrypted and authenticated.',
        });
    }
    // 7. Supply Chain Attacks
    if (/require\(.+\)/.test(code) && /node_modules/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'require'),
            message: 'Verify the integrity of third-party packages to prevent supply chain attacks.',
        });
    }
    // 8. Insufficient Logging and Monitoring
    if (/try\s*{.+} catch/.test(code) && !/logError/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'catch'),
            message: 'Ensure errors are logged properly for monitoring and forensic analysis.',
        });
    }
    // 9. Blockchain Vulnerabilities
    if (/web3\.eth/.test(code) && !/validateTransaction/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'web3.eth'),
            message: 'Validate transactions to prevent re-entrancy attacks and ensure blockchain integrity.',
        });
    }
    // 10. Shadow IT and Unauthorized Tools
    if (/exec\(.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'exec'),
            message: 'Avoid using unauthorized tools or scripts. Use approved tools for operations.',
        });
    }
    return issues;
}
exports.detectEmergingThreats = detectEmergingThreats;
//# sourceMappingURL=emergingThreats.js.map