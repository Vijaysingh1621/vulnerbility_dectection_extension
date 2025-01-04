"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectBusinessLogic = void 0;
const findLineNumber_1 = require("../utils/findLineNumber");
function detectBusinessLogic(code) {
    const issues = [];
    // Unsafe direct object references
    if (/\.getUser\((['"`]).*\1\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'getUser'),
            message: 'Avoid exposing sensitive object references. Validate and authorize access.',
        });
    }
    // Insecure role-based logic
    if (/role\s*===\s*['"`]admin['"`]/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'role'),
            message: 'Avoid hardcoding role-based checks. Use a secure access control mechanism.',
        });
    }
    // 1. Missing Authorization Check
    if (/if\s*\(req\.user\.role\s*==\s*['"]admin['"]/.test(code) && !/authorizeAdmin/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'req.user.role'),
            message: 'Authorization checks are missing for sensitive actions. Use a centralized authorization mechanism.',
        });
    }
    // 2. Weak Session Management
    if (/cookie\s*\(\s*['"]sessionId['"]\s*,\s*.+\)/.test(code) && !/httpOnly: true/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'cookie'),
            message: 'Session cookies must be marked as HttpOnly to prevent theft via client-side scripts.',
        });
    }
    // 3. Improper Workflow Enforcement
    if (/status\s*=\s*['"]approved['"]/.test(code) && !/checkPreviousStatus/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'status'),
            message: 'Ensure the workflow enforces valid transitions between states.',
        });
    }
    // 4. Unrestricted Critical Functionality
    if (/route\(['"]\/deleteAccount['"],\s*.+\)/.test(code) && !/req\.user\.isAdmin/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'route'),
            message: 'Critical actions like account deletion should be restricted to authorized users only.',
        });
    }
    // 5. Insufficient Rate Limiting
    if (/app\.post\(.+['"]\/login['"]/.test(code) && !/rateLimiter/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, '/login'),
            message: 'Rate limiting is missing on sensitive endpoints like login. This can lead to brute force attacks.',
        });
    }
    // 6. Missing Business Rule Validation
    if (/order\.quantity\s*=\s*\d+/.test(code) && !/validateOrderRules/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'order.quantity'),
            message: 'Ensure business rules are validated for critical operations like placing orders.',
        });
    }
    // 7. Exposing Sensitive Operations via APIs
    if (/app\.get\(.+['"]\/internalStats['"]/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, '/internalStats'),
            message: 'Avoid exposing sensitive internal operations through public APIs.',
        });
    }
    // 8. Bypassing Business Logic
    if (/if\s*\(promoCode\s*==\s*['"]SPECIAL50['"]/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'promoCode'),
            message: 'Hardcoded promo codes can lead to unauthorized discounts. Use secure validation.',
        });
    }
    // 9. Lack of Input Dependency Validation
    if (/calculatePrice\(.+/.test(code) && !/validateInputs/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'calculatePrice'),
            message: 'Ensure inputs to critical business logic are validated before processing.',
        });
    }
    // 10. Race Conditions in Business Logic
    if (/updateAccountBalance\(.+/.test(code) && !/lockAccount/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'updateAccountBalance'),
            message: 'Concurrency issues may lead to race conditions. Use locks or atomic operations.',
        });
    }
    return issues;
}
exports.detectBusinessLogic = detectBusinessLogic;
//# sourceMappingURL=businessLogic.js.map