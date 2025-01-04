"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeCode = void 0;
const owaspRules_1 = require("./rules/owaspRules");
const sansRules_1 = require("./rules/sansRules");
const businessLogic_1 = require("./rules/businessLogic");
const emergingThreats_1 = require("./rules/emergingThreats");
function analyzeCode(code) {
    const issues = [];
    // OWASP Top 10 Detection
    issues.push(...(0, owaspRules_1.detectOWASP)(code));
    // SANS Top 25 Detection
    issues.push(...(0, sansRules_1.detectSANS)(code));
    // Business Logic Vulnerabilities
    issues.push(...(0, businessLogic_1.detectBusinessLogic)(code));
    // Emerging Threats
    issues.push(...(0, emergingThreats_1.detectEmergingThreats)(code));
    return issues;
}
exports.analyzeCode = analyzeCode;
//# sourceMappingURL=scanner.js.map