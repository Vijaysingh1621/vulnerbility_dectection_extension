"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectSANS = void 0;
const findLineNumber_1 = require("../utils/findLineNumber");
function detectSANS(code) {
    const issues = [];
    if (/\.innerHTML\s*=\s*[^;]+;/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'innerHTML'),
            message: 'Avoid using innerHTML. This can lead to DOM-based XSS.',
        });
    }
    if (/query\(.+userInput/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'query'),
            message: 'Avoid concatenating user input in SQL queries. Use parameterized queries instead.',
        });
    }
    if (/exec\(.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'exec'),
            message: 'Avoid using exec() with untrusted input. This can lead to command injection attacks.',
        });
    }
    if (/strcpy\(.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'strcpy'),
            message: 'Avoid using unsafe functions like strcpy. Use safer alternatives like strncpy.',
        });
    }
    if (/const\s+\w+\s*=\s*['"].+['"];/.test(code) && /password|username|key/i.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'const'),
            message: 'Avoid hardcoding credentials. Use environment variables.',
        });
    }
    if (/function\s+\w+\s*\([\w,\s]*\)/.test(code) && !/validateInput/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'function'),
            message: 'Ensure input validation is performed on all user inputs.',
        });
    }
    if (/catch\s*\(\s*error\s*\)\s*\{/.test(code) && !/console\.log|console\.error/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'catch'),
            message: 'Ensure errors are properly logged and handled to avoid information leaks.',
        });
    }
    if (/fs\.readFileSync\s*\(.+userInput.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'fs.readFileSync'),
            message: 'Avoid using untrusted input in file paths. This can lead to path traversal.',
        });
    }
    if (/fs\.writeFile\s*\(.+\)/.test(code) && !/try/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'fs.writeFile'),
            message: 'Ensure proper locking mechanisms to avoid race conditions.',
        });
    }
    if (/fs\.chmod\s*\(.+['"]777['"]\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'fs.chmod'),
            message: 'Avoid using overly permissive file permissions. Use the principle of least privilege.',
        });
    }
    // 11. Improper Restriction of Operations Within the Bounds of a Memory Buffer
    if (/new\s+Buffer\s*\(/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'new Buffer'),
            message: 'Avoid using deprecated Buffer constructors. This can lead to memory issues.',
        });
    }
    // 12. Integer Overflow or Wraparound
    if (/Math\.pow\(.+\)/.test(code) && /int\s*/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'Math.pow'),
            message: 'Ensure proper checks for integer overflow or wraparound.',
        });
    }
    // 13. Uncontrolled Resource Consumption
    if (/while\s*\(.+\)/.test(code) && !/break;/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'while'),
            message: 'Ensure there are termination conditions to prevent infinite loops.',
        });
    }
    // 14. Incorrect Calculation
    if (/\d+\s*\/\s*0/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, '/'),
            message: 'Avoid division by zero to prevent crashes or undefined behavior.',
        });
    }
    // 15. Deserialization of Untrusted Data
    if (/JSON\.parse\(.+userInput.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'JSON.parse'),
            message: 'Avoid deserializing untrusted input. Validate or sanitize input before parsing.',
        });
    }
    // 16. Improper Control of Generation of Code ('Code Injection')
    if (/eval\(.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'eval'),
            message: 'Avoid using eval for dynamic code execution. This can lead to code injection.',
        });
    }
    // 17. Untrusted Search Path
    if (/require\(.+['"]\.\.\//.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'require'),
            message: 'Avoid loading modules from untrusted paths. Validate and sanitize paths.',
        });
    }
    // 18. Improper Certificate Validation
    if (/https\.request\(.+\)/.test(code) && code.includes('rejectUnauthorized: false')) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'https.request'),
            message: 'Avoid disabling SSL certificate validation. Always verify certificates.',
        });
    }
    // 19. Improper Privilege Management
    if (/process\.setuid\(.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'process.setuid'),
            message: 'Ensure privilege changes are secure and only applied when necessary.',
        });
    }
    // 20. Improper Initialization
    if (/let\s+\w+\s*;/.test(code) && !/=/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'let'),
            message: 'Ensure variables are initialized before use.',
        });
    }
    // 21. Improper Shutdown or Release of Resources
    if (/fs\.open\(.+\)/.test(code) && !code.includes('.close')) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'fs.open'),
            message: 'Ensure file descriptors are properly closed after use.',
        });
    }
    // 22. Unrestricted Upload of File with Dangerous Type
    if (/file\.mimetype/.test(code) && !/\.jpg|\.png|\.gif|\.txt/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'file.mimetype'),
            message: 'Restrict file uploads to safe types only.',
        });
    }
    // 23. Missing Input Validation
    if (/function\s+\w+\s*\([\w,\s]*\)/.test(code) && !code.includes('validateInput')) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'function'),
            message: 'Ensure input validation is performed on all user inputs.',
        });
    }
    // 24. Unnecessary File Inclusion
    if (/require\(.+\)/.test(code) && code.includes('eval(')) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'require'),
            message: 'Avoid dynamically including files. Use static imports wherever possible.',
        });
    }
    // 25. Improper Encoding or Escaping of Output
    if (/response\.send\(.+userInput.+\)/.test(code)) {
        issues.push({
            line: (0, findLineNumber_1.findLineNumber)(code, 'response.send'),
            message: 'Ensure all output is properly escaped to prevent injection attacks.',
        });
    }
    return issues;
}
exports.detectSANS = detectSANS;
//# sourceMappingURL=sansRules.js.map