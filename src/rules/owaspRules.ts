export function detectOWASP(code: string) {
    const issues = [];
  
     // 1. Injection (SQL/Command Injection)
     if (/query\(.+userInput/.test(code) || /exec\(.+userInput/.test(code)) {
      issues.push({
          line: findLineNumber(code, 'query('),
          message: 'Avoid using untrusted user input in SQL/command queries. Use parameterized queries or sanitize inputs.',
      });
  }

  // 2. Broken Authentication
  if (/password\s*=\s*['"].+['"]/.test(code)) {
      issues.push({
          line: findLineNumber(code, 'password'),
          message: 'Avoid hardcoding passwords. Use environment variables or secure vaults.',
      });
  }

  // 3. Sensitive Data Exposure
  if (/http:\//.test(code)) {
      issues.push({
          line: findLineNumber(code, 'http://'),
          message: 'Sensitive data might be exposed over HTTP. Use HTTPS instead.',
      });
  }

  // 4. XML External Entities (XXE)
  if (/xml2js/.test(code) || /DOMParser\(.+\)/.test(code)) {
      issues.push({
          line: findLineNumber(code, 'xml2js'),
          message: 'Ensure XML parsers are configured to disable external entity resolution to prevent XXE attacks.',
      });
  }

  // 5. Broken Access Control
  if (/req\.user\.role\s*==\s*['"]admin['"]/.test(code)) {
      issues.push({
          line: findLineNumber(code, 'req.user.role'),
          message: 'Avoid role-based checks directly in the code. Use centralized access control policies.',
      });
  }

  // 6. Security Misconfiguration
  if (/app\.use\(.+helmet/.test(code) === false) {
      issues.push({
          line: 0,
          message: 'Ensure security headers are configured using Helmet or similar libraries.',
      });
  }

  // 7. Cross-Site Scripting (XSS)
  if (/\.innerHTML\s*=\s*[^;]+;/.test(code)) {
      issues.push({
          line: findLineNumber(code, 'innerHTML'),
          message: 'Avoid using innerHTML. This can lead to DOM-based XSS.',
      });
  }

  // 8. Insecure Deserialization
  if (/JSON\.parse\(.+userInput.+\)/.test(code)) {
      issues.push({
          line: findLineNumber(code, 'JSON.parse'),
          message: 'Avoid deserializing untrusted input. Validate or sanitize input before parsing.',
      });
  }

  // 9. Using Components with Known Vulnerabilities
  if (/require\(.+['"](lodash|underscore|express)['"]\)/.test(code)) {
      issues.push({
          line: findLineNumber(code, 'require'),
          message: 'Ensure third-party libraries are up-to-date and free of known vulnerabilities.',
      });
  }

  // 10. Insufficient Logging & Monitoring
  if (!/console\.log\(.+\)/.test(code) && !/logger\.info\(.+\)/.test(code)) {
      issues.push({
          line: 0,
          message: 'Add sufficient logging and monitoring to detect and respond to security incidents.',
      });
  }
  
    return issues;
  }
  
  function findLineNumber(code: string, pattern: string) {
    const lines = code.split('\n');
    return lines.findIndex((line) => line.includes(pattern)) + 1;
  }
  