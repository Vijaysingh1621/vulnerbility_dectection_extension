export interface Vulnerability {
    line: number;
    message: string;
  }
  
  export function analyzeCode(code: string): Vulnerability[] {
    const issues: Vulnerability[] = [];
    const lines = code.split('\n');
  
    lines.forEach((line, index) => {
      if (line.includes('eval(')) {
        issues.push({
          line: index,
          message: 'Avoid using eval(). This can lead to code injection attacks.',
        });
      }
  
      if (line.match(/res\.send\((.*?)\+/)) {
        issues.push({
          line: index,
          message: 'Potential XSS vulnerability detected. Avoid concatenating user input directly.',
        });
      }
  
      if (line.includes('innerHTML')) {
        issues.push({
          line: index,
          message: 'Avoid using innerHTML. This can lead to DOM-based XSS.',
        });
      }
    });
  
    return issues;
  }
  