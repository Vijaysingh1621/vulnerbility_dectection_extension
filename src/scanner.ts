import { detectOWASP } from './rules/owaspRules';
import { detectSANS } from './rules/sansRules';
import { detectBusinessLogic } from './rules/businessLogic';
import { detectEmergingThreats } from './rules/emergingThreats';

export function analyzeCode(code: string) {
  const issues: any[] = [];

  // OWASP Top 10 Detection
  issues.push(...detectOWASP(code));

  // SANS Top 25 Detection
  issues.push(...detectSANS(code));

  // Business Logic Vulnerabilities
  issues.push(...detectBusinessLogic(code));

  // Emerging Threats
  issues.push(...detectEmergingThreats(code));

  return issues;
}
