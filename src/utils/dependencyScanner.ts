import { exec } from 'child_process';

export function scanDependencies() {
  exec('npm audit --json', (error, stdout) => {
    if (error) {
      console.error(`Error running npm audit: ${error.message}`);
      return [];
    }

    const vulnerabilities = JSON.parse(stdout).advisories || [];
    return vulnerabilities.map((vuln: any) => ({
      module: vuln.module_name,
      severity: vuln.severity,
      message: vuln.overview,
    }));
  });
}
