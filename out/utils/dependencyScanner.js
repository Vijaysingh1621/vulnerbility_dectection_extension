"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanDependencies = void 0;
const child_process_1 = require("child_process");
function scanDependencies() {
    (0, child_process_1.exec)('npm audit --json', (error, stdout) => {
        if (error) {
            console.error(`Error running npm audit: ${error.message}`);
            return [];
        }
        const vulnerabilities = JSON.parse(stdout).advisories || [];
        return vulnerabilities.map((vuln) => ({
            module: vuln.module_name,
            severity: vuln.severity,
            message: vuln.overview,
        }));
    });
}
exports.scanDependencies = scanDependencies;
//# sourceMappingURL=dependencyScanner.js.map