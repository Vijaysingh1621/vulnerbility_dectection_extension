"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deactivate = exports.activate = void 0;
const vscode = require("vscode");
const scanner_1 = require("./scanner");
const fixProvider_1 = require("./fixProvider");
function activate(context) {
    // Real-time detection
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('vulnerabilities');
    vscode.workspace.onDidChangeTextDocument((event) => {
        const editor = vscode.window.activeTextEditor;
        if (!editor || event.document !== editor.document)
            return;
        const code = editor.document.getText();
        const issues = (0, scanner_1.analyzeCode)(code);
        const diagnostics = issues.map((issue) => {
            const range = new vscode.Range(issue.line, 0, issue.line, 100);
            return new vscode.Diagnostic(range, issue.message, vscode.DiagnosticSeverity.Warning);
        });
        diagnosticCollection.set(editor.document.uri, diagnostics);
    });
    // Manual scanning command
    const scanCommand = vscode.commands.registerCommand('vulnerabilityscanner.scan', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor)
            return;
        const code = editor.document.getText();
        const issues = (0, scanner_1.analyzeCode)(code);
        if (issues.length > 0) {
            vscode.window.showErrorMessage(`Security Issues Found:\n${issues.map((i) => i.message).join('\n')}`);
        }
        else {
            vscode.window.showInformationMessage('No vulnerabilities detected!');
        }
    });
    // Register quick fix provider
    const quickFixProvider = vscode.languages.registerCodeActionsProvider({ language: 'javascript', scheme: 'file' }, fixProvider_1.provideQuickFix);
    context.subscriptions.push(scanCommand, diagnosticCollection, quickFixProvider);
}
exports.activate = activate;
function deactivate() { }
exports.deactivate = deactivate;
//# sourceMappingURL=extension.js.map