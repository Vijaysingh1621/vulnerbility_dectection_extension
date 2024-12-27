"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.provideQuickFix = void 0;
const vscode = require("vscode");
exports.provideQuickFix = {
    provideCodeActions(document, range, context, token) {
        const codeActions = [];
        context.diagnostics.forEach((diagnostic) => {
            if (diagnostic.message.includes('eval')) {
                const fix = new vscode.CodeAction('Replace eval with safer alternative', vscode.CodeActionKind.QuickFix);
                fix.edit = new vscode.WorkspaceEdit();
                fix.edit.replace(document.uri, diagnostic.range, '// TODO: Replace eval with a safer alternative');
                codeActions.push(fix);
            }
            if (diagnostic.message.includes('innerHTML')) {
                const fix = new vscode.CodeAction('Replace innerHTML with safer methods', vscode.CodeActionKind.QuickFix);
                fix.edit = new vscode.WorkspaceEdit();
                fix.edit.replace(document.uri, diagnostic.range, '// TODO: Use textContent instead of innerHTML');
                codeActions.push(fix);
            }
        });
        return codeActions;
    },
};
//# sourceMappingURL=fixProvider.js.map