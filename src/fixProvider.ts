import * as vscode from 'vscode';

export const provideQuickFix: vscode.CodeActionProvider = {
  provideCodeActions(document, range, context, token) {
    const codeActions: vscode.CodeAction[] = [];

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
