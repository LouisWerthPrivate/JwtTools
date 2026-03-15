import * as vscode from 'vscode';
import { JwtPanel } from './JwtPanel';

export function activate(context: vscode.ExtensionContext): void {
  // Open panel command
  const openPanel = vscode.commands.registerCommand('jwt-tools.openPanel', () => {
    JwtPanel.createOrShow(context);
  });

  // Decode selection command — right-click on selected text
  const decodeSelection = vscode.commands.registerCommand('jwt-tools.decodeSelection', () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      return;
    }
    const selection = editor.selection;
    const selectedText = editor.document.getText(selection).trim();
    JwtPanel.createOrShow(context, selectedText);
  });

  context.subscriptions.push(openPanel, decodeSelection);
}

export function deactivate(): void {
  JwtPanel.currentPanel?.dispose();
}
