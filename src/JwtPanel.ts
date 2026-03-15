import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { decodeJwt, verifyJwt, signJwt } from './jwtCrypto';

interface WebviewMessage {
  command: string;
  [key: string]: unknown;
}

export class JwtPanel {
  public static currentPanel: JwtPanel | undefined;
  private static readonly viewType = 'jwtTools';

  private readonly _panel: vscode.WebviewPanel;
  private readonly _context: vscode.ExtensionContext;
  private _disposables: vscode.Disposable[] = [];

  public static createOrShow(context: vscode.ExtensionContext, prefilledToken?: string): void {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : vscode.ViewColumn.One;

    if (JwtPanel.currentPanel) {
      JwtPanel.currentPanel._panel.reveal(column);
      if (prefilledToken) {
        JwtPanel.currentPanel._sendToken(prefilledToken);
      }
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      JwtPanel.viewType,
      'JWT Tools',
      column ?? vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, 'src', 'webview'))],
      }
    );

    JwtPanel.currentPanel = new JwtPanel(panel, context);

    if (prefilledToken) {
      // Small delay to ensure webview is ready
      setTimeout(() => JwtPanel.currentPanel?._sendToken(prefilledToken), 300);
    }
  }

  private constructor(panel: vscode.WebviewPanel, context: vscode.ExtensionContext) {
    this._panel = panel;
    this._context = context;

    this._panel.webview.html = this._getWebviewContent();

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    this._panel.webview.onDidReceiveMessage(
      (message: WebviewMessage) => this._handleMessage(message),
      null,
      this._disposables
    );
  }

  private _sendToken(token: string): void {
    this._panel.webview.postMessage({ command: 'prefill', token });
  }

  private _handleMessage(message: WebviewMessage): void {
    switch (message.command) {
      case 'decode': {
        const result = decodeJwt(String(message.token ?? ''));
        this._panel.webview.postMessage({ command: 'decoded', result });
        break;
      }

      case 'verify': {
        const result = verifyJwt(
          String(message.token ?? ''),
          String(message.secret ?? '')
        );
        this._panel.webview.postMessage({ command: 'verified', result });
        break;
      }

      case 'sign': {
        let payload: Record<string, unknown> = {};
        try {
          payload = JSON.parse(String(message.payload ?? '{}')) as Record<string, unknown>;
        } catch {
          this._panel.webview.postMessage({
            command: 'signed',
            result: { success: false, error: 'Invalid payload JSON' },
          });
          return;
        }

        const result = signJwt(
          payload,
          String(message.algorithm ?? 'HS256'),
          String(message.secret ?? ''),
          (message.extraHeader as Record<string, unknown>) ?? {}
        );
        this._panel.webview.postMessage({ command: 'signed', result });
        break;
      }

      case 'copyToClipboard': {
        vscode.env.clipboard.writeText(String(message.text ?? '')).then(() => {
          this._panel.webview.postMessage({ command: 'copySuccess' });
        });
        break;
      }
    }
  }

  private _getWebviewContent(): string {
    const htmlPath = path.join(this._context.extensionPath, 'src', 'webview', 'panel.html');
    if (fs.existsSync(htmlPath)) {
      let html = fs.readFileSync(htmlPath, 'utf8');
      // Inject CSP. 'unsafe-inline' is needed for inline onclick/oninput handlers
      // and is acceptable for a local developer tool inside VS Code.
      const csp = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">`;
      html = html.replace('<head>', `<head>\n${csp}`);
      return html;
    }
    return '<html><body>Error: panel.html not found</body></html>';
  }

  public dispose(): void {
    JwtPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) {
      const d = this._disposables.pop();
      d?.dispose();
    }
  }
}
