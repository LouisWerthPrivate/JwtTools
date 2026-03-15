# JWT Tools

JWT Tools is a Visual Studio Code extension for developers who need to inspect, verify, and create JSON Web Tokens without leaving the editor. It provides a dedicated panel inside VS Code so you can work with tokens during API development, authentication debugging, and local testing workflows.

Written by Louis Werth.

## Purpose

JWTs are common in modern authentication flows, but working with them usually means copying tokens into external web tools or ad hoc scripts. JWT Tools brings that workflow into VS Code so you can:

- decode a token and inspect its header, payload, and signature
- verify a token signature with the appropriate secret or key
- create signed JWTs for testing and development
- decode a selected token directly from the editor

This makes the extension useful when debugging login issues, checking claim values, validating expiration dates, or generating tokens for local services and integration tests.

## Features

### Decode and Inspect

Paste a JWT into the panel and immediately view:

- the decoded header
- the decoded payload
- the raw signature segment
- token structure validation feedback

The extension is designed to make token contents easier to inspect during development, especially when you need to confirm claim values such as `iss`, `sub`, `aud`, `iat`, `nbf`, and `exp`.

### Verify Signatures

JWT Tools can verify token signatures using the selected token algorithm and the secret or key you provide. This helps confirm whether a token was signed with the expected material before you continue debugging downstream authentication issues.

Supported algorithm families include:

- `HS256`, `HS384`, `HS512`
- `RS256`, `RS384`, `RS512`
- `ES256`, `ES384`, `ES512`

### Build Tokens

The extension also includes a builder workflow for generating signed JWTs inside VS Code. You can provide payload JSON, choose an algorithm, add optional header values, and generate a token for local testing or manual API calls.

## Commands

JWT Tools contributes the following commands to VS Code:

- `JWT Tools: Open Panel`
- `JWT Tools: Decode Selected Token`

The main panel can also be opened with the default shortcut:

- macOS: `Cmd+Shift+J`
- Windows/Linux: `Ctrl+Shift+J`

When text is selected in the editor, you can use the context menu command to send that token straight into the JWT Tools panel.

## Typical Use Cases

- inspect access tokens returned from a local API
- verify whether a token is expired or malformed
- confirm claim values during OAuth or OpenID Connect debugging
- generate JWTs for local integration tests
- quickly decode tokens copied from logs, requests, or config files

## Development Preview

If you are previewing the extension during development in the Extension Development Host, open the Command Palette and run `JWT Tools: Open Panel`. You can then paste a token into the panel, inspect its decoded content, verify signatures, or generate a new token for testing.

## Installation and Development

Install dependencies and compile the extension:

```bash
npm install
npm run compile
```

To preview the extension while developing:

1. Open this project in VS Code.
2. Press `F5` to launch the Extension Development Host.
3. Run `JWT Tools: Open Panel` from the Command Palette.

## Notes

JWT Tools is intended as a developer utility. It is designed to help with local inspection and testing workflows inside VS Code, reducing the need to move sensitive tokens into external tools during day-to-day development.
