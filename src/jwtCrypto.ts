import * as crypto from 'crypto';

export interface JwtHeader {
  alg: string;
  typ?: string;
  [key: string]: unknown;
}

export interface JwtPayload {
  [key: string]: unknown;
}

export interface DecodedJwt {
  header: JwtHeader;
  payload: JwtPayload;
  signature: string;
  raw: { header: string; payload: string; signature: string };
}

export interface DecodeResult {
  success: boolean;
  data?: DecodedJwt;
  error?: string;
}

export interface VerifyResult {
  valid: boolean;
  error?: string;
}

export interface SignResult {
  success: boolean;
  token?: string;
  error?: string;
}

function base64urlDecode(str: string): string {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '=='.substring(0, (4 - (base64.length % 4)) % 4);
  return Buffer.from(padded, 'base64').toString('utf8');
}

function base64urlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function decodeJwt(token: string): DecodeResult {
  try {
    const parts = token.trim().split('.');
    if (parts.length !== 3) {
      return { success: false, error: `Invalid JWT structure: expected 3 parts, found ${parts.length}` };
    }

    let header: JwtHeader;
    let payload: JwtPayload;

    try {
      header = JSON.parse(base64urlDecode(parts[0])) as JwtHeader;
    } catch {
      return { success: false, error: 'Invalid header: could not parse JSON' };
    }

    try {
      payload = JSON.parse(base64urlDecode(parts[1])) as JwtPayload;
    } catch {
      return { success: false, error: 'Invalid payload: could not parse JSON' };
    }

    return {
      success: true,
      data: {
        header,
        payload,
        signature: parts[2],
        raw: { header: parts[0], payload: parts[1], signature: parts[2] },
      },
    };
  } catch (err) {
    return { success: false, error: `Parse error: ${String(err)}` };
  }
}

export function verifyJwt(token: string, secret: string): VerifyResult {
  const decoded = decodeJwt(token);
  if (!decoded.success || !decoded.data) {
    return { valid: false, error: decoded.error };
  }

  const { header, raw } = decoded.data;
  const alg = header.alg;
  const signingInput = `${raw.header}.${raw.payload}`;

  try {
    if (alg.startsWith('HS')) {
      const hashAlg = alg === 'HS256' ? 'sha256' : alg === 'HS384' ? 'sha384' : 'sha512';
      const expectedSig = base64urlEncode(
        crypto.createHmac(hashAlg, secret).update(signingInput).digest()
      );
      const valid = crypto.timingSafeEqual(
        Buffer.from(expectedSig),
        Buffer.from(raw.signature.padEnd(expectedSig.length, ' '))
      ) && expectedSig === raw.signature;
      return { valid };
    }

    if (alg.startsWith('RS')) {
      const hashAlg = alg === 'RS256' ? 'sha256' : alg === 'RS384' ? 'sha384' : 'sha512';
      const verify = crypto.createVerify(hashAlg);
      verify.update(signingInput);
      const sigBuffer = Buffer.from(raw.signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      const valid = verify.verify(secret, sigBuffer);
      return { valid };
    }

    if (alg.startsWith('ES')) {
      const hashAlg = alg === 'ES256' ? 'sha256' : alg === 'ES384' ? 'sha384' : 'sha512';
      const verify = crypto.createVerify(hashAlg);
      verify.update(signingInput);
      const sigBuffer = Buffer.from(raw.signature.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
      const valid = verify.verify(secret, sigBuffer);
      return { valid };
    }

    if (alg === 'none') {
      return { valid: raw.signature === '', error: raw.signature !== '' ? 'Algorithm is "none" but signature is present' : undefined };
    }

    return { valid: false, error: `Unsupported algorithm: ${alg}` };
  } catch (err) {
    return { valid: false, error: `Verification error: ${String(err)}` };
  }
}

export function signJwt(
  payload: JwtPayload,
  algorithm: string,
  secret: string,
  extraHeader: Record<string, unknown> = {}
): SignResult {
  try {
    const header: JwtHeader = { alg: algorithm, typ: 'JWT', ...extraHeader };
    const headerB64 = base64urlEncode(Buffer.from(JSON.stringify(header)));
    const payloadB64 = base64urlEncode(Buffer.from(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;

    let signature: string;

    if (algorithm.startsWith('HS')) {
      const hashAlg = algorithm === 'HS256' ? 'sha256' : algorithm === 'HS384' ? 'sha384' : 'sha512';
      signature = base64urlEncode(
        crypto.createHmac(hashAlg, secret).update(signingInput).digest()
      );
    } else if (algorithm.startsWith('RS')) {
      const hashAlg = algorithm === 'RS256' ? 'sha256' : algorithm === 'RS384' ? 'sha384' : 'sha512';
      const sign = crypto.createSign(hashAlg);
      sign.update(signingInput);
      signature = base64urlEncode(sign.sign(secret));
    } else if (algorithm.startsWith('ES')) {
      const hashAlg = algorithm === 'ES256' ? 'sha256' : algorithm === 'ES384' ? 'sha384' : 'sha512';
      const sign = crypto.createSign(hashAlg);
      sign.update(signingInput);
      signature = base64urlEncode(sign.sign(secret));
    } else {
      return { success: false, error: `Unsupported algorithm: ${algorithm}` };
    }

    return { success: true, token: `${signingInput}.${signature}` };
  } catch (err) {
    return { success: false, error: `Signing error: ${String(err)}` };
  }
}
