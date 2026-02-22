export interface Env {
  VIDEO_TOKEN_SECRET: string;
  R2_BUCKET: R2Bucket;
  ALLOWED_ORIGIN: string;
}

/* ===================== TYPES ===================== */
type TokenPayload = { vid: string; exp?: number; [k: string]: unknown };

type ReqCtx = {
  path: string;
  origin: string | null;
  range: string | null;
};

type VerifyResult =
  | { ok: true; payload: TokenPayload }
  | { ok: false; reason: string };

/* ===================== LOGGING ===================== */
function logEvent(event: string, ctx: ReqCtx, status: number, reason?: string): void {
  const payload: {
    event: string;
    path: string;
    origin: string | null;
    range: string | null;
    status: number;
    reason?: string;
  } = {
    event,
    path: ctx.path,
    origin: ctx.origin,
    range: ctx.range,
    status,
  };
  if (reason) payload.reason = reason;
  console.log(JSON.stringify(payload));
}

/* ===================== CORS ===================== */
function cors(origin: string | null, allowed: string): Headers {
  const h = new Headers();
  if (origin === allowed) h.set('Access-Control-Allow-Origin', allowed);
  h.set('Vary', 'Origin');
  h.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  h.set('Access-Control-Allow-Headers', 'Content-Type, Range');
  h.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
  return h;
}

function makeReject(allowed: string) {
  return (ctx: ReqCtx, status: number, reason: string): Response => {
    logEvent('request_rejected', ctx, status, reason);
    const h = cors(ctx.origin, allowed);
    h.set('Content-Type', 'text/plain');
    return new Response(reason, { status, headers: h });
  };
}

function resp(
  body: BodyInit | null,
  status: number,
  origin: string | null,
  allowed: string,
  extra?: HeadersInit,
) {
  const h = cors(origin, allowed);
  if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
  return new Response(body, { status, headers: h });
}

/* ===================== BASE64URL ===================== */
function b64uDecode(str: string): string {
  let b = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  return atob(b);
}

function b64uEncode(str: string): string {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/* ===================== SIGN / VERIFY ===================== */
async function sign(body: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const buf = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(body),
  );
  const sig = [...new Uint8Array(buf)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  return b64uEncode(`${body}.${sig}`);
}

async function verifyToken(token: string, secret: string): Promise<VerifyResult> {
  try {
    const decoded = b64uDecode(token);
    const [json, sig] = decoded.split('.');
    if (!json || !sig) return { ok: false, reason: 'malformed_token' };

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const buf = await crypto.subtle.sign(
      'HMAC',
      key,
      new TextEncoder().encode(json),
    );
    const expected = [...new Uint8Array(buf)]
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    if (expected !== sig) return { ok: false, reason: 'bad_signature' };

    const payload = JSON.parse(json) as TokenPayload;
    if (payload.exp !== undefined && payload.exp <= Math.floor(Date.now() / 1000)) {
      return { ok: false, reason: 'token_expired' };
    }
    return { ok: true, payload };
  } catch {
    return { ok: false, reason: 'decode_error' };
  }
}

/* ===================== WORKER ===================== */
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const origin = req.headers.get('Origin');
    const referer = req.headers.get('Referer') || '';
    const allowed = env.ALLOWED_ORIGIN;

    const url = new URL(req.url);
    const ctx: ReqCtx = {
      path: url.pathname,
      origin,
      range: req.headers.get('Range'),
    };
    const reject = makeReject(allowed);

    try {
      const { path } = ctx;

      // OPTIONS
      if (req.method === 'OPTIONS') {
        logEvent('preflight', ctx, 204);
        return resp('OK', 204, origin, allowed);
      }

      // FRONTEND ONLY
      if (!(origin === allowed || referer.startsWith(allowed))) {
        return reject(ctx, 403, 'origin_not_allowed');
      }

      /* ===== m3u8 ===== */
      if (path.endsWith('.m3u8')) {
        const token = url.searchParams.get('token');
        if (!token) {
          return reject(ctx, 403, 'missing_video_token');
        }

        const result = await verifyToken(token, env.VIDEO_TOKEN_SECRET);
        if (!result.ok) {
          return reject(ctx, 403, result.reason);
        }

        const r2Key = path.slice(1);
        const obj = await env.R2_BUCKET.get(r2Key);
        if (!obj) {
          return reject(ctx, 404, 'manifest_not_found');
        }

        const segToken = await sign(
          JSON.stringify({ vid: result.payload.vid }),
          env.VIDEO_TOKEN_SECRET,
        );

        let playlist = await obj.text();
        playlist = playlist.replace(
          /([^\s]+\.ts)/g,
          `$1?st=${segToken}`,
        );

        logEvent('manifest_served', ctx, 200);
        return resp(playlist, 200, origin, allowed, {
          'Content-Type': 'application/vnd.apple.mpegurl',
          'Cache-Control': 'no-store',
        });
      }

      /* ===== SEGMENT (.ts) ===== */
      if (path.endsWith('.ts')) {
        const st = url.searchParams.get('st');
        if (!st) {
          return reject(ctx, 403, 'missing_segment_token');
        }

        const result = await verifyToken(st, env.VIDEO_TOKEN_SECRET);
        if (!result.ok) {
          return reject(ctx, 403, `seg_${result.reason}`);
        }
        if (!result.payload.vid || !path.includes(result.payload.vid)) {
          return reject(ctx, 403, 'seg_vid_mismatch');
        }
      }

      /* ===== FETCH R2 (RANGE SUPPORT) ===== */
      const rangeHeader = req.headers.get('Range');
      let range: R2Range | undefined;

      if (rangeHeader) {
        const m = rangeHeader.match(/bytes=(\d+)-(\d*)/);
        if (m) {
          const start = parseInt(m[1], 10);
          const end = m[2] ? parseInt(m[2], 10) : undefined;
          range = {
            offset: start,
            length: end ? end - start + 1 : undefined,
          };
        }
      }

      const r2Key = path.slice(1);
      const obj = await env.R2_BUCKET.get(
        r2Key,
        range ? { range } : undefined,
      );
      if (!obj) {
        return reject(ctx, 404, 'file_not_found');
      }

      const headers = cors(origin, allowed);
      obj.writeHttpMetadata(headers);
      headers.set('Accept-Ranges', 'bytes');

      if (path.endsWith('.ts')) {
        headers.set('Content-Type', 'video/mp2t');
        headers.set('Cache-Control', 'public, max-age=31536000, immutable');
      }

      if (range && obj.range) {
        // @ts-ignore
        const off = obj.range.offset ?? 0;
        // @ts-ignore
        const len = obj.range.length ?? obj.size;
        headers.set(
          'Content-Range',
          `bytes ${off}-${off + len - 1}/${obj.size}`,
        );
      }

      const status = range ? 206 : 200;
      logEvent('r2_served', ctx, status);

      return new Response(obj.body, { status, headers });
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      logEvent('worker_error', ctx, 500, message);
      return resp(message, 500, origin, allowed, {
        'Content-Type': 'text/plain',
      });
    }
  },
};
