export interface Env {
  VIDEO_TOKEN_SECRET: string;
  R2_BUCKET: R2Bucket;
  ALLOWED_ORIGIN: string;
}

// TODO: Add logging + update tránh seek nhiều quá

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

async function verify(token: string, secret: string): Promise<any | null> {
  try {
    const decoded = b64uDecode(token);
    const [json, sig] = decoded.split('.');
    if (!json || !sig) return null;

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

    if (expected !== sig) return null;
    return JSON.parse(json);
  } catch {
    return null;
  }
}

/* ===================== WORKER ===================== */
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const origin = req.headers.get('Origin');
    const referer = req.headers.get('Referer') || '';
    const allowed = env.ALLOWED_ORIGIN;

    try {
      const url = new URL(req.url);
      const path = url.pathname;

      // OPTIONS
      if (req.method === 'OPTIONS') {
        return resp('OK', 204, origin, allowed);
      }

      // FRONTEND ONLY
      if (!(origin === allowed || referer.startsWith(allowed))) {
        return resp('Origin not allowed', 403, origin, allowed, {
          'Content-Type': 'text/plain',
        });
      }

      /* ===== m3u8 ===== */
      if (path.endsWith('.m3u8')) {
        const token = url.searchParams.get('token');
        if (!token) {
          return resp('Missing video token', 403, origin, allowed, { 'Content-Type': 'text/plain' });
        }

        const main = await verify(token, env.VIDEO_TOKEN_SECRET);
        if (!main || main.exp <= Math.floor(Date.now() / 1000)) {
          return resp('Invalid video token', 403, origin, allowed, { 'Content-Type': 'text/plain' });
        }

        const obj = await env.R2_BUCKET.get(path.slice(1));
        if (!obj) {
          return resp('Video not found', 404, origin, allowed, { 'Content-Type': 'text/plain' });
        }

        // segment token KHÔNG expire – chỉ bind theo videoId
        const segToken = await sign(
          JSON.stringify({ vid: main.vid }),
          env.VIDEO_TOKEN_SECRET,
        );

        let playlist = await obj.text();
        playlist = playlist.replace(
          /([^\s]+\.ts)/g,
          `$1?st=${segToken}`,
        );

        return resp(playlist, 200, origin, allowed, {
          'Content-Type': 'application/vnd.apple.mpegurl',
          'Cache-Control': 'no-store',
        });
      }

      /* ===== SEGMENT (.ts) ===== */
      if (path.endsWith('.ts')) {
        const st = url.searchParams.get('st');
        if (!st) {
          return resp('Missing segment token', 403, origin, allowed, { 'Content-Type': 'text/plain' });
        }

        const seg = await verify(st, env.VIDEO_TOKEN_SECRET);
        if (!seg || !seg.vid || !path.includes(seg.vid)) {
          return resp('Invalid segment token', 403, origin, allowed, { 'Content-Type': 'text/plain' });
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

      const obj = await env.R2_BUCKET.get(
        path.slice(1),
        range ? { range } : undefined,
      );
      if (!obj) {
        return resp('File not found', 404, origin, allowed, { 'Content-Type': 'text/plain' });
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

      return new Response(obj.body, {
        status: range ? 206 : 200,
        headers,
      });
    } catch (error) {
      return resp(error instanceof Error ? error.message : 'Unknown error', 403, origin, allowed, {
        'Content-Type': 'text/plain',
      });
    }
  },
};
