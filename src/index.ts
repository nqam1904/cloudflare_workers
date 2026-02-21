export interface Env {
	VIDEO_TOKEN_SECRET: string;
	R2_BUCKET: R2Bucket;
	ALLOWED_ORIGIN: string;
}

type TokenPayload = {
	vid?: string;
	exp?: number;
	[key: string]: unknown;
};

type ReqCtx = {
	path: string;
	origin: string | null;
	range: string | null;
};

type VerifyResult = { ok: true; payload: TokenPayload } | { ok: false; reason: string };

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

function buildCorsHeaders(allowedOrigin: string): Headers {
	const headers = new Headers();
	headers.set('Access-Control-Allow-Origin', allowedOrigin);
	headers.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
	headers.set('Access-Control-Allow-Headers', 'Content-Type, Range');
	headers.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
	headers.set('Vary', 'Origin');
	return headers;
}

function responseWithCors(body: BodyInit | null, status: number, allowedOrigin: string, extraHeaders?: HeadersInit): Response {
	const headers = buildCorsHeaders(allowedOrigin);
	if (extraHeaders) {
		new Headers(extraHeaders).forEach((v, k) => headers.set(k, v));
	}
	return new Response(body, { status, headers });
}

function reject(ctx: ReqCtx, allowedOrigin: string, status: number, message: string, reason: string): Response {
	logEvent('request_rejected', ctx, status, reason);
	return responseWithCors(message, status, allowedOrigin, {
		'Content-Type': 'text/plain; charset=utf-8',
	});
}

function b64uDecode(str: string): string {
	let b = str.replace(/-/g, '+').replace(/_/g, '/');
	while (b.length % 4) b += '=';
	return atob(b);
}

function b64uEncode(str: string): string {
	return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hexToBytes(hex: string): Uint8Array | null {
	if (!/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) return null;
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
	return out;
}

async function importHmacKey(secret: string, usages: ('sign' | 'verify')[]): Promise<CryptoKey> {
	return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, usages);
}

async function sign(body: string, secret: string): Promise<string> {
	const key = await importHmacKey(secret, ['sign']);
	const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
	const sigHex = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
	return b64uEncode(`${body}.${sigHex}`);
}

async function verify(token: string, secret: string): Promise<VerifyResult> {
	try {
		const decoded = b64uDecode(token);
		const lastDot = decoded.lastIndexOf('.');
		if (lastDot <= 0 || lastDot === decoded.length - 1) {
			return { ok: false, reason: 'malformed_token' };
		}

		const json = decoded.slice(0, lastDot);
		const sigHex = decoded.slice(lastDot + 1);
		const sigBytes = hexToBytes(sigHex);
		if (!sigBytes) return { ok: false, reason: 'invalid_signature_encoding' };

		const key = await importHmacKey(secret, ['verify']);
		const isValid = await crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(json));
		if (!isValid) return { ok: false, reason: 'signature_mismatch' };
		return { ok: true, payload: JSON.parse(json) as TokenPayload };
	} catch {
		return { ok: false, reason: 'token_decode_failed' };
	}
}

function appendSegmentToken(uri: string, token: string): string {
	try {
		const [baseWithQuery, hash] = uri.split('#', 2);
		const [base, query] = baseWithQuery.split('?', 2);
		const params = new URLSearchParams(query ?? '');
		params.set('st', token);
		const out = `${base}?${params.toString()}`;
		return hash ? `${out}#${hash}` : out;
	} catch {
		return uri;
	}
}

function rewritePlaylist(playlist: string, segToken: string): string {
	return playlist
		.split('\n')
		.map((line) => {
			const trimmed = line.trim();
			if (!trimmed) return line;
			if (!trimmed.startsWith('#') && /\.ts(\?|$)/i.test(trimmed)) {
				return appendSegmentToken(trimmed, segToken);
			}
			if (trimmed.includes('URI="') && /\.ts(\?|")/i.test(trimmed)) {
				return line.replace(/URI="([^"]+\.ts[^"]*)"/gi, (_m, uri: string) => `URI="${appendSegmentToken(uri, segToken)}"`);
			}
			return line;
		})
		.join('\n');
}

function parseRange(rangeHeader: string | null): { range?: R2Range; partial: boolean; valid: boolean } {
	if (!rangeHeader) return { partial: false, valid: true };
	const value = rangeHeader.trim();
	if (!value.startsWith('bytes=')) return { partial: false, valid: false };

	const spec = value.slice(6).trim();
	if (!spec || spec.includes(',')) return { partial: false, valid: false };

	const startEnd = /^(\d+)-(\d*)$/.exec(spec);
	if (startEnd) {
		const start = Number.parseInt(startEnd[1], 10);
		const end = startEnd[2] ? Number.parseInt(startEnd[2], 10) : undefined;
		if (!Number.isFinite(start) || start < 0) return { partial: false, valid: false };
		if (end !== undefined && (!Number.isFinite(end) || end < start)) return { partial: false, valid: false };
		return {
			range: {
				offset: start,
				length: end === undefined ? undefined : end - start + 1,
			},
			partial: true,
			valid: true,
		};
	}

	const suffix = /^-(\d+)$/.exec(spec);
	if (suffix) {
		const n = Number.parseInt(suffix[1], 10);
		if (!Number.isFinite(n) || n <= 0) return { partial: false, valid: false };
		return { range: { suffix: n }, partial: true, valid: true };
	}

	return { partial: false, valid: false };
}

function inferReturnedRange(obj: R2ObjectBody): { offset: number; length: number } {
	const info = obj.range as { offset?: number; length?: number } | undefined;
	const offset = typeof info?.offset === 'number' ? info.offset : 0;
	const length = typeof info?.length === 'number' ? info.length : Math.max(obj.size - offset, 0);
	return { offset, length };
}

export default {
	async fetch(req: Request, env: Env): Promise<Response> {
		const origin = req.headers.get('Origin');
		const allowed = env.ALLOWED_ORIGIN;
		const url = new URL(req.url);
		const path = url.pathname;
		const ctx: ReqCtx = {
			path,
			origin,
			range: req.headers.get('Range'),
		};

		try {
			if (req.method === 'OPTIONS') {
				return responseWithCors(null, 204, allowed);
			}

			if (req.method !== 'GET' && req.method !== 'HEAD') {
				return reject(ctx, allowed, 405, 'Method not allowed', 'method_not_allowed');
			}

			// Production-safe CORS:
			// - allow when Origin header is missing
			// - reject only when Origin exists and mismatches ALLOWED_ORIGIN
			if (origin && origin !== allowed) {
				return reject(ctx, allowed, 403, 'Origin not allowed', 'origin_mismatch');
			}

			if (path.endsWith('.m3u8')) {
				const token = url.searchParams.get('token');
				if (!token) return reject(ctx, allowed, 403, 'Missing video token', 'video_token_missing');

				const main = await verify(token, env.VIDEO_TOKEN_SECRET);
				if (!main.ok) return reject(ctx, allowed, 403, 'Invalid video token', `video_token_invalid:${main.reason}`);
				if (typeof main.payload.exp !== 'number' || main.payload.exp <= Math.floor(Date.now() / 1000)) {
					return reject(ctx, allowed, 403, 'Invalid video token', 'video_token_expired');
				}
				if (typeof main.payload.vid !== 'string' || !main.payload.vid) {
					return reject(ctx, allowed, 403, 'Invalid video token', 'video_token_missing_vid');
				}

				const obj = await env.R2_BUCKET.get(path.slice(1));
				if (!obj) return reject(ctx, allowed, 404, 'Video not found', 'm3u8_not_found');

				const segToken = await sign(JSON.stringify({ vid: main.payload.vid }), env.VIDEO_TOKEN_SECRET);
				const rawPlaylist = await obj.text();
				const playlist = rewritePlaylist(rawPlaylist, segToken);
				const contentLength = new TextEncoder().encode(playlist).byteLength;

				return responseWithCors(req.method === 'HEAD' ? null : playlist, 200, allowed, {
					'Content-Type': 'application/vnd.apple.mpegurl',
					'Cache-Control': 'no-store',
					'Accept-Ranges': 'bytes',
					'Content-Length': String(contentLength),
				});
			}

			if (path.endsWith('.ts')) {
				const st = url.searchParams.get('st');
				if (!st) return reject(ctx, allowed, 403, 'Missing segment token', 'segment_token_missing');

				const seg = await verify(st, env.VIDEO_TOKEN_SECRET);
				if (!seg.ok) return reject(ctx, allowed, 403, 'Invalid segment token', `segment_token_invalid:${seg.reason}`);
				if (typeof seg.payload.vid !== 'string' || !path.includes(seg.payload.vid)) {
					return reject(ctx, allowed, 403, 'Invalid segment token', 'segment_token_vid_mismatch');
				}
			}

			const parsed = parseRange(req.headers.get('Range'));
			if (!parsed.valid) return reject(ctx, allowed, 416, 'Invalid Range header', 'range_parse_failed');

			const obj = await env.R2_BUCKET.get(path.slice(1), parsed.range ? { range: parsed.range } : undefined);
			if (!obj) return reject(ctx, allowed, 404, 'File not found', path.endsWith('.ts') ? 'segment_not_found' : 'object_not_found');

			const headers = buildCorsHeaders(allowed);
			obj.writeHttpMetadata(headers);
			headers.set('Accept-Ranges', 'bytes');

			let status = 200;
			if (parsed.partial) {
				const { offset, length } = inferReturnedRange(obj);
				const end = offset + length - 1;
				headers.set('Content-Range', `bytes ${offset}-${end}/${obj.size}`);
				headers.set('Content-Length', String(length));
				status = 206;
			} else {
				headers.set('Content-Length', String(obj.size));
			}

			if (path.endsWith('.ts')) {
				headers.set('Content-Type', 'video/mp2t');
				headers.set('Cache-Control', 'public, max-age=31536000, immutable');
			}

			return new Response(req.method === 'HEAD' ? null : obj.body, {
				status,
				headers,
			});
		} catch (error) {
			const message = error instanceof Error ? error.message : 'Unknown error';
			logEvent('worker_error', ctx, 500, message);
			return responseWithCors('Internal error', 500, allowed, {
				'Content-Type': 'text/plain; charset=utf-8',
			});
		}
	},
};
