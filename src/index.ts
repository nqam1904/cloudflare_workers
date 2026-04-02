/* ===================== CONSTANTS ===================== */

const DISCORD_FIELD_VALUE_LIMIT = 1000;
const SEGMENT_TOKEN_TTL_SECONDS = 60 * 60 * 6; // 6 hours

/* ===================== ENV ===================== */

export interface Env {
	VIDEO_TOKEN_SECRET: string;
	R2_BUCKET: R2Bucket;
	ALLOWED_ORIGIN: string;
	WEBHOOK_DISCORD_URL?: string;
	BACKEND_API_URL: string;
}

/* ===================== TYPES ===================== */

type TokenPayload = {
	vid: string;
	exp?: number;
	[k: string]: unknown;
};

/**
 * Extended context — carries all request metadata through the entire lifecycle.
 * Every log and webhook call receives this, so debug info is always complete.
 */
type ReqCtx = {
	path: string;
	origin: string | null;
	referer: string;
	userAgent: string;
	range: string | null;
	clientIp: string;
	country: string;
};

type VerifyResult = { ok: true; payload: TokenPayload } | { ok: false; reason: string };

/* ===================== LOGGING ===================== */

type LogLevel = 'info' | 'warn' | 'error';

type LogEventName = 'preflight' | 'manifest_served' | 'r2_served' | 'request_rejected' | 'worker_error' | 'token_verify_failed';

type LogPayload = {
	event: LogEventName;
	level: LogLevel;
	status: number;
	path: string;
	origin: string | null;
	referer: string;
	userAgent: string;
	clientIp: string;
	country: string;
	range: string | null;
	reason?: string;
	detail?: string;
};

function logEvent(event: LogEventName, level: LogLevel, ctx: ReqCtx, status: number, reason?: string, detail?: string): void {
	const payload: LogPayload = {
		event,
		level,
		status,
		path: ctx.path,
		origin: ctx.origin,
		referer: ctx.referer || '—',
		userAgent: ctx.userAgent || '—',
		clientIp: ctx.clientIp || '—',
		country: ctx.country || '—',
		range: ctx.range,
	};
	if (reason) payload.reason = reason;
	if (detail) payload.detail = detail;

	if (level === 'error') console.error(JSON.stringify(payload));
	else if (level === 'warn') console.warn(JSON.stringify(payload));
	else console.log(JSON.stringify(payload));
}

/* ===================== CORS ===================== */

function normalizeOrigin(value: string | null): string | null {
	if (!value) return null;
	try {
		// URL.origin normalizes protocol/host/port and removes trailing slash/path/query.
		return new URL(value.trim()).origin.toLowerCase();
	} catch {
		// Fallback for non-standard values (rare) — still remove trailing slash.
		return value.trim().replace(/\/+$/, '').toLowerCase();
	}
}

function parseAllowedOrigins(raw: string): string[] {
	return raw
		.split(',')
		.map((v) => normalizeOrigin(v))
		.filter((v): v is string => Boolean(v));
}

function resolveAllowedRequestOrigin(origin: string | null, referer: string, allowedRaw: string): string | null {
	const allowedOrigins = parseAllowedOrigins(allowedRaw);
	if (allowedOrigins.length === 0) return null;

	const normalizedOrigin = normalizeOrigin(origin);
	if (normalizedOrigin && allowedOrigins.includes(normalizedOrigin)) {
		return normalizedOrigin;
	}

	const refererOrigin = normalizeOrigin(referer);
	if (refererOrigin && allowedOrigins.includes(refererOrigin)) {
		return refererOrigin;
	}

	return null;
}

function isAllowedOrigin(origin: string | null, referer: string, allowedRaw: string): boolean {
	return resolveAllowedRequestOrigin(origin, referer, allowedRaw) !== null;
}

function cors(origin: string | null, referer: string, allowedRaw: string): Headers {
	const h = new Headers();
	const matchedOrigin = resolveAllowedRequestOrigin(origin, referer, allowedRaw);
	if (matchedOrigin) {
		h.set('Access-Control-Allow-Origin', matchedOrigin);
		h.set('Access-Control-Allow-Credentials', 'true');
	}
	h.set('Vary', 'Origin');
	h.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
	h.set('Access-Control-Allow-Headers', 'Content-Type, Range');
	h.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');
	return h;
}

/* ===================== DISCORD WEBHOOK (unified) ===================== */

type DiscordColor = number;
const COLOR_RED: DiscordColor = 0xff0000;
const COLOR_ORANGE: DiscordColor = 0xff8800;
const COLOR_YELLOW: DiscordColor = 0xffcc00;

type WebhookEvent =
	| { kind: 'request_rejected'; ctx: ReqCtx; status: number; reason: string }
	| { kind: 'token_verify_failed'; ctx: ReqCtx; tokenPrefix: string; reason: string; diag: Record<string, unknown> }
	| { kind: 'worker_error'; ctx: ReqCtx; error: string };

/**
 * Single unified webhook dispatcher.
 * All Discord notifications go through here — no more scattered fire* functions.
 *
 * Color scheme:
 *   🔴 request_rejected  — 403/404 from origin/token issues
 *   🟠 token_verify_failed — bad sig / expired / malformed
 *   🟡 worker_error        — unexpected 500
 */
function fireWebhook(execCtx: ExecutionContext, env: Env, event: WebhookEvent): void {
	const webhookUrl = env.WEBHOOK_DISCORD_URL;
	if (!webhookUrl) return;

	let title: string;
	let color: DiscordColor;
	let fields: Array<{ name: string; value: string; inline?: boolean }>;

	// Common request context fields — always included for traceability
	const ctxFields = (ctx: ReqCtx) => [
		{ name: 'Path', value: ctx.path || '—', inline: true },
		{ name: 'Origin', value: ctx.origin || '—', inline: true },
		{ name: 'Referer', value: ctx.referer || '—', inline: false },
		{ name: 'User-Agent', value: ctx.userAgent || '—', inline: false },
		{ name: 'Client IP', value: ctx.clientIp || '—', inline: true },
		{ name: 'Country', value: ctx.country || '—', inline: true },
		{ name: 'Range', value: ctx.range || 'none', inline: true },
	];

	switch (event.kind) {
		case 'request_rejected':
			title = `🚨 [${event.status}] Request rejected`;
			color = COLOR_RED;
			fields = [
				{ name: 'Reason', value: event.reason, inline: false },
				{ name: 'Status', value: String(event.status), inline: true },
				...ctxFields(event.ctx),
			];
			break;

		case 'token_verify_failed':
			title = `🟠 Token verify failed: ${event.reason}`;
			color = COLOR_ORANGE;
			fields = [
				{ name: 'Reason', value: event.reason, inline: false },
				{ name: 'Token (prefix)', value: event.tokenPrefix || '—', inline: true },
				{ name: 'Diagnostic', value: JSON.stringify(event.diag).slice(0, 500), inline: false },
				...ctxFields(event.ctx),
			];
			break;

		case 'worker_error':
			title = '🟡 Worker uncaught error';
			color = COLOR_YELLOW;
			fields = [{ name: 'Error', value: event.error.slice(0, 500), inline: false }, ...ctxFields(event.ctx)];
			break;
	}

	const embed = {
		title,
		color,
		fields: fields.map((f) => ({ ...f, value: f.value.slice(0, DISCORD_FIELD_VALUE_LIMIT) })),
		timestamp: new Date().toISOString(),
		footer: { text: 'NISE Worker' },
	};

	execCtx.waitUntil(
		fetch(webhookUrl, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ embeds: [embed] }),
		}).then(() => undefined),
	);
}

/* ===================== FORWARD TO BACKEND ===================== */

function forwardToBackend(execCtx: ExecutionContext, env: Env, event: LogEventName, ctx: ReqCtx, status: number, reason?: string, detail?: string): void {
	if (!env.BACKEND_API_URL) return;

	const body = {
		event,
		status,
		reason: reason || null,
		detail: detail || null,
		path: ctx.path,
		origin: ctx.origin,
		referer: ctx.referer || null,
		userAgent: ctx.userAgent || null,
		clientIp: ctx.clientIp || null,
		country: ctx.country || null,
		range: ctx.range || null,
		videoId: extractVidFromPath(ctx.path),
		timestamp: new Date().toISOString(),
	};

	execCtx.waitUntil(
		fetch(`https://loveblender.online/api/worker-monitor/ingest`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body),
		}).catch(() => {}),
	);
}

function extractVidFromPath(path: string): string | null {
	const parts = path.split('/').filter(Boolean);
	// /course-videos/{vid}/hls/...
	if (parts.length >= 2 && parts[0] === 'course-videos') {
		return parts[1];
	}
	return null;
}

/* ===================== REJECT HELPER ===================== */

function makeReject(ctx: ReqCtx, allowed: string, env: Env, execCtx: ExecutionContext) {
	return (status: number, reason: string): Response => {
		logEvent('request_rejected', status >= 500 ? 'error' : 'warn', ctx, status, reason);
		fireWebhook(execCtx, env, { kind: 'request_rejected', ctx, status, reason });
		forwardToBackend(execCtx, env, 'request_rejected', ctx, status, reason);

		const h = cors(ctx.origin, ctx.referer, allowed);
		h.set('Content-Type', 'text/plain');
		return new Response(reason, { status, headers: h });
	};
}

function resp(body: BodyInit | null, status: number, ctx: ReqCtx, allowed: string, extra?: HeadersInit): Response {
	const h = cors(ctx.origin, ctx.referer, allowed);
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
	return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ===================== SECURITY HELPERS ===================== */

function safeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return result === 0;
}

/* ===================== SIGN / VERIFY ===================== */

async function sign(body: string, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
	const sig = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
	return b64uEncode(`${body}.${sig}`);
}

/**
 * ctx is passed in so that token errors include origin + referer in Discord notifications.
 * Previously token errors had NO request context — impossible to trace which user/page triggered it.
 */
async function verifyToken(token: string, secret: string, ctx: ReqCtx, execCtx: ExecutionContext, env: Env): Promise<VerifyResult> {
	const tokenPrefix = token ? `${token.slice(0, 20)}…` : '—';

	const fail = (reason: string, diag: Record<string, unknown> = {}): VerifyResult => {
		logEvent('token_verify_failed', 'warn', ctx, 403, reason);
		fireWebhook(execCtx, env, { kind: 'token_verify_failed', ctx, tokenPrefix, reason, diag });
		forwardToBackend(execCtx, env, 'token_verify_failed', ctx, 403, reason, JSON.stringify(diag).slice(0, 500));
		return { ok: false, reason };
	};

	try {
		const decoded = b64uDecode(token);

		// [FIX] lastIndexOf instead of split('.') — JSON body can contain decimal dots
		const lastDot = decoded.lastIndexOf('.');
		if (lastDot === -1) return fail('malformed_token', { decoded: decoded.slice(0, 80) });

		const json = decoded.slice(0, lastDot);
		const sig = decoded.slice(lastDot + 1);
		if (!json || !sig) return fail('malformed_token', { hasJson: !!json, hasSig: !!sig });

		const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
		const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(json));
		const expected = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

		// Never log full sig — only short prefix for correlation
		if (!safeEqual(expected, sig)) return fail('bad_signature', { sigPrefix: sig.slice(0, 8) });

		const payload = JSON.parse(json) as TokenPayload;

		if (payload.exp !== undefined && payload.exp <= Math.floor(Date.now() / 1000)) {
			const expiredAt = new Date(payload.exp * 1000);
			const formatted = expiredAt.toLocaleString('vi-VN', {
				day: '2-digit',
				month: '2-digit',
				year: 'numeric',
				hour: '2-digit',
				minute: '2-digit',
				hour12: false,
			});
			return fail('token_expired', {
				vid: payload.vid,
				expiredAt: formatted,
				serverTime: new Date().toLocaleString('vi-VN', {
					day: '2-digit',
					month: '2-digit',
					year: 'numeric',
					hour: '2-digit',
					minute: '2-digit',
					hour12: false,
				}),
			});
		}

		return { ok: true, payload };
	} catch (err: unknown) {
		return fail(`decode_error: ${err instanceof Error ? err.message : 'Unknown'}`, {});
	}
}

/* ===================== WORKER ===================== */

export default {
	async fetch(req: Request, env: Env, execCtx: ExecutionContext): Promise<Response> {
		const url = new URL(req.url);
		const origin = req.headers.get('Origin');
		const referer = req.headers.get('Referer') || '';
		const userAgent = req.headers.get('User-Agent') || '';
		const clientIp = req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || '';
		const country = (req.cf?.country as string) || '';
		const allowed = env.ALLOWED_ORIGIN;

		const ctx: ReqCtx = {
			path: url.pathname,
			origin,
			referer,
			userAgent,
			range: req.headers.get('Range'),
			clientIp,
			country,
		};

		// reject() is now ctx-aware — always includes origin + referer in logs & Discord
		const reject = makeReject(ctx, allowed, env, execCtx);

		try {
			const { path } = ctx;

			/* ===== OPTIONS ===== */
			if (req.method === 'OPTIONS') {
				logEvent('preflight', 'info', ctx, 204);
				return resp('OK', 204, ctx, allowed);
			}

			/* ===== ORIGIN CHECK ===== */
			if (path.endsWith('.m3u8')) {
				if (!origin && !referer) {
					return reject(403, 'missing_origin');
				}

				if (!isAllowedOrigin(origin, referer, allowed)) {
					return reject(403, 'origin_not_allowed');
				}
			}

			/* ===== MANIFEST (.m3u8) ===== */
			if (path.endsWith('.m3u8')) {
				const token = url.searchParams.get('token');
				if (!token) return reject(403, 'missing_video_token');

				const result = await verifyToken(token, env.VIDEO_TOKEN_SECRET, ctx, execCtx, env);
				if (!result.ok) return reject(403, result.reason);

				const r2Key = path.slice(1);
				const obj = await env.R2_BUCKET.get(r2Key);
				if (!obj) return reject(404, 'manifest_not_found');

				// Segment token: short-lived (6h), bound to vid
				const segToken = await sign(
					JSON.stringify({
						vid: result.payload.vid,
						exp: Math.floor(Date.now() / 1000) + SEGMENT_TOKEN_TTL_SECONDS,
					}),
					env.VIDEO_TOKEN_SECRET,
				);

				let playlist = await obj.text();
				// Append ?st=<token> to every .ts line in the playlist
				playlist = playlist.replace(/^(?!#)(.+\.ts)$/gm, `$1?st=${segToken}`);

				logEvent('manifest_served', 'info', ctx, 200);

				return resp(playlist, 200, ctx, allowed, {
					'Content-Type': 'application/vnd.apple.mpegurl',
					'Cache-Control': 'no-store',
				});
			}

			/* ===== SEGMENT (.ts) ===== */
			if (path.endsWith('.ts')) {
				const st = url.searchParams.get('st');
				if (!st) return reject(403, 'missing_segment_token');

				const result = await verifyToken(st, env.VIDEO_TOKEN_SECRET, ctx, execCtx, env);
				if (!result.ok) return reject(403, `seg_${result.reason}`);

				// Path structure: /course-videos/{vid}/hls/seg_xxx.ts
				const parts = path.split('/').filter(Boolean);
				const pathVid = parts.length >= 2 ? parts[1] : null;

				if (!result.payload.vid || result.payload.vid !== pathVid) {
					return reject(403, 'seg_vid_mismatch');
				}
			}

			/* ===== R2 FETCH + RANGE SUPPORT ===== */
			const rangeHeader = req.headers.get('Range');
			let range: R2Range | undefined;

			if (rangeHeader) {
				const m = rangeHeader.match(/bytes=(\d+)-(\d*)/);
				if (m) {
					const start = parseInt(m[1], 10);
					const end = m[2] ? parseInt(m[2], 10) : undefined;
					range = { offset: start, length: end !== undefined ? end - start + 1 : undefined };
				}
			}

			const r2Key = path.slice(1);
			const obj = await env.R2_BUCKET.get(r2Key, range ? { range } : undefined);
			if (!obj) return reject(404, 'file_not_found');

			const headers = cors(origin, referer, allowed);
			obj.writeHttpMetadata(headers);
			headers.set('Accept-Ranges', 'bytes');

			if (path.endsWith('.ts')) {
				headers.set('Content-Type', 'video/mp2t');
				headers.set('Cache-Control', 'public, max-age=31536000, immutable');
			}

			if (range && obj.range) {
				const off = (obj.range as { offset?: number }).offset ?? 0;
				const len = (obj.range as { length?: number }).length ?? obj.size;
				headers.set('Content-Range', `bytes ${off}-${off + len - 1}/${obj.size}`);
			}

			const status = range ? 206 : 200;
			logEvent('r2_served', 'info', ctx, status);

			// .ts segments: immutable → cache at Cloudflare edge PoP
			// Cache key = path only (strip ?st=... token so all users share the same cache entry)
			if (path.endsWith('.ts')) {
				return new Response(obj.body, {
					status,
					headers,
					// @ts-ignore — Cloudflare Workers cf property
					cf: {
						cacheEverything: true,
						cacheTtl: 31536000,
						cacheKey: path,
					},
				});
			}

			return new Response(obj.body, { status, headers });
		} catch (error) {
			const message = error instanceof Error ? `${error.name}: ${error.message}` : 'Unknown error';
			logEvent('worker_error', 'error', ctx, 500, message);
			fireWebhook(execCtx, env, { kind: 'worker_error', ctx, error: message });
			forwardToBackend(execCtx, env, 'worker_error', ctx, 500, message);
			return resp(message, 500, ctx, allowed, { 'Content-Type': 'text/plain' });
		}
	},
};
