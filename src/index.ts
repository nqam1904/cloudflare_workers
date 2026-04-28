const DISCORD_FIELD_VALUE_LIMIT = 1000;
const CLOUDFLARE_WEB_BOT_AUTH_AGENT = 'https://web-bot-auth-directory.radar.cloudflare.com/';
const ADDITIONAL_ALLOWED_ORIGINS = ['https://www.loveblender.online'];

function truncateWebhookFieldValue(value: string): string {
	return value.slice(0, DISCORD_FIELD_VALUE_LIMIT);
}

function getHeaderValue(headers: Headers | Record<string, string> | undefined, name: string): string | null {
	if (!headers) return null;
	if (typeof (headers as Headers).get === 'function') return (headers as Headers).get(name);
	return (headers as Record<string, string>)[name.toLowerCase()] ?? (headers as Record<string, string>)[name] ?? null;
}

function normalizeSignatureAgent(value: string | null | undefined): string {
	return (value ?? '').trim().replace(/^"+|"+$/g, '');
}

function isCloudflareWebBotAuthRequest(req: { headers?: Headers | Record<string, string> } | undefined): boolean {
	const signatureAgent = normalizeSignatureAgent(getHeaderValue(req?.headers, 'signature-agent'));
	return signatureAgent === CLOUDFLARE_WEB_BOT_AUTH_AGENT;
}

export interface Env {
	VIDEO_TOKEN_SECRET: string;
	R2_BUCKET: R2Bucket;
	ALLOWED_ORIGIN: string;
	WEBHOOK_DISCORD_URL?: string;
	NISE_BE_API_URL?: string;
	NISE_BE_INGEST_URL?: string;
}

/* ===================== TYPES ===================== */

type TokenPayload = {
	vid: string;
	exp?: number;
	userId?: string;
	email?: string;
	ip?: string;
	[k: string]: unknown;
};

type UserIdentity = {
	userId?: string;
	email?: string;
};

type ReqCtx = {
	path: string;
	origin: string | null;
	range: string | null;
};

type VerifyResult = { ok: true; payload: TokenPayload } | { ok: false; reason: string };

/* ===================== LOGGING ===================== */

function logEvent(event: string, ctx: ReqCtx, status: number, reason?: string): void {
	const payload: any = {
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

function normalizeOrigin(origin: string): string {
	return origin.trim().replace(/\/+$/, '');
}

function getAllowedOrigins(envAllowedOrigin: string): string[] {
	return Array.from(
		new Set([...envAllowedOrigin.split(','), ...ADDITIONAL_ALLOWED_ORIGINS].map(normalizeOrigin).filter(Boolean)),
	);
}

function isAllowedOrigin(origin: string | null, referer: string, allowed: string): boolean {
	const allowedOrigins = getAllowedOrigins(allowed);
	if (!origin && !referer) return false;
	if (origin && allowedOrigins.includes(normalizeOrigin(origin))) return true;
	if (referer) {
		return allowedOrigins.some((allowedOrigin) => {
			const normalizedReferer = normalizeOrigin(referer);
			return normalizedReferer === allowedOrigin || normalizedReferer.startsWith(`${allowedOrigin}/`);
		});
	}
	return false;
}

function cors(origin: string | null, referer: string, allowed: string): Headers {
	const h = new Headers();
	const allowedOrigins = getAllowedOrigins(allowed);

	if (isAllowedOrigin(origin, referer, allowed) && allowedOrigins.length > 0) {
		h.set('Access-Control-Allow-Origin', origin ? normalizeOrigin(origin) : allowedOrigins[0]);
		h.set('Access-Control-Allow-Credentials', 'true');
	}

	h.set('Vary', 'Origin');
	h.set('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
	h.set('Access-Control-Allow-Headers', 'Content-Type, Range');
	h.set('Access-Control-Expose-Headers', 'Content-Length, Content-Range, Accept-Ranges');

	return h;
}

/* ===================== DISCORD WEBHOOK ===================== */

type WebhookPayload = {
	title?: string;
	color?: number;
	fields?: Array<{ name: string; value: string; inline?: boolean }>;
	footerText?: string;
	userId?: string;
	userEmail?: string;
	nodeEnv?: string;
};

function buildDiscordEmbed(payload: WebhookPayload): object {
	const title = payload.title ?? 'Notification';
	const color = typeof payload.color === 'number' ? payload.color : 0xff0000;
	const sanitizedFields = (payload.fields ?? []).map((f) => ({
		...f,
		value: truncateWebhookFieldValue(f.value),
	}));
	return {
		title,
		color,
		fields: [...sanitizedFields],
		timestamp: new Date().toISOString(),
		footer: { text: payload.footerText ?? 'NISE Worker' },
	};
}

function notifyDiscordWebhook(webhookUrl: string, payload: WebhookPayload): Promise<void> {
	const embed = buildDiscordEmbed(payload);
	return fetch(webhookUrl, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ embeds: [embed] }),
	}).then(() => undefined);
}

function buildUserIdentityFields(identity: UserIdentity): Array<{ name: string; value: string; inline?: boolean }> {
	return [
		{ name: '👤 User ID', value: identity.userId || '—', inline: true },
		{ name: '📧 Email', value: identity.email || '—', inline: true },
	];
}

function fireErrorWebhook(
	execCtx: ExecutionContext,
	env: Env,
	opts: {
		status: number;
		reason: string;
		referer: string;
		origin: string | null;
		ctx: ReqCtx;
		req?: any;
		identity?: UserIdentity;
	},
): void {
	const webhookUrl = env.WEBHOOK_DISCORD_URL;
	if (!webhookUrl) return;
	const identity = opts.identity ?? {};
	const payload: WebhookPayload = {
		title: '🚨 Worker reject',
		color: 0xff0000,
		fields: [
			...buildUserIdentityFields(identity),
			{ name: 'Status', value: String(opts.status), inline: false },
			{ name: 'Reason', value: opts.reason, inline: false },
			{ name: 'Referer', value: opts.referer || '—', inline: false },
			{ name: 'Origin', value: opts.origin || '—', inline: false },
			{ name: 'Context', value: JSON.stringify(opts.ctx), inline: false },
			{ name: 'Request', value: JSON.stringify(opts.req), inline: false },
		],
		footerText: 'NISE Worker',
	};
	execCtx.waitUntil(notifyDiscordWebhook(webhookUrl, payload));
}

function fireIngestWarningWebhook(
	execCtx: ExecutionContext,
	env: Env,
	opts: {
		status: string;
		url?: string;
		error?: string;
		ctx: ReqCtx;
		reason: string;
	},
): void {
	const webhookUrl = env.WEBHOOK_DISCORD_URL;
	if (!webhookUrl) return;
	execCtx.waitUntil(
		notifyDiscordWebhook(webhookUrl, {
			title: '⚠️ Worker ingest failed',
			color: 0xf59e0b,
			fields: [
				{ name: 'Status', value: opts.status, inline: false },
				{ name: 'URL', value: opts.url || '—', inline: false },
				{ name: 'Reason', value: opts.reason, inline: false },
				{ name: 'Error', value: opts.error || '—', inline: false },
				{ name: 'Context', value: JSON.stringify(opts.ctx), inline: false },
			],
			footerText: 'NISE Worker',
		}),
	);
}

/**
 * Removed: fireErrorVerifyTokenWebhook was causing duplicate Discord
 * notifications — the caller (reject → fireErrorWebhook) already sends
 * a Discord alert with full request context.  Token verification details
 * are now logged via console.error for Cloudflare dashboard inspection.
 */
function logTokenVerifyError(reason: string, detail: Record<string, unknown>): void {
	console.error(`[verifyToken] ${reason}`, JSON.stringify(detail));
}

/* ===================== NISE-BE INGEST API ===================== */

function extractVideoIdFromPath(path: string): string | null {
	const parts = path.split('/').filter(Boolean);
	return parts.length >= 2 && parts[0] === 'course-videos' ? parts[1] : null;
}

function resolveIngestUrl(env: Env): string | null {
	if (env.NISE_BE_INGEST_URL) {
		return env.NISE_BE_INGEST_URL.trim();
	}
	if (!env.NISE_BE_API_URL) {
		return null;
	}
	const apiUrl = env.NISE_BE_API_URL.trim()
		.replace(/\/+$/, '')
		.replace(/\/api$/, '');
	return `${apiUrl}/worker-monitor/ingest`;
}

function fireIngestApi(
	execCtx: ExecutionContext,
	env: Env,
	opts: {
		event: 'request_rejected' | 'token_verify_failed' | 'worker_error';
		status: number;
		reason: string;
		ctx: ReqCtx;
		referer: string;
		userAgent?: string;
		clientIp?: string;
		country?: string;
		identity?: UserIdentity;
	},
): void {
	const ingestUrl = resolveIngestUrl(env);
	if (!ingestUrl) {
		console.error('[fireIngestApi] missing NISE_BE_API_URL or NISE_BE_INGEST_URL');
		fireIngestWarningWebhook(execCtx, env, {
			status: 'missing_config',
			ctx: opts.ctx,
			reason: opts.reason,
		});
		return;
	}

	const body = {
		event: opts.event,
		status: opts.status,
		reason: opts.reason,
		path: opts.ctx.path,
		origin: opts.ctx.origin ?? undefined,
		referer: opts.referer || undefined,
		userAgent: opts.userAgent,
		clientIp: opts.clientIp,
		country: opts.country,
		range: opts.ctx.range ?? undefined,
		videoId: extractVideoIdFromPath(opts.ctx.path) ?? undefined,
		userId: opts.identity?.userId,
		email: opts.identity?.email,
		timestamp: new Date().toISOString(),
	};

	execCtx.waitUntil(
		fetch(ingestUrl, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'User-Agent': 'NISE-Cloudflare-Worker/1.0',
				'X-Worker-Log-Source': 'cloudflare-workers',
			},
			body: JSON.stringify(body),
		})
			.then(async (res) => {
				if (!res.ok) {
					const text = await res.text().catch(() => '');
					const error = `${res.status} ${res.statusText}: ${text}`;
					console.error(`[fireIngestApi] ${error}`);
					fireIngestWarningWebhook(execCtx, env, {
						status: 'http_error',
						url: ingestUrl,
						error,
						ctx: opts.ctx,
						reason: opts.reason,
					});
				}
			})
			.catch((err) => {
				const error = err instanceof Error ? err.message : String(err);
				console.error(`[fireIngestApi] fetch failed:`, err);
				fireIngestWarningWebhook(execCtx, env, {
					status: 'fetch_failed',
					url: ingestUrl,
					error,
					ctx: opts.ctx,
					reason: opts.reason,
				});
			}),
	);
}

function makeReject(
	origin: string,
	allowed: string,
	referer: string,
	env: Env,
	execCtx: ExecutionContext,
	req: any,
	identity: UserIdentity,
) {
	return (ctx: ReqCtx, status: number, reason: string): Response => {
		const userAgent = req?.headers?.['user-agent'] ?? undefined;
		const clientIp = req?.headers?.['cf-connecting-ip'] ?? undefined;
		const country = req?.headers?.['cf-ipcountry'] ?? undefined;
		const shouldNotify = !isCloudflareWebBotAuthRequest(req);

		if (shouldNotify) {
			fireErrorWebhook(execCtx, env, {
				status,
				reason,
				referer,
				origin,
				ctx,
				req,
				identity,
			});

			fireIngestApi(execCtx, env, {
				event: 'request_rejected',
				status,
				reason,
				ctx,
				referer,
				userAgent,
				clientIp,
				country,
				identity,
			});
		}

		logEvent('request_rejected', ctx, status, reason);
		const h = cors(origin, referer, allowed);
		h.set('Content-Type', 'text/plain');
		return new Response(reason, { status, headers: h });
	};
}

function resp(body: BodyInit | null, status: number, origin: string | null, referer: string, allowed: string, extra?: HeadersInit) {
	const h = cors(origin, referer, allowed);
	if (extra) new Headers(extra).forEach((v, k) => h.set(k, v));
	return new Response(body, { status, headers: h });
}

/* ===================== BASE64URL ===================== */

function b64uDecode(str: string): string {
	let b = str.replace(/-/g, '+').replace(/_/g, '/');
	while (b.length % 4) b += '=';
	return atob(b);
}

/**
 * Best-effort token payload decoder (no signature verification).
 * Used to enrich error webhooks with user identity (userId/email) even when
 * the token is invalid/expired/tampered — we still want to know WHO hit the
 * error in production monitoring.
 */
function tryDecodeTokenPayload(token: string | null | undefined): Partial<TokenPayload> | null {
	if (!token) return null;
	try {
		const decoded = b64uDecode(token);
		const lastDot = decoded.lastIndexOf('.');
		if (lastDot === -1) return null;
		const json = decoded.slice(0, lastDot);
		if (!json) return null;
		const parsed = JSON.parse(json) as Partial<TokenPayload>;
		return parsed && typeof parsed === 'object' ? parsed : null;
	} catch {
		return null;
	}
}

function extractUserIdentity(payload: Partial<TokenPayload> | null | undefined): UserIdentity {
	if (!payload) return {};
	const userId = typeof payload.userId === 'string' ? payload.userId : undefined;
	const email = typeof payload.email === 'string' ? payload.email : undefined;
	return { userId, email };
}

function extractUserIdentityFromUrl(url: URL): UserIdentity {
	const token = url.searchParams.get('token') || url.searchParams.get('st');
	return extractUserIdentity(tryDecodeTokenPayload(token));
}

function b64uEncode(str: string): string {
	return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ===================== SECURITY HELPERS ===================== */

function safeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let result = 0;
	for (let i = 0; i < a.length; i++) {
		result |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return result === 0;
}

/* ===================== SIGN / VERIFY ===================== */

async function sign(body: string, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

	const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));

	const sig = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

	return b64uEncode(`${body}.${sig}`);
}

async function verifyToken(token: string, secret: string, _execCtx?: ExecutionContext, _env?: Env): Promise<VerifyResult> {
	try {
		const decoded = b64uDecode(token);

		// NOTE: use lastIndexOf('.') instead of split('.') because the signed JSON
		// payload can contain dots (e.g. `ip: "58.186.71.156"`), which would make
		// split('.') chop the JSON into multiple pieces and mistake an IP octet
		// for the signature. Keep this consistent with nise-be and nise-fe.
		const lastDot = decoded.lastIndexOf('.');
		if (lastDot === -1) {
			logTokenVerifyError('malformed_token', { decoded });
			return { ok: false, reason: 'malformed_token' };
		}
		const json = decoded.slice(0, lastDot);
		const sig = decoded.slice(lastDot + 1);
		if (!json || !sig) {
			logTokenVerifyError('malformed_token', { json, sig });
			return { ok: false, reason: 'malformed_token' };
		}

		const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);

		const buf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(json));

		const expected = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

		if (!safeEqual(expected, sig)) {
			logTokenVerifyError('bad_signature', { expected, sig });
			return { ok: false, reason: 'bad_signature' };
		}

		const payload = JSON.parse(json) as TokenPayload;

		if (payload.exp !== undefined && payload.exp <= Math.floor(Date.now() / 1000)) {
			logTokenVerifyError('token_expired', { payload });
			return { ok: false, reason: 'token_expired' };
		}

		return { ok: true, payload };
	} catch (err: unknown) {
		logTokenVerifyError(`decode_error: ${err instanceof Error ? err.message : 'Unknown error'}`, { err: String(err) });
		return { ok: false, reason: 'decode_error' };
	}
}

/* ===================== WORKER ===================== */

export default {
	async fetch(req: Request, env: Env, execCtx: ExecutionContext): Promise<Response> {
		const origin = req.headers.get('Origin');
		const referer = req.headers.get('Referer') || '';
		const allowed = env.ALLOWED_ORIGIN;

		const url = new URL(req.url);

		const ctx: ReqCtx = {
			path: url.pathname,
			origin,
			range: req.headers.get('Range'),
		};

		const reqLog = { url: req.url, method: req.method, headers: Object.fromEntries(req.headers.entries()) };
		const identity = extractUserIdentityFromUrl(url);
		const reject = makeReject(origin || '', allowed, referer, env, execCtx, reqLog, identity);

		try {
			const { path } = ctx;

			/* ===== OPTIONS ===== */
			if (req.method === 'OPTIONS') {
				logEvent('preflight', ctx, 204);
				return resp('OK', 204, origin, referer, allowed);
			}

			/* ===== ORIGIN CHECK ===== */
			if (path.endsWith('.m3u8') || path.endsWith('.ts')) {
				if (!origin && !referer) {
					return reject(ctx, 403, 'missing_origin');
				}

				if (!isAllowedOrigin(origin, referer, allowed)) {
					return reject(ctx, 403, 'origin_not_allowed');
				}
			}
			/* ===== MANIFEST (.m3u8) ===== */
			if (path.endsWith('.m3u8')) {
				const token = url.searchParams.get('token');
				if (!token) {
					return reject(ctx, 403, 'missing_video_token');
				}

				const result = await verifyToken(token, env.VIDEO_TOKEN_SECRET, execCtx, env);

				if (!result.ok) {
					return reject(ctx, 403, result.reason);
				}

				const r2Key = path.slice(1);
				const obj = await env.R2_BUCKET.get(r2Key);
				if (!obj) {
					return reject(ctx, 404, 'manifest_not_found');
				}

				const clientIp = req.headers.get('cf-connecting-ip') || '';
				// Forward user identity from the m3u8 payload so segment-level
				// webhooks can attribute errors to the right user.
				const segPayload: Record<string, unknown> = {
					vid: result.payload.vid,
					ip: clientIp,
					exp: Math.floor(Date.now() / 1000) + 60 * 60 * 4,
				};
				if (typeof result.payload.userId === 'string') segPayload.userId = result.payload.userId;
				if (typeof result.payload.email === 'string') segPayload.email = result.payload.email;
				const segToken = await sign(JSON.stringify(segPayload), env.VIDEO_TOKEN_SECRET);

				let playlist = await obj.text();

				playlist = playlist.replace(/^(?!#)(.+\.ts)$/gm, `$1?st=${segToken}`);

				logEvent('manifest_served', ctx, 200);

				return resp(playlist, 200, origin, referer, allowed, {
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

				const result = await verifyToken(st, env.VIDEO_TOKEN_SECRET, execCtx, env);

				if (!result.ok) {
					return reject(ctx, 403, `seg_${result.reason}`);
				}

				// Extract vid from path:
				// /course-videos/{vid}/hls/seg_xxx.ts
				const parts = path.split('/').filter(Boolean);
				const pathVid = parts.length >= 2 ? parts[1] : null;

				if (!result.payload.vid || result.payload.vid !== pathVid) {
					return reject(ctx, 403, 'seg_vid_mismatch');
				}

				// Chặn IDM, tải tool bằng cách check IP
				const clientIp = req.headers.get('cf-connecting-ip') || '';
				if (result.payload.ip !== undefined && result.payload.ip !== clientIp) {
					return reject(ctx, 403, 'ip_stolen');
				}

				// Chặn tải trực tiếp qua tab mới bật (IDM hay bắt link thế này)
				const secFetchDest = req.headers.get('sec-fetch-dest');
				if (secFetchDest && !['empty', 'video', 'audio'].includes(secFetchDest)) {
					return reject(ctx, 403, 'direct_download_blocked');
				}

				const secFetchMode = req.headers.get('sec-fetch-mode');
				if (secFetchMode && ['navigate', 'nested-navigate'].includes(secFetchMode)) {
					return reject(ctx, 403, 'direct_download_blocked');
				}
			}

			/* ===== RANGE SUPPORT ===== */

			const rangeHeader = req.headers.get('Range');
			let range: R2Range | undefined;

			if (rangeHeader) {
				const m = rangeHeader.match(/bytes=(\d+)-(\d*)/);
				if (m) {
					const start = parseInt(m[1], 10);
					const endStr = m[2];
					const end = endStr ? parseInt(endStr, 10) : undefined;
					range = {
						offset: start,
						length: end !== undefined && !isNaN(end) ? end - start + 1 : undefined,
					};
				}
			}

			const r2Key = path.slice(1);
			const obj = await env.R2_BUCKET.get(r2Key, range ? { range } : undefined);

			if (!obj) {
				return reject(ctx, 404, 'file_not_found');
			}

			const headers = cors(origin, referer, allowed);
			obj.writeHttpMetadata(headers);
			headers.set('Accept-Ranges', 'bytes');

			if (path.endsWith('.ts')) {
				headers.set('Content-Type', 'video/mp2t');
				headers.set('Cache-Control', 'public, max-age=31536000, immutable');
				headers.set('Content-Disposition', 'inline; filename="video.ts"');
				headers.set('X-Content-Type-Options', 'nosniff');
			}

			if (range && obj.range) {
				// @ts-ignore
				const off = obj.range.offset ?? 0;
				// @ts-ignore
				const len = obj.range.length ?? obj.size;
				headers.set('Content-Range', `bytes ${off}-${off + len - 1}/${obj.size}`);
			}

			const status = range ? 206 : 200;
			logEvent('r2_served', ctx, status);

			return new Response(obj.body, {
				status,
				headers,
			});
		} catch (error) {
			const message = error instanceof Error ? `${error.name}: ${error.message}` : 'Unknown error';
			const shouldNotify = !isCloudflareWebBotAuthRequest(req);

			if (shouldNotify) {
				fireErrorWebhook(execCtx, env, {
					status: 500,
					reason: message,
					referer,
					origin,
					ctx,
					req: reqLog,
					identity,
				});

				fireIngestApi(execCtx, env, {
					event: 'worker_error',
					status: 500,
					reason: message,
					ctx,
					referer,
					userAgent: req.headers.get('user-agent') ?? undefined,
					clientIp: req.headers.get('cf-connecting-ip') ?? undefined,
					country: req.headers.get('cf-ipcountry') ?? undefined,
					identity,
				});
			}

			logEvent('worker_error', ctx, 500, message);

			return resp(message, 500, origin, referer, allowed, {
				'Content-Type': 'text/plain',
			});
		}
	},
};
