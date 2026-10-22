import BizError from '../error/biz-error';
import constant from '../const/constant';
import jwtUtils from '../utils/jwt-utils';
import KvConst from '../const/kv-const';
import dayjs from 'dayjs';
import userService from '../service/user-service';
import permService from '../service/perm-service';
import { t } from '../i18n/i18n'
import app from '../hono/hono';
import { getCookie, setCookie } from 'hono/cookie';
import { bodyLimit } from 'hono/body-limit';

const exclude = [
	'/login',
	'/register',
	'/setting/websiteConfig'
];

const requirePerms = [
	'/role/selectUse',
	'/email/send',
	'/email/delete',
	'/account/list',
	'/account/delete',
	'/account/add',
	'/my/delete',
	'/analysis/echarts',
	'/role/add',
	'/role/list',
	'/role/delete',
	'/role/tree',
	'/role/set',
	'/role/setDefault',
	'/allEmail/list',
	'/allEmail/delete',
	'/allEmail/batchDelete',
	'/allEmail/latest',
	'/setting/setBackground',
	'/setting/deleteBackground',
	'/setting/set',
	'/setting/query',
	'/setting/setBlacklist',
	'/user/delete',
	'/user/setPwd',
	'/user/setStatus',
	'/user/setType',
	'/user/list',
	'/user/restore',
	'/user/resetSendCount',
	'/user/add',
	'/user/deleteAccount',
	'/user/allAccount',
	'/regKey/add',
	'/regKey/list',
	'/regKey/delete',
	'/regKey/clearNotUse',
	'/regKey/history'
];

const premKey = {
	'email:delete': ['/email/delete'],
	'email:send': ['/email/send'],
	'account:add': ['/account/add'],
	'account:query': ['/account/list'],
	'account:delete': ['/account/delete'],
	'my:delete': ['/my/delete'],
	'role:add': ['/role/add'],
	'role:set': ['/role/set','/role/setDefault'],
	'role:query': ['/role/list', '/role/tree', '/role/selectUse'],
	'role:delete': ['/role/delete'],
	'user:query': ['/user/list','/user/allAccount'],
	'user:add': ['/user/add'],
	'user:reset-send': ['/user/resetSendCount'],
	'user:set-pwd': ['/user/setPwd'],
	'user:set-status': ['/user/setStatus', '/user/restore'],
	'user:set-type': ['/user/setType'],
	'user:delete': ['/user/delete','/user/deleteAccount'],
	'all-email:query': ['/allEmail/list','/allEmail/latest'],
	'all-email:delete': ['/allEmail/delete','/allEmail/batchDelete'],
	'setting:query': ['/setting/query'],
	'setting:set': ['/setting/set', '/setting/setBackground','/setting/deleteBackground','/setting/setBlacklist'],
	'analysis:query': ['/analysis/echarts'],
	'reg-key:add': ['/regKey/add'],
	'reg-key:query': ['/regKey/list','/regKey/history'],
	'reg-key:delete': ['/regKey/delete','/regKey/clearNotUse'],
};

async function consumeAuthAttempt(c, kind, identity, limit) {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(identity));
	const key = kind + ':' + Array.from(new Uint8Array(digest), n => n.toString(16).padStart(2, '0')).join('');
	const window = Math.floor(Date.now() / 60000);
	const row = await c.env.db.prepare(`INSERT INTO auth_rate_limits (key, window_start, count) VALUES (?, ?, 1)
		ON CONFLICT(key) DO UPDATE SET window_start=excluded.window_start,
		count=CASE WHEN auth_rate_limits.window_start=excluded.window_start THEN auth_rate_limits.count+1 ELSE 1 END
		RETURNING count`).bind(key, window).first();
	if (row.count > limit) {
		c.header('Retry-After', String(60 - Math.floor(Date.now() / 1000) % 60));
		throw new BizError('Too many attempts; retry in one minute', 429);
	}
}

app.use('/login', bodyLimit({ maxSize: 8192 }));
app.use('/register', bodyLimit({ maxSize: 8192 }));
app.use('/my/resetPassword', bodyLimit({ maxSize: 8192 }));
app.use('/email/send', bodyLimit({ maxSize: 32 * 1024 * 1024 }));
app.use('*', async (c, next) => {

	const path = c.req.path;
	const matches = (prefix) => path === prefix || path.startsWith(prefix + '/');
	// Unconfigured OAuth is retired until state, identity scoping and binding proofs are implemented.
	if (matches('/oauth')) throw new BizError('OAuth is disabled', 403);
	if (matches('/init')) return c.notFound();
	if (c.req.method === 'POST' && (path === '/login' || path === '/register')) {
		if (!c.env.db) throw new BizError('Authentication temporarily unavailable', 503);
		const ip = c.req.header('CF-Connecting-IP') || 'unknown';
		await consumeAuthAttempt(c, 'ip', ip, 30);
		let body;
		try { body = await c.req.json(); } catch { throw new BizError('Invalid request', 400); }
		if (typeof body?.email !== 'string' || body.email.length > 254) throw new BizError('Invalid request', 400);
		const email = body.email.trim().toLowerCase();
		await consumeAuthAttempt(c, 'account', email, 10);
	}
	if (path === '/webhooks' && c.req.method === 'POST') return next();
	if (/^\/telegram\/getEmail\/[^/]+$/.test(path) && c.req.method === 'GET') return next();
	const objectRequest = matches('/oss');
	if (objectRequest && /^\/oss\/static\/background\/[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$/.test(path)) {
		return next();
	}
	// The legacy token grants instance-wide access. Retire it, including token minting.
	if (matches('/public')) {
		throw new BizError('Legacy public API disabled; use authenticated user APIs', 403);
	}

	if (exclude.includes(path)) return next();

	const jwt = c.req.header(constant.TOKEN_HEADER) ||
		(objectRequest && ['GET', 'HEAD'].includes(c.req.method) ? getCookie(c, '__Host-mail-session') : undefined);

	const result = await jwtUtils.verifyToken(c, jwt);

	if (!result) {
		throw new BizError(t('authExpired'), 401);
	}

	const { userId, token } = result;
	const authInfo = await c.env.kv.get(KvConst.AUTH_INFO + userId, { type: 'json' });

	if (!authInfo) {
		throw new BizError(t('authExpired'), 401);
	}

	if (!authInfo.tokens.includes(token)) {
		throw new BizError(t('authExpired'), 401);
	}

	// Password salts rotate on every reset. D1 is authoritative even while KV replicas lag.
	const current = await c.env.db.prepare('SELECT salt, status, is_del, email FROM user WHERE user_id = ?').bind(userId).first();
	if (!current || current.status !== 0 || current.is_del !== 0 || !authInfo.credentialVersion || authInfo.credentialVersion !== current.salt || authInfo.user.email !== current.email) {
		throw new BizError(t('authExpired'), 401);
	}
	const permIndex = requirePerms.findIndex(item => {
		return matches(item);
	});

	if (permIndex > -1) {

		const permKeys = await permService.userPermKeys(c, authInfo.user.userId);

		const userPaths = permKeyToPaths(permKeys);

		const userPermIndex = userPaths.findIndex(item => {
			return matches(item);
		});

		if (userPermIndex === -1 && authInfo.user.email !== c.env.admin) {
			throw new BizError(t('unauthorized'), 403);
		}

	}

	const refreshTime = dayjs(authInfo.refreshTime).startOf('day');
	const nowTime = dayjs().startOf('day')

	if (!nowTime.isSame(refreshTime)) {
		authInfo.refreshTime = dayjs().toISOString();
		await userService.updateUserInfo(c, authInfo.user.userId);
		await c.env.kv.put(KvConst.AUTH_INFO + userId, JSON.stringify(authInfo), { expirationTtl: constant.TOKEN_EXPIRE });
	}

	if (path === '/my/resetPassword' && c.req.method === 'PUT') await consumeAuthAttempt(c, 'password-change', String(userId), 5);
	c.set('user',authInfo.user)
	delete authInfo.user.password;
	delete authInfo.user.salt;
	if (c.req.header(constant.TOKEN_HEADER) && new URL(c.req.url).protocol === 'https:') {
		setCookie(c, '__Host-mail-session', jwt, {
			httpOnly: true, secure: true, sameSite: 'Strict', path: '/', maxAge: constant.TOKEN_EXPIRE,
		});
	}

	return await next();
});

function permKeyToPaths(permKeys) {

	const paths = [];

	for (const key of permKeys) {
		const routeList = premKey[key];
		if (routeList && Array.isArray(routeList)) {
			paths.push(...routeList);
		}
	}
	return paths;
}
