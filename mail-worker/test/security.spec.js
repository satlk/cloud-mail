import { DatabaseSync } from 'node:sqlite';
import { describe, it, expect, vi, afterEach } from 'vitest';
import worker from '../src/index';
import app from '../src/hono/webs';
import jwt from '../src/utils/jwt-utils';
import passwords from '../src/utils/crypto-utils';
import storage from '../src/service/r2-service';
import permissions from '../src/service/perm-service';
import roles from '../src/service/role-service';
import publicService from '../src/service/public-service';
import emailService from '../src/service/email-service';
import loginService from '../src/service/login-service';
import userService from '../src/service/user-service';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';

const values = new Map();
const activeUsers = new Map();
const sqlite = new DatabaseSync(':memory:');
sqlite.exec(readFileSync(new URL('../migrations/security-auth-rate-limits.sql', import.meta.url), 'utf8'));
const env = {
  admin: 'admin@example.test', jwt_secret: 'isolated-test-secret-with-at-least-32-characters', domain: ['example.test'],
  RESEND_WEBHOOK_SECRET: 'whsec_' + Buffer.from('isolated-webhook-test-secret').toString('base64'),
  kv: {
    async put(key, value) { values.set(key, value); },
    async get(key, options) { const value = values.get(key) ?? null; return value && options?.type === 'json' ? JSON.parse(value) : value; },
    async delete(key) { values.delete(key); },
  },
  db: {
    async exec(sql) { sqlite.exec(sql); },
    prepare(sql) { if (sql.startsWith('SELECT salt, status, is_del, email FROM user')) return { bind(id) { return { async first() { return activeUsers.get(id) || null; } }; } }; return { bind(...args) { return {
      async first() { return sqlite.prepare(sql).get(...args) ?? null; },
      async run() { return sqlite.prepare(sql).run(...args); },
      async all() { return { results: sqlite.prepare(sql).all(...args) }; },
      async raw() { return sqlite.prepare(sql).all(...args).map(row => Object.values(row)); },
    }; } }; },
  },
};

const request = (path, options = {}) => new Request('https://mail.example.test' + path, options);
const fetch = (path, options) => worker.fetch(request(path, options), env, {});
app.get('/security-error-test', () => { throw new Error('D1_ERROR: private table details'); });
async function session(userId = 7, email = 'user@example.test') {
  activeUsers.set(userId, { salt: 'synthetic-epoch', status: 0, is_del: 0, email });
  await env.kv.put('auth-uid:' + userId, JSON.stringify({ credentialVersion: 'synthetic-epoch', user: { userId, email }, tokens: ['test-token'], refreshTime: new Date().toISOString() }));
  return jwt.generateToken({ env }, { userId, token: 'test-token' });
}
afterEach(() => { vi.restoreAllMocks(); sqlite.exec('DELETE FROM auth_rate_limits'); });

describe('security regression', () => {
  it('blocks anonymous KV secrets, attachments, and every legacy public route', async () => {
    await env.kv.put('public_key:', 'leaked-token');
    for (const path of ['/api/oss/public_key:', '/api/oss/setting:', '/api/oss/auth-uid:7', '/oss/public_key:', '/attachments/test.png']) {
      expect((await fetch(path)).status, path).toBe(401);
    }
    for (const path of ['/api/public/emailList', '/api/public/addUser', '/api/public/genToken']) {
      const response = await fetch(path, { method: 'POST', headers: { Authorization: 'leaked-token' }, body: '{}' });
      expect(response.status, path).toBe(403);
    }
  });
  it('rejects secret keys even for authenticated users and restricts CORS', async () => {
    const token = await session();
    expect((await fetch('/api/oss/public_key:', { headers: { Authorization: token } })).status).toBe(404);
    const response = await fetch('/api/oss/setting:', { headers: { Origin: 'https://evil.example' } });
    expect(response.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });
  it('serves attachments only to their owner, through API/root aliases and secure cookie', async () => {
    await env.db.exec('CREATE TABLE attachments (att_id INTEGER PRIMARY KEY, key TEXT, user_id INTEGER);');
    await env.db.prepare('INSERT INTO attachments VALUES (1, ?, 7)').bind('attachments/test.png').run();
    vi.spyOn(storage, 'getObj').mockImplementation(async () => new Response('synthetic attachment'));
    const token = await session();
    for (const path of ['/api/oss/attachments/test.png', '/oss/attachments/test.png', '/attachments/test.png']) {
      const response = await fetch(path, { headers: { Authorization: token } });
      expect(response.status).toBe(200);
      expect(await response.text()).toBe('synthetic attachment');
      expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    }
    expect((await fetch('/attachments/test.png', { headers: { Cookie: '__Host-mail-session=' + token } })).status).toBe(200);
    const other = await session(8, 'other@example.test');
    expect((await fetch('/attachments/test.png', { headers: { Authorization: other } })).status).toBe(404);
    await env.kv.delete('auth-uid:7');
    expect((await fetch('/attachments/test.png', { headers: { Cookie: '__Host-mail-session=' + token } })).status).toBe(401);
  });
  it('keeps public login backgrounds working and checks role permissions', async () => {
    vi.spyOn(storage, 'getObj').mockResolvedValue(new Response('background'));
    expect((await fetch('/static/background/test.png')).status).toBe(200);
    vi.spyOn(permissions, 'userPermKeys').mockResolvedValue([]);
    const token = await session();
    expect((await fetch('/api/role/selectUse', { headers: { Authorization: token } })).status).toBe(403);
  });
  it('hides unexpected database errors', async () => {
    const token = await session();
    const response = await app.fetch(request('/security-error-test', { headers: { Authorization: token } }), env);
    expect(response.status).toBe(500);
    expect(await response.text()).not.toContain('private table');
  });
  it('binds hostile email and request metadata as SQL values', async () => {
    vi.spyOn(roles, 'roleSelectUse').mockResolvedValue([{ isDefault: 1, roleId: 1 }]);
    const statements = [];
    const db = { prepare: vi.fn(sql => ({ bind: (...values) => { statements.push({ sql, values }); return {}; } })), batch: vi.fn().mockResolvedValue([]) };
    const hostile = "audit'--@example.test";
    const c = { env: { ...env, db }, req: { header: key => key === 'CF-Connecting-IP' ? "x'); DROP TABLE user;--" : '' } };
    await publicService.addUser(c, { list: [{ email: hostile, password: 'test-password' }] });
    expect(statements).toHaveLength(2);
    expect(statements[0].values[0]).toBe(hostile);
    expect(statements[0].sql).not.toContain(hostile);
    expect(statements[0].sql).not.toContain('DROP TABLE');
  });
  it('uses versioned PBKDF2 and verifies legacy passwords for migration', async () => {
    const { salt, hash } = await passwords.hashPassword('test-password');
    expect(hash).toMatch(/^pbkdf2-sha256\$100000\$/);
    expect(await passwords.verifyPassword('test-password', salt, hash)).toBe(true);
    expect(await passwords.verifyPassword('wrong', salt, hash)).toBe(false);
    const legacy = await passwords.genHashPassword('legacy-password', salt);
    expect(await passwords.verifyPassword('legacy-password', salt, legacy)).toBe(true);
  });
  it('rejects tokens from a previous session generation', async () => {
    const token = await session();
    expect(await jwt.verifyToken({ env: { ...env, session_version: 'rotated-generation' } }, token)).toBeNull();
  });
  it('closes initialization even with the real root secret', async () => {
    const prepare = vi.spyOn(env.db, 'prepare');
    for (const path of ['/api/init/wrong', '/api/init/' + env.jwt_secret]) expect((await fetch(path)).status).toBe(404);
    expect(prepare).not.toHaveBeenCalled();
  });
  it('rejects session JWTs and expired Telegram capabilities without querying emails', async () => {
    const prepare = vi.spyOn(env.db, 'prepare');
    const signed = await jwt.generateToken({ env }, { emailId: 1 });
    const response = await fetch('/api/telegram/getEmail/' + signed);
    expect(response.status).toBe(404);
    expect(response.headers.get('Cache-Control')).toBe('private, no-store');
    const token = crypto.randomUUID();
    await env.kv.put('telegram-email:' + token, JSON.stringify({ emailId: 1, expiresAt: Date.now() - 1 }));
    expect((await fetch('/api/telegram/getEmail/' + token)).status).toBe(404);
    expect(prepare).not.toHaveBeenCalled();
  });
  it('rate limits auth by trusted source and normalized account before login work', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1800000);
    for (let i = 0; i < 30; i++) expect((await fetch('/api/login', { method: 'POST', body: '{}' })).status).toBe(400);
    let response = await fetch('/api/login', { method: 'POST', body: '{}' });
    expect(response.status).toBe(429);
    expect(response.headers.get('Retry-After')).toBe('60');
    sqlite.exec('DELETE FROM auth_rate_limits');
    vi.spyOn(loginService, 'login').mockResolvedValue('synthetic-token');
    for (let i = 0; i < 10; i++) expect((await fetch('/api/login', { method: 'POST', body: JSON.stringify({ email: 'user@example.test', password: 'wrong' }) })).status).toBe(200);
    response = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ email: ' USER@Example.TEST ', password: 'wrong' }) });
    expect(response.status).toBe(429);
    expect((await fetch('/api/register', { method: 'POST', body: JSON.stringify({ email: 'user@example.test', password: 'test-password' }) })).status).toBe(429);
  });
  it('atomically enforces the shared account limit for concurrent attempts', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1800000);
    vi.spyOn(loginService, 'login').mockResolvedValue('synthetic-token');
    const responses = await Promise.all(Array.from({ length: 20 }, () => fetch('/api/login', { method: 'POST', body: JSON.stringify({ email: 'parallel@example.test', password: 'wrong' }) })));
    expect(responses.filter(r => r.status === 200)).toHaveLength(10);
    expect(responses.filter(r => r.status === 429)).toHaveLength(10);
  });
  it('returns the same failure for nonexistent accounts and wrong passwords', async () => {
    const lookup = vi.spyOn(userService, 'selectByEmailIncludeDel').mockResolvedValue(null);
    await expect(loginService.login({ env }, { email: 'user@example.test', password: 'wrong' })).rejects.toMatchObject({ code: 401, message: '邮箱或密码错误' });
    const { salt, hash } = await passwords.hashPassword('test-password');
    lookup.mockResolvedValue({ userId: 7, email: 'user@example.test', salt, password: hash, isDel: 0, status: 0 });
    await expect(loginService.login({ env }, { email: 'user@example.test', password: 'wrong' })).rejects.toMatchObject({ code: 401, message: '邮箱或密码错误' });
  });
  it('verifies raw-body webhook signatures and timestamp before writes', async () => {
    const update = vi.spyOn(emailService, 'updateEmailStatus').mockResolvedValue({ emailId: 1 });
    const payload = JSON.stringify({ type: 'email.delivered', data: { email_id: crypto.randomUUID() } });
    const id = 'msg_security_test';
    const timestamp = String(Math.floor(Date.now() / 1000));
    const secret = Buffer.from(env.RESEND_WEBHOOK_SECRET.slice(6), 'base64');
    const signature = 'v1,' + createHmac('sha256', secret).update(id + '.' + timestamp + '.' + payload).digest('base64');
    const headers = { 'Content-Type': 'application/json', 'svix-id': id, 'svix-timestamp': timestamp, 'svix-signature': signature };
    expect((await fetch('/api/webhooks', { method: 'POST', body: payload, headers: { 'Content-Type': 'application/json' } })).status).toBe(401);
    expect(update).not.toHaveBeenCalled();
    expect((await fetch('/api/webhooks', { method: 'POST', body: payload + ' ', headers })).status).toBe(401);
    const stale = String(Number(timestamp) - 601);
    const staleSignature = 'v1,' + createHmac('sha256', secret).update(id + '.' + stale + '.' + payload).digest('base64');
    expect((await fetch('/api/webhooks', { method: 'POST', body: payload, headers: { ...headers, 'svix-timestamp': stale, 'svix-signature': staleSignature } })).status).toBe(401);
    expect(update).not.toHaveBeenCalled();
    expect((await fetch('/api/webhooks', { method: 'POST', body: payload, headers })).status).toBe(200);
    expect(update).toHaveBeenCalledOnce();
  });
  it('fails closed when auth or webhook security configuration is missing', async () => {
    const noLimit = await worker.fetch(request('/api/login', { method: 'POST', body: '{}' }), { ...env, db: undefined }, {});
    expect(noLimit.status).toBe(503);
    const noSecret = await worker.fetch(request('/api/webhooks', { method: 'POST', body: '{}' }), { ...env, RESEND_WEBHOOK_SECRET: undefined }, {});
    expect(noSecret.status).toBe(503);
    expect((await fetch('/api/webhooks', { method: 'POST', body: '{}' })).status).toBe(415);
  });
  it('rejects signed webhook IDs with invalid types before database writes', async () => {
    const update = vi.spyOn(emailService, 'updateEmailStatus');
    await expect((await import('../src/service/resend-service')).default.webhooks({}, { type: 'email.delivered', data: { email_id: {} } })).rejects.toMatchObject({ code: 400 });
    expect(update).not.toHaveBeenCalled();
  });
});

it('requires strong JWT configuration, strict header/claims and bounded expiry', async () => {
  const now = Math.floor(Date.now() / 1000);
  function sign(payload, header = { alg: 'HS256', typ: 'JWT' }) {
    const data = Buffer.from(JSON.stringify(header)).toString('base64url') + '.' + Buffer.from(JSON.stringify(payload)).toString('base64url');
    return data + '.' + createHmac('sha256', env.jwt_secret).update(data).digest('base64url');
  }
  const payload = { userId: 7, token: 'test-token', ver: 'security-v2', iat: now, exp: now + 3600 };
  expect(await jwt.verifyToken({ env }, sign(payload))).toMatchObject({ userId: 7 });
  for (const changed of [{ exp: undefined }, { exp: now }, { iat: now + 600 }, { exp: now + 2592001 }, { userId: -1 }, { token: {} }, { ver: 'security-v1' }])
    expect(await jwt.verifyToken({ env }, sign({ ...payload, ...changed }))).toBeNull();
  expect(await jwt.verifyToken({ env }, sign(payload, { alg: 'none', typ: 'JWT' }))).toBeNull();
  expect(await jwt.verifyToken({ env }, sign(payload) + '.extra')).toBeNull();
  await expect(jwt.generateToken({ env: { jwt_secret: 'weak' } }, payload)).rejects.toThrow('32 random');
});

it('restricts outbound mail webhooks to deployment-approved URLs and refuses redirects', async () => {
  const { default: webhooks, approvedWebhookUrl } = await import('../src/service/webhook-service');
  const c = { env: { WEBHOOK_ALLOWED_URLS: 'https://trusted.example/mail' } };
  for (const value of ['http://trusted.example/mail', 'https://127.0.0.1/mail', 'https://[::1]/mail', 'https://169.254.169.254/', 'https://evil.example/mail', 'https://trusted.example/other', 'https://user@trusted.example/mail', 'https://trusted.example/mail#x'])
    expect(() => approvedWebhookUrl(c, value)).toThrow();
  expect(approvedWebhookUrl(c, 'https://trusted.example/mail')).toBe('https://trusted.example/mail');
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(null, { status: 302, headers: { Location: 'http://127.0.0.1' } }));
  await webhooks.sendEmail(c, {}, 'https://trusted.example/mail', 100);
  expect(fetchMock).toHaveBeenCalledOnce();
  expect(fetchMock.mock.calls[0][1].redirect).toBe('manual');
  expect(fetchMock.mock.calls[0][1].signal).toBeInstanceOf(AbortSignal);
  fetchMock.mockClear();
  await webhooks.sendEmail({ env: {} }, {}, 'https://trusted.example/mail');
  expect(fetchMock).not.toHaveBeenCalled();
});

it('sets security headers on static pages and API errors', async () => {
  const staticEnv = { ...env, assets: { fetch: async () => new Response('<html>test</html>', { headers: { 'Content-Type': 'text/html' } }) } };
  for (const path of ['/', '/api/my/loginUserInfo']) {
    const response = await worker.fetch(request(path), staticEnv, {});
    expect(response.headers.get('Strict-Transport-Security')).toContain('31536000');
    expect(response.headers.get('Content-Security-Policy')).toContain("object-src 'none'");
    expect(response.headers.get('X-Frame-Options')).toBe('DENY');
  }
});

it('keeps production CI on existing storage bindings and operator-managed JWT secrets', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/deploy-cloudflare.yml', import.meta.url), 'utf8');
  expect(workflow).toContain('--config wrangler.toml --keep-vars --no-autoconfig');
  expect(workflow).not.toContain('/api/init/');
  expect(workflow).not.toMatch(/wrangler (d1|kv) create/);
  const config = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8');
  expect(config).not.toMatch(/^jwt_secret\s*=/m);
});

it('revokes existing sessions after a self-service password change', async () => {
  sqlite.exec('CREATE TABLE IF NOT EXISTS user (user_id INTEGER PRIMARY KEY, password TEXT, salt TEXT); INSERT OR REPLACE INTO user VALUES (97, 1, 2);');
  await session(97);
  const { salt, hash } = await passwords.hashPassword('isolated-old-password');
  vi.spyOn(userService, 'selectById').mockResolvedValue({ userId: 97, salt, password: hash });
  await expect(userService.resetPassword({ env }, { password: 'isolated-new-password' }, 97)).rejects.toMatchObject({ code: 403 });
  expect(await env.kv.get('auth-uid:97')).not.toBeNull();
  await userService.resetPassword({ env }, { password: 'isolated-new-password', currentPassword: 'isolated-old-password' }, 97);
  expect(await env.kv.get('auth-uid:97')).toBeNull();
});

it('closes dormant OAuth login and binding endpoints before database access', async () => {
  const query = vi.spyOn(env.db, 'prepare');
  for (const [method, path] of [['POST', '/api/oauth/github/login'], ['POST', '/api/oauth/google/login'], ['POST', '/api/oauth/linuxDo/login'], ['PUT', '/api/oauth/bindUser']]) {
    expect((await fetch(path, { method, body: '{}' })).status).toBe(403);
  }
  expect(query).not.toHaveBeenCalled();
});

it('revokes sessions for administrator password reset and string-valued account bans', async () => {
  sqlite.exec('ALTER TABLE user ADD COLUMN status INTEGER DEFAULT 0; INSERT OR REPLACE INTO user (user_id,password,salt) VALUES (98,1,2);');
  await session(98);
  await userService.setStatus({ env }, { userId: '98', status: '1' });
  expect(await env.kv.get('auth-uid:98')).toBeNull();
  await session(98);
  await userService.setPwd({ env }, { userId: 98, password: 'admin-generated-test-password' });
  expect(await env.kv.get('auth-uid:98')).toBeNull();
  await expect(userService.setStatus({ env }, { userId: 98, status: 7 })).rejects.toMatchObject({ code: 400 });
});

it('rejects cross-user attachment references during inline-image conversion', async () => {
  const { default: attachments } = await import('../src/service/att-service');
  const { default: settings } = await import('../src/service/setting-service');
  for (const column of ['email_id', 'account_id', 'filename', 'mime_type', 'size', 'status', 'type', 'disposition', 'related', 'content_id', 'encoding', 'create_time'])
    sqlite.exec('ALTER TABLE attachments ADD COLUMN ' + column + ' TEXT');
  sqlite.prepare('INSERT INTO attachments (att_id,user_id,key,filename,mime_type) VALUES (23,8,?,?,?)').run('attachments/victim-only.png', 'synthetic.png', 'image/png');
  vi.spyOn(settings, 'query').mockResolvedValue({ r2Domain: '' });
  const read = vi.spyOn(storage, 'getObj').mockImplementation(async () => new Response('synthetic-private-image'));
  await expect(attachments.toImageUrlHtml({ env }, '<img src="attachments/victim-only.png">', 7)).rejects.toMatchObject({ code: 404 });
  expect(read).not.toHaveBeenCalled();
  for (const src of ['attachments/victim-only.png', '/attachments/victim-only.png', '/oss/attachments/victim-only.png']) {
    const own = await attachments.toImageUrlHtml({ env }, `<img src="${src}">`, 8);
    expect(own.imageDataList).toHaveLength(1);
  }
  await expect(attachments.toImageUrlHtml({ env }, '<img src="attachments/../secret">', 8)).rejects.toMatchObject({ code: 404 });
});

it('checks send authorization and reply ownership before loading objects', async () => {
  const { default: settings } = await import('../src/service/setting-service');
  const { default: attachments } = await import('../src/service/att-service');
  const { default: accounts } = await import('../src/service/account-service');
  const query = vi.spyOn(settings, 'query').mockResolvedValue({ send: 1 });
  const read = vi.spyOn(attachments, 'toImageUrlHtml');
  const params = { accountId: 7, receiveEmail: ['recipient@example.test'], content: '', attachments: [] };
  await expect(emailService.send({ env }, params, 7)).rejects.toMatchObject({ code: 403 });
  expect(read).not.toHaveBeenCalled();
  query.mockResolvedValue({ send: 0, domainList: ['@example.test'], resendTokens: {} });
  vi.spyOn(userService, 'selectById').mockResolvedValue({ userId: 7, email: env.admin, type: 1 });
  vi.spyOn(roles, 'selectById').mockResolvedValue({});
  vi.spyOn(accounts, 'selectById').mockResolvedValue({ userId: 7, email: env.admin });
  vi.spyOn(emailService, 'selectById').mockResolvedValue({ userId: 8, messageId: 'synthetic-victim-message-id' });
  await expect(emailService.send({ env }, { ...params, sendType: 'reply', emailId: 99 }, 7)).rejects.toMatchObject({ code: 404 });
  expect(read).not.toHaveBeenCalled();
});

it('rejects stale KV sessions against authoritative D1 password epochs and account state', async () => {
  const token = await session(96);
  expect((await fetch('/api/oss/setting:', { headers: { Authorization: token } })).status).toBe(404);
  activeUsers.get(96).salt = 'rotated-password-epoch';
  expect((await fetch('/api/oss/setting:', { headers: { Authorization: token } })).status).toBe(401);
  activeUsers.get(96).salt = 'synthetic-epoch';
  activeUsers.get(96).status = 1;
  expect((await fetch('/api/oss/setting:', { headers: { Authorization: token } })).status).toBe(401);
  activeUsers.get(96).status = 0;
  activeUsers.get(96).is_del = 1;
  expect((await fetch('/api/oss/setting:', { headers: { Authorization: token } })).status).toBe(401);
});
