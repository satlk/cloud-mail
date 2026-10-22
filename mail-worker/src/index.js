import app from './hono/webs';
import { email } from './email/email';
import userService from './service/user-service';
import verifyRecordService from './service/verify-record-service';
import emailService from './service/email-service';
import oauthService from './service/oauth-service';
import analysisService from './service/analysis-service';
async function route(req, env, ctx) {

		const url = new URL(req.url)

		if (url.pathname.startsWith('/api/')) {
			url.pathname = url.pathname.replace('/api', '')
			req = new Request(url.toString(), req)
			return app.fetch(req, env, ctx);
		}

		if (['/oss/', '/static/', '/attachments/'].some(p => url.pathname.startsWith(p))) {
			if (!url.pathname.startsWith('/oss/')) url.pathname = '/oss' + url.pathname;
			return app.fetch(new Request(url.toString(), req), env, ctx);
		}

		return env.assets.fetch(req);
	}

export default {
	async fetch(req, env, ctx) {
		const result = await route(req, env, ctx);
		const response = new Response(result.body, result);
		response.headers.set('Strict-Transport-Security', 'max-age=31536000');
		response.headers.set('X-Content-Type-Options', 'nosniff');
		response.headers.set('X-Frame-Options', 'DENY');
		response.headers.set('Referrer-Policy', 'no-referrer');
		response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
		if (!response.headers.has('Content-Security-Policy')) response.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' https: data: blob:; font-src 'self' https: data:; connect-src 'self' https://api.iconify.design https://api.simplesvg.com https://api.unisvg.com; frame-src 'self' https://challenges.cloudflare.com; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
		return response;
	},

	email: email,
	async scheduled(c, env, ctx) {
		await env.db.prepare('DELETE FROM auth_rate_limits WHERE window_start < ?').bind(Math.floor(Date.now() / 60000) - 60).run();
		if (c.cron === '*/30 * * * *') {
			await analysisService.refreshEchartsCache({ env })
			return;
		}

		await verifyRecordService.clearRecord({ env })
		await userService.resetDaySendCount({ env })
		await emailService.completeReceiveAll({ env })
		await emailService.autoClean({ env })
		await analysisService.refreshEchartsCache({ env })
		await oauthService.clearNoBindOathUser({ env })
	},
};
