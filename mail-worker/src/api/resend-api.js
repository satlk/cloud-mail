import resendService from '../service/resend-service';
import app from '../hono/hono';
import { Resend } from 'resend';
import BizError from '../error/biz-error';
import { bodyLimit } from 'hono/body-limit';
const verifier = new Resend('local-signature-verification').webhooks;
app.post('/webhooks', bodyLimit({ maxSize: 65536 }), async (c) => {
	if (!c.env.RESEND_WEBHOOK_SECRET) throw new BizError('Webhook unavailable', 503);
	if (!/^application\/json(?:\s*;|$)/i.test(c.req.header('Content-Type') || '')) throw new BizError('JSON required', 415);
	const payload = await c.req.text();
	let body;
	try {
		body = verifier.verify({ payload, webhookSecret: c.env.RESEND_WEBHOOK_SECRET, headers: {
			id: c.req.header('svix-id'), timestamp: c.req.header('svix-timestamp'), signature: c.req.header('svix-signature'),
		} });
	} catch {
		throw new BizError('Invalid webhook signature', 401);
	}
	await resendService.webhooks(c, body);
	return c.text('success', 200);
})
