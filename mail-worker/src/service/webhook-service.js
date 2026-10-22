import BizError from '../error/biz-error';

// Only deployment operators can approve destinations; application settings cannot expand trust.
export function approvedWebhookUrl(c, value) {
	if (!value) return '';
	let url;
	try { url = new URL(value); } catch { throw new BizError('Invalid webhook URL', 400); }
	const host = url.hostname;
	const allowed = String(c.env.WEBHOOK_ALLOWED_URLS || '').split(',').map(s => s.trim()).filter(Boolean);
	if (url.protocol !== 'https:' || url.username || url.password || url.port || url.hash ||
		!host.includes('.') || !/[a-z]$/i.test(host) || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal') ||
		!allowed.includes(url.href)) throw new BizError('Webhook destination requires deployment approval', 400);
	return url.href;
}

const webhookService = {
	async sendEmail(c, emailRow, webhookUrl, retry = 0, webhookSecret) {
		let target;
		try { target = approvedWebhookUrl(c, webhookUrl); }
		catch { console.error('Webhook destination blocked'); return; }
		if (!target) return;
		const headers = { 'Content-Type': 'application/json' };
		if (webhookSecret) headers.Authorization = webhookSecret;
		const body = JSON.stringify({
			emailId: emailRow.emailId, sendEmail: emailRow.sendEmail, sendName: emailRow.name,
			toEmail: emailRow.toEmail, toName: emailRow.toName, subject: emailRow.subject,
			text: emailRow.text, content: emailRow.content, code: emailRow.code, createTime: emailRow.createTime
		});
		retry = Math.min(2, Math.max(0, Math.floor(Number(retry) || 0)));
		for (let i = 0; i <= retry; i++) {
			try {
				const res = await fetch(target, { method: 'POST', headers, body, redirect: 'manual', signal: AbortSignal.timeout(5000) });
				await res.body?.cancel();
				if (res.ok) return;
				if (res.status >= 300 && res.status < 400) break;
			} catch { /* bounded retry; never log response contents or destination credentials */ }
		}
		console.error('Webhook delivery failed');
	}
};
export default webhookService;
