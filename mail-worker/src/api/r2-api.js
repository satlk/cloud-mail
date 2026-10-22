import r2Service from '../service/r2-service';
import app from '../hono/hono';

app.get('/oss/*', async (c) => {
	const key = c.req.path.split('/oss/')[1];
	if (/^attachments\/[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9]+)?$/.test(key)) {
		const user = c.get('user');
		if (!user) return c.json({ code: 401, message: 'Authentication required' }, 401);
		const query = user.email === c.env.admin
			? c.env.db.prepare('SELECT att_id FROM attachments WHERE key = ? LIMIT 1').bind(key)
			: c.env.db.prepare('SELECT att_id FROM attachments WHERE key = ? AND user_id = ? LIMIT 1').bind(key, user.userId);
		const row = await query.first();
		if (!row) return c.notFound();
	} else if (!/^static\/background\/[a-zA-Z0-9_-]+\.[a-zA-Z0-9]+$/.test(key)) {
		return c.notFound();
	}
	const obj = await r2Service.getObj(c, key);
	if (!obj) {
		return c.notFound();
	}
	const resp = obj instanceof Response ? obj : new Response(obj.body, {
		headers: {
			'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
			'Content-Disposition': obj.httpMetadata?.contentDisposition || 'attachment',
		},
	});
	const headers = new Headers(resp.headers);
	headers.delete('Access-Control-Allow-Origin');
	headers.set('X-Content-Type-Options', 'nosniff');
	headers.set('Content-Security-Policy', "sandbox; default-src 'none'");
	if (key.startsWith('attachments/')) {
		headers.set('Cache-Control', 'private, no-store');
		if (!/^image\/(png|jpeg|gif|webp|bmp)$/i.test(headers.get('Content-Type') || '')) headers.set('Content-Disposition', `attachment; filename="${key.split('/').pop()}"`);
	}
	return new Response(resp.body, { status: resp.status, headers });
});


