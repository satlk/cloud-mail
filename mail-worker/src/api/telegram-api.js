import app from '../hono/hono';
import telegramService from '../service/telegram-service';

app.get('/telegram/getEmail/:token', async (c) => {
	c.header('Cache-Control', 'private, no-store');
	c.header('Referrer-Policy', 'no-referrer');
	c.header('X-Content-Type-Options', 'nosniff');
	c.header('Content-Security-Policy', "sandbox; default-src 'none'; img-src data: https:; style-src 'unsafe-inline'");
	const content = await telegramService.getEmailContent(c, c.req.param());
	if (content === null) return c.notFound();
	return c.html(content)
});

