import app from '../hono/hono';

app.get('/init/:secret', (c) => {
	return c.notFound();
})
