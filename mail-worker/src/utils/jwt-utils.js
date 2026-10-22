const encoder = new TextEncoder();
const decoder = new TextDecoder();

const base64url = (input) => {
	const str = btoa(String.fromCharCode(...new Uint8Array(input)));
	return str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
};

const base64urlDecode = (str) => {
	str = str.replace(/-/g, '+').replace(/_/g, '/');
	while (str.length % 4) str += '=';
	return Uint8Array.from(atob(str), c => c.charCodeAt(0));
};

const jwtUtils = {
	async generateToken(c, payload, expiresInSeconds = 60 * 60 * 24 * 30) {
		if (typeof c.env.jwt_secret !== 'string' || c.env.jwt_secret.length < 32) throw new Error('JWT secret must contain at least 32 random characters');
		const header = {
			alg: 'HS256',
			typ: 'JWT'
		};

		const now = Math.floor(Date.now() / 1000);
		const exp = now + Math.min(Math.max(Number(expiresInSeconds) || 1, 1), 60 * 60 * 24 * 30);

		const fullPayload = {
			...payload,
			ver: c.env.session_version || 'security-v2',
			iat: now,
			exp
		};

		const headerStr = base64url(encoder.encode(JSON.stringify(header)));
		const payloadStr = base64url(encoder.encode(JSON.stringify(fullPayload)));
		const data = `${headerStr}.${payloadStr}`;

		const key = await crypto.subtle.importKey(
			'raw',
			encoder.encode(c.env.jwt_secret),
			{ name: 'HMAC', hash: 'SHA-256' },
			false,
			['sign']
		);

		const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
		const signatureStr = base64url(signature);

		return `${data}.${signatureStr}`;
	},

	async verifyToken(c, token) {
		if (typeof token !== 'string' || token.length > 8192 || typeof c.env.jwt_secret !== 'string' || c.env.jwt_secret.length < 32) return null;
		try {
			const parts = token.split('.');
			if (parts.length !== 3) return null;
			const [headerB64, payloadB64, signatureB64] = parts;
			const header = JSON.parse(decoder.decode(base64urlDecode(headerB64)));
			if (header.alg !== 'HS256' || header.typ !== 'JWT') return null;

			if (!headerB64 || !payloadB64 || !signatureB64) return null;

			const data = `${headerB64}.${payloadB64}`;
			const key = await crypto.subtle.importKey(
				'raw',
				encoder.encode(c.env.jwt_secret),
				{ name: 'HMAC', hash: 'SHA-256' },
				false,
				['verify']
			);

			const valid = await crypto.subtle.verify(
				'HMAC',
				key,
				base64urlDecode(signatureB64),
				encoder.encode(data)
			);

			if (!valid) return null;

			const payloadJson = decoder.decode(base64urlDecode(payloadB64));
			const payload = JSON.parse(payloadJson);
			if (payload.ver !== (c.env.session_version || 'security-v2')) return null;

			const now = Math.floor(Date.now() / 1000);
			if (!Number.isInteger(payload.exp) || payload.exp <= now || !Number.isInteger(payload.iat) || payload.iat > now + 60 || payload.exp <= payload.iat || payload.exp - payload.iat > 60 * 60 * 24 * 30) return null;
			if (!Number.isSafeInteger(payload.userId) || payload.userId <= 0 || typeof payload.token !== 'string' || !payload.token) return null;

			return payload;

		} catch (err) {

			return null;
		}
	}
};

export default jwtUtils;
