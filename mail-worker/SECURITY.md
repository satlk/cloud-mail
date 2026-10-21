# Security update

- Private objects require a valid session and attachment ownership. Background images remain public.
- Legacy instance-wide `/api/public/*` endpoints are retired. Integrations must migrate to authenticated, user-scoped APIs.
- Existing sessions must sign in again. Successful password login upgrades legacy password hashes to PBKDF2.
- Keep object storage private; external public bucket/CDN URLs bypass Worker authorization.
- Run `npm run test:security` with Node.js 22.13+ before publishing.
- Preserve the existing D1 and KV bindings and back up the database before deployment.
- `/api/init/*` is retired. Run future schema migrations through an authenticated maintenance/deployment workflow.
- Telegram email links are opaque, email-scoped KV capabilities that expire after 15 minutes. Previously issued JWT links are retired; responses are private and non-cacheable.
- Resend callbacks require a dedicated `RESEND_WEBHOOK_SECRET` Worker secret (the Resend endpoint's signing secret, separate from the outbound webhook setting). Missing configuration closes the callback with 503; invalid signatures/timestamps return 401. Raw JSON is verified before database updates.
- Password login and registration share account (10/minute) and source-IP (30/minute) native limits. Counters are approximate per Cloudflare location; strict global limits require Durable Objects. Shared networks can hit the IP limit. Rejected attempts return 429 with Retry-After.
- Registration/captcha switches remain operator-controlled. Open registration exposes whether creation succeeds; generic duplicate-account failures and rate limits reduce detail and volume, while invitation/address-verification policies provide stronger controls.
