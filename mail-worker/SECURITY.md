# Security update

- Private objects require a valid session and attachment ownership. Background images remain public.
- Legacy instance-wide `/api/public/*` endpoints are retired. Integrations must migrate to authenticated, user-scoped APIs.
- Existing sessions must sign in again. Successful password login upgrades legacy password hashes to PBKDF2.
- Keep object storage private; external public bucket/CDN URLs bypass Worker authorization.
- Run `npm run test:security` with Node.js 22.13+ before publishing.
- Preserve the existing D1 and KV bindings and back up the database before deployment.
