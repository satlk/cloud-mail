# Invitation registration and regression verification — 2026-10-22

## Deployed
Worker version: cb1b827c-54f9-4cbd-a1fa-72d054d661a4.
Mandatory invitation registration enabled (reg_key=0, register=0); application sending disabled (send=1), preserving incoming routing. Existing invitation table has zero codes; administrators create codes through 注册码.

## Fresh rate-limit evidence
- 05:02 UTC, synthetic nonexistent email: ten 401 responses; uppercase/localpart/domain variants each 429, all in the same minute.
- 05:03 UTC, same IP: thirty malformed requests return 400; request 31 returns 429.
- Source uses trusted CF-Connecting-IP and trim().toLowerCase() account keys. Fixed UTC-minute windows reset on the minute boundary. The supplied report's 30x401+30x429 is consistent with the existing IP cap. Its case-bypass conclusion was not reproduced.
- Evidence: F:\AI\codex\软件开发\cloud-mail-security-artifacts\round5-rate-results.json.

## Additional fixes
- Reject object/array invitation codes, non-string password/email/token and oversized fields with 400 before DB lookups.
- Invitation consumption uses a single conditional D1 UPDATE RETURNING, requiring remaining count, role match and non-expired date. Twenty concurrent synthetic requests consume a single-use code once.
- Reservation precedes account creation: failed provisioning consumes a use; administrator can reissue. Full account provisioning is still multi-step; automatic reservation refund is deliberately excluded.
- Creation checks count/role/date/code length and awaits role lookup. UI generator uses crypto.randomUUID(), 128-bit random codes.
- Existing public websiteConfig serves login UI flags and domains; these fields are intentional public metadata. Prior secret-field allowlist checks remain in place.

## Verification and data
32 tests passed; real Miniflare smoke passed; production login page loaded.
Fresh D1 SELECT: total emails 228, retained 228. No real account or mail was created/deleted by these tests.
Backup: F:\AI\codex\软件开发\cloud-mail-security-backups\cloudmail-before-invite-20261022.sql
SQLite integrity_check=ok; SHA256 e98f31662683fc9446b275a2b9c2abb3d624bc82b1ebbe0e0f14ed7bd9453d8e.

## Pending
DNS edit API returns 403; scoped DNS token file is still absent. SPF/DMARC changes remain pending and are not claimed deployed. Preserve Cloudflare MX/routing and SPF include while tightening policies after authorization. Existing forwarding behavior and third-party sender records require preservation.
Static traversal in the supplied report did not disclose data; no new confirmed traversal finding. Ordinary-user live IDOR tests require explicitly provisioned test identities; disabled historical test accounts stay disabled. Isolated owner/other-user attachment and send tests pass.
