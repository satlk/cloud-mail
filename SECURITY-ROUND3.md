# 2026-10-22 第三轮验证与加固

## 已发布
- 邮箱 Worker：`9531a26b-6b13-4fd1-b788-dc78e73535ae`。
- 主站 Pages：项目 `web`，部署 `bda23723-2b4b-45a4-9ca4-3fd819e63b85`，源码 `satlk/web` 提交 `802dafe`。

## 验证结果与处置
| 项目 | 本轮证据 | 处置/最终状态 |
|---|---|---|
| 弱 JWT 根密钥及泄露会话 | 修复前以报告中历史会话调用身份接口，HTTP 200、管理员权限成立；与部署变量在内存比对相符 | 生成 384-bit 随机根密钥，保存为 Cloudflare secret_text；撤销全部 15 份 auth-uid 会话；旧伪造令牌现为 401 |
| JWT 校验边界 | 源码允许缺失 exp，header 未检查 | security-v2；强制 HS256/JWT、三段结构、正整数用户、非空会话、iat/exp 及最长 30 天寿命；短密钥拒绝签发/验证 |
| 用户口令哈希响应 | user/list 查询包含 password/salt | 返回前移除两字段，登录与缓存既有过滤保留 |
| 邮件正文 XSS | 隔离 Chrome 中旧 Shadow DOM innerHTML 的 onerror 能改写父页面标题 | DOMPurify 3.4.17；阅读器使用禁止脚本的 sandbox iframe 和独立 CSP；草稿/回复/转发在编辑器入口共用净化函数。allow-same-origin 用于保留认证图片，allow-scripts 始终关闭 |
| 附件活动内容 | 既有归属校验、sandbox/no-store 回归有效 | HTML/SVG 等活动类型强制下载；安全栅格图片保留预览；X-Content-Type-Options 保留 |
| 出站 Webhook | 源码 fetch 无目标审批、自动跟随跳转。报告的外部投递证明外部转发，内网 SSRF 未作线上探测 | WEBHOOK_ALLOWED_URLS 由部署者管理，精确 HTTPS URL 白名单；默认全部关闭；设置保存和实际发送双重校验；拒绝凭据/IP/非标准端口；manual 跳转、5 秒超时、最多两次重试；不记录响应正文 |
| 登录限制/账号枚举 | 合成不存在账号在线 10 次401，第11次429 | 原有 D1 原子限速、统一错误仍有效；未创建线上测试账号 |
| 入站 /api/webhooks | 无签名请求503，缺少 Resend 专用签名密钥时关闭 | 原签名验证及字段检查保留；真实回调恢复需要 RESEND_WEBHOOK_SECRET |
| 两站响应头 | 修复前主站 ACAO *、两站缺 CSP/HSTS 等 | 两站 CSP/HSTS/nosniff/XFO/Permissions-Policy/no-referrer 生效，恶意 Origin 测试均无 ACAO；主站未知路径404，首页标题及7个原有链接保留 |
| websiteConfig | 线上仅返回登录/界面需要的白名单字段 | 保留公共配置；检查无 jwt_secret/password/salt/secretKey/tgBotToken/resendTokens/webhookSecret 字段 |
| CI 回退风险 | 原 workflow 会把历史 JWT_SECRET 注回明文变量，按名称创建新数据库，调用带密钥 init URL | CI 使用已绑定的 wrangler.toml、保留 Cloudflare secrets；仅幂等补建限速表；移除公开初始化及自动新建存储行为 |

## 数据与验收
- 本轮 D1 备份：`F:\AI\codex\软件开发\cloud-mail-security-backups\cloudmail-before-round3-20261022.sql`。
- SHA256：`c56595b5565d70564f3c37e7b84e66149e8c98e1d0c9ceafec9706c5f9b9561a`；SQLite integrity_check=ok。
- 备份与线上邮件均 228 封；线上 is_del=0 为228；uid3 当前76封。业务邮件、账号、附件数据保留。
- `cd mail-worker && npm run test:security`：22 条通过。
- Miniflare：真实登录、PBKDF2迁移、私有对象、附件归属、旧初始化、Telegram能力链接、入站签名关闭策略和并发限速检查通过。
- Chrome：旧实现合成 XSS 可复现；新组件保留文本/表格，移除事件/script/SVG/form/meta/javascript链接，父页面标题保持；Strict Cookie 图片在禁止脚本的同源 sandbox 中可加载。
- 线上登录页加载成功。Cloudflare 自动分析 beacon 被 CSP 拦截，邮箱基本功能正常；需要统计时另行显式批准分析域名。
- 详细测试脚本/截图/脱敏结果位于 `F:\AI\codex\软件开发\cloud-mail-security-artifacts`。

## 待完成与操作边界
1. DNS：实时 `_dmarc.d0nge.com` 为 p=none，根域 SPF 为 `include:_spf.mx.cloudflare.net ~all`。当前授权 DNS 读取接口403，DNS编辑权限缺失。需确认 Cloudflare/Resend 等所有合法发信来源与对齐结果后分阶段启用 quarantine/reject；保持收发链路可用。SPF软失败与DMARC监控本身不足以证明投递钓鱼成功。
2. 注册：原有开放注册策略保留并限速；用户尚待选择 Turnstile / 邀请码 / 保留开放。Turnstile需有效Site Key和Secret Key。
3. 历史暴露凭据：管理员及其他已泄露哈希用户应修改密码；历史暴露的Telegram Bot/Resend凭据需在对应平台轮换。JWT轮换只撤销邮箱会话。
4. 测试账号、SQLi遗留用户、孤儿 account 保留；清理需要逐条核对所有权和业务邮件，避免删除真实数据。
5. 出站 Webhook 默认关闭；恢复只批准操作者控制的公网 HTTPS 接收端，避免给测试者域名转发真实邮件。

## 发布命令与防回退
使用 `mail-worker` 工作目录：
```
npx wrangler deploy --config wrangler.toml --keep-vars --no-autoconfig
```
生产 jwt_secret 通过 `wrangler secret put jwt_secret` 管理，使用密码学随机数生成器；保持 D1/KV 资源 ID。
主站使用仓库 `_headers`（Cloudflare Pages官方支持）及404.html，GitHub main推送自动部署。

参考：[DOMPurify](https://github.com/cure53/DOMPurify)、[Cloudflare Request redirects](https://developers.cloudflare.com/workers/runtime-apis/request/)、[Cloudflare Pages headers](https://developers.cloudflare.com/pages/configuration/headers/)。
