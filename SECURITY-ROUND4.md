# 2026-10-22 第四轮主动复核与加固

生产邮箱 Worker：`35fcc5f1-cb1d-42b0-b70c-69703ade72aa`。

## 新发现与处置
1. **改密保留旧会话：已复现、已修复。** 隔离测试中原 resetPassword 更新口令后 auth-uid 缓存仍在。现自行改密需提供当前密码，5次/分钟限速、8KiB请求上限；修改成功撤销会话并引导重新登录。管理员重置与已验证的旧哈希升级共用更新入口。
2. **KV旧会话恢复风险：已修复。** 每个认证请求从D1读取当前用户salt/状态/删除标记/邮箱；登录缓存携带credentialVersion。随机salt随改密轮换，作为现有口令版本；D1版本不匹配即401。新登录遇到旧版本KV会丢弃旧token集合。Miniflare中模拟将改密前KV整份写回，旧会话仍401；随后新密码登录成功，旧token不会重新加入。每次认证增加一次D1单行读取。
3. **附件转换越权：隔离复现、已修复。** 原 toImageUrlHtml 会仅按key查询其他用户附件并加载对象。现所有站内图片转换必须传入可信userId，按key+user_id查询，缺失或不属于当前用户则404，拒绝发生在对象读取前。覆盖 attachments/、/attachments/、/oss/attachments/ 三种入口及路径穿越输入。线上发信保持原配置，本轮测试未向外部发送真实邮件。
4. **发信前置检查：已修复。** 关闭发信/角色权限/发送账号归属/回复邮件归属先于附件加载；接收人格式与数量、附件数量、头字段换行在外部副作用前校验。正文请求上限32MiB，内嵌图片数量在实际发送前检查。
5. **未配置OAuth公开入口：已关闭。** 当前三个渠道clientId为空且开关关闭。源码绑定流程接受用户提供的oauthUserId，缺少授权绑定证明，并有跨平台身份作用域/state等后续审查项。现整个/oauth前缀403，免认证名单精确匹配；此处属于移除闲置攻击入口，OAuth完整安全启用流程保留待开发。
6. **封禁与注销边界：已加固。** status规范为0/1，字符串"1"也执行会话撤销；永久删除用户同步清理认证缓存；D1认证检查持续拒绝禁用/已删除用户。

## 依赖审计
- 官方npm注册表 `pnpm audit --prod --registry=https://registry.npmjs.org --json`：后端、前端当前info/low/moderate/high/critical均为0。
- 移除Worker中未被引用的@cloudflare/vite-plugin，避免将开发服务依赖列为运行依赖；升级AWS SDK、Drizzle、Hono、Resend、UUID、UA Parser及Vue、Axios、Element Plus、Lodash、ECharts等。
- ECharts跨主版本升级另做SVG服务端柱状图渲染检查；生产构建及登录页面加载通过。
- 此结论覆盖已知生产依赖公告。开发工具依赖、未公开漏洞与业务权限设计需要分别审查，依赖告警数和实际可利用网站漏洞数分开记录。
- 原始/最终审计JSON位于 `F:\AI\codex\软件开发\cloud-mail-security-artifacts`。
- 参考：[fast-xml-parser维护方公告](https://github.com/NaturalIntelligence/fast-xml-parser/security/advisories/GHSA-m7jm-9gc2-mpf2)。

## 验收证据
- 回归测试：29条通过；测试命令 `cd mail-worker && npm run test:security`。
- 实际Miniflare Worker：真实登录、旧口令哈希升级、当前口令校验、改密、新密码登录、旧KV恢复模拟、私有附件归属、Telegram能力链接、签名回调关闭策略、D1限速均通过。
- 线上：邮箱与主站200，CSP/HSTS有效，恶意Origin无ACAO；OAuth绑定/登录403；匿名改密401；此前伪造管理员JWT401；合成不存在账号第11次尝试429。
- 生产网页登录页加载通过。Cloudflare分析beacon仍按既有CSP策略阻止，不扩展第三方脚本权限。
- 本轮统一撤销2份会话；最新D1凭据版本检查同时使此前缺少版本的缓存失效。
- D1邮件总数228、未删除228，保持与备份一致；本轮未删除邮件、用户或附件。

## 备份
`F:\AI\codex\软件开发\cloud-mail-security-backups\cloudmail-before-round4-20261022.sql`
SHA256：`36a3373b679d1af41a32f0cd9762376a9127c09c77f48069827cff45e1d2a11e`；SQLite integrity_check=ok。

## 剩余配置与审计边界
- DNS实时仍为DMARC p=none、SPF ~all。DNS编辑授权与合法发信来源/对齐验证仍待完成；修改策略前保护合法发信。
- 公开注册仍保留既有策略和原子限速；Turnstile或邀请码方案待用户选择，Turnstile需有效配置。
- 历史暴露的第三方服务凭据轮换需分别核对。用户报告已修改密码，凭据内容不回显。
- 报告中3个测试遗留账号仍启用：autotest1（6封）、massassign1（0封）、uid12（0封），已向用户请求禁用确认；保留数据。
- 未进行资源耗尽测试、真实第三方发信、未配置OAuth的身份提供商端到端测试。S3存储和外部回调恢复需要各自独立验收；当前生产使用既有KV与D1。
