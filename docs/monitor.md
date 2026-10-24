# 监控、今日用量与私有网页

这个目录保留 collector、日账本、只读本机网页、上传器和测试源码。`web/` 是另外一份完整的私有 Sites 工程。它们不记录访问的网址或内容，只处理设备状态、速率和用量。

## 数据路径

```text
strongSwan VICI -> Python collector -> 本机 status.json
                                      |            |
                              127.0.0.1:8767       Node uploader
                                                   |
                                          owner-private Sites + D1
```

collector 每秒采样。今日累计使用 `Asia/Kuala_Lumpur` 日界线；未知计数不会变成零，重连与换钥不会重复相减。计数是已采样小计，不能当运营商计费账单。

网站实时数据每秒刷新，历史最多每分钟保存一个有效点，保留七天。图表默认显示最近 24 小时所有设备的用量，纵轴为每 30 分钟上传加下载量。可勾选设备；尚未记录或无法可靠比较的时间段留空，当前未完成区间只显示已观察部分。

## 离线构建与检查

要求 Python 3；上传器及网页要求 Node 24 或更新版本。

```sh
python3 -I -B monitor/check.py
node --test monitor/uploader/check-loop.mjs
cd web
npm ci
npm test
npm run build
```

`monitor/build.py` 将完整运行时及 UI 写入 `monitor/build/`，重建内容摘要，替换服务入口的文件绑定。它不会连接 VICI、安装服务、读取账本或操作防火墙。测试使用合成会话和临时文件；通过不代表真实多手机验收。

## 安装适配

这份源码来自已运行工程的公开化快照，不是通用监控一键安装器。已有安装不能直接覆盖；先核对原版本和备份。新的安装需匹配核心工程的设备 registry、strongSwan 路径与 VICI socket：

| 资源 | 默认位置/要求 |
| --- | --- |
| VICI | `/var/run/family-vpn/charon.vici`，`runtime/worker.py` |
| strongSwan daemon | `/usr/local/family-vpn/strongswan-6.1.0/libexec/ipsec/charon` |
| 设备 registry | `/usr/local/etc/family-vpn/devices.json`，使用核心工具生成 |
| collector 运行时 | `/usr/local/family-vpn/monitor`；root 目录 0700、文件 0600 |
| 服务入口 | `/usr/local/family-vpn/monitor-service/service.py`；root 0600 |
| 私有账本 | `/private/var/db/family-vpn/monitor-daily`；root 0700 |
| 公开快照 | `/private/var/run/family-vpn-monitor/status.json`；目录 0755、文件 0644 |
| 本机 UI | `/usr/local/share/family-vpn-monitor`；root 目录 0755、文件 0644 |

运行时目录只放 `build/runtime/` 的文件，包含新生成的 `installed-manifest.json`。UI 目录只放 `build/ui/`；不能混入测试、源码清单或构建脚本。以上程序检查固定路径、归属、ACL 和摘要，路径修改后必须重新构建。私有账本不要发布或迁移到公开目录。

root LaunchDaemon 使用 `org.familyvpn.monitor`，入口为 `/usr/bin/python3 -I -B /usr/local/family-vpn/monitor-service/service.py`，配合 `RunAtLoad`、`KeepAlive`、60 秒 `ThrottleInterval` 和标准输出 `/dev/null`。对应 launchd 示例在 `monitor/launchd/`。普通用户 UI 使用 `/usr/bin/python3 -I -B /usr/local/share/family-vpn-monitor/ui.py`。UI 只能监听 loopback，不能直接开放到公网。首次新机安装和真实 launchd 生命周期需要在目标 Mac 验证，本仓库离线检查不自动完成这部分。

## 配置私有 Sites

`web/` 是 Vinext/React + Cloudflare Worker + D1，包含完整 lockfile、迁移、历史计算和前端测试。`.openai/hosting.json` 仅保留 `DB` 绑定，不含原站点身份。

1. 在 Sites 创建新的**仅本人可见**站点，将新 `project_id` 写入该 manifest。
2. 配置 D1 `DB`，应用 `web/drizzle/` 的迁移；数据库从空库开始，不上传真实历史快照。
3. 验证平台对整个站点（包括 `/monitor/`、`/api/status`、`/api/history`）执行 owner-private 登录策略；对 `/api/telemetry` 验证上传服务凭据。
4. 仅完成上述配置后，在站点运行时设置 `FAMILY_VPN_PRIVATE_SITES_DEPLOYMENT=owner-private-confirmed`，构建并私有发布。缺少该值时生产 Worker 默认返回 503。
5. 用未登录浏览器确认被拒绝，再用本人账号确认能够访问；无上传凭据的 POST 应被平台拒绝。

**这个显式开关不是认证机制。** 实际认证由 Sites dispatch 提供，代码不能自行证明网关配置正确。应用读取的 ChatGPT 身份头只有来自可信平台才有意义。移到普通 Workers 或其他主机时，必须先增加服务端认证与授权；不要设置该开关后裸部署。静态资源可能由平台直接提供，不一定经过这个 Worker 开关，因此它不能保护整个站点。私有 dispatch 必须覆盖静态与 API；API 和数据存储不能只靠此开关保护。

## 上传器

只有确定新站点是 owner-private 后才构建：

```sh
python3 monitor/uploader/build.py \
  --site-url https://YOUR-PRIVATE-SITE.chatgpt.site \
  --keychain-account appgprj_YOUR_PROJECT_ID
```

构建程序只接受站点地址和非秘密的项目标识，不接受 token。默认源码 `CONFIGURED=false`，直接安装或运行会拒绝。构建结果位于忽略的 `monitor/uploader/build/`。

使用 macOS「钥匙串访问」安全保存平台颁发的私有站点服务凭据：服务名 `org.familyvpn.sites.monitor`、账户名与上述项目 ID 相同。不要把凭据放进 Git、命令行参数、环境文件或聊天。

普通用户执行 `node monitor/uploader/build/install.mjs` 安装 LaunchAgent；它绑定当前 Node 可执行文件的绝对路径，因此 Node 必须安装在长期稳定的位置。源码装入当前用户 `Library/Application Support/Family VPN/Sites`。未知旧版本会拒绝覆盖，需明确迁移，不能强制删除来绕过检查。

上传器每秒串行 POST，慢响应不会重叠或补发一串历史请求；网络错误退避，鉴权失败后重新读取 Keychain。上传失败不会停止 VPN。卸载该用户的 `org.familyvpn.sites-monitor` LaunchAgent 后，可单独停用上传而保留本机监控和 VPN。
