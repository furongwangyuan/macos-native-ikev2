# 配置说明

## 适用范围

目标是 Apple Silicon Mac 上原生运行 strongSwan，iPhone 使用系统 IKEv2，不使用 Linux 虚拟机或第三方 iOS 客户端。公开版用于理解、构建及移植完整工程；**仓库没有可直接在空白 Mac 上运行的通用首次安装器**。`server/` 中旧机升级/PKI 迁移模板仍需要部署者生成自己的绑定与初始状态，不能靠跳过验证把它们变成首次安装器。

以下步骤区分“可以直接进行的源码构建”和“需要适配并验收的系统部署”。只有构建成功，不代表 VPN 已安装或已可上网。

## 1. 准备网络和工具链

记录 macOS 版本、CPU 架构、Xcode Command Line Tools、SDK 和 Python 版本：

```sh
sw_vers
uname -m
xcode-select -p
xcrun --show-sdk-path
python3 --version
networksetup -listallhardwareports
route -n get default
route -n get -inet6 default
```

确认家庭宽带具备可从公网到达的 IPv4，以及可用的 IPv6 默认路由。路由器 WAN 地址若是私网或 CGNAT 地址，普通端口转发不够，须先取得运营商可入站的地址。给 Mac 的有线接口设置 DHCP 地址保留。不要假定任意 Mac 的以太网都叫 `en0`。

IPv4 入口将 **UDP 500、UDP 4500** 转发到这台 Mac 同名端口，域名 A 记录指向家庭公网 IPv4。不要把 SSH、VICI、监控端口或 DMZ 一并开放。方案使用 UDP 封装；隧道内 IPv6 不要求入口也使用 IPv6。

可选的 IPv6 入口需要客户端与家庭宽带之间真正可达的 IPv6 路径，并在家庭路由器的 IPv6 防火墙中允许 UDP 500/4500 到 Mac 的当前稳定全局地址。它使用该 IPv6 地址直接入站，不是把 IPv4 端口转发规则复制一遍。先用限定来源的测试验证真实认证与数据，再考虑公开 AAAA；仅验证 UDP 到达、IKE 认证或监听端口不够。

新会话将已核验的 LAN IPv4 和 `en0` 稳定 IPv6 地址一起绑定到连接配置、策略观察及 PF 入口规则。旧 IPv4 会话记录保留原含义。当前地址作用域在一次运行期间固定；ISP 前缀变化的不中断热更新尚未实现，不能只修改 DNS 或配置文件就认为运行中的新地址已生效。现有 [DDNS helper](ddns.md) 仍是 A-only 且要求 AAAA 为空；本次源码更新没有为它新增 AAAA 调度。

## 2. 确定一组一致的部署参数

| 参数 | 示例 | 必须同步的地方 |
| --- | --- | --- |
| VPN 入口域名 | `vpn.example.com` | DDNS、iOS `RemoteAddress`、连接排查 |
| 服务器 IKE 身份 | `vpn.family.home.arpa` | 服务器证书 SAN、strongSwan local id、iOS `RemoteIdentifier` |
| Mac 有线接口 | `en0` | PF、路由/地址校验、DDNS、恢复逻辑 |
| Mac 局域网 IPv4 | `192.0.2.8`（文档保留地址） | `outer_endpoints.py`、连接生成、本机地址校验、路由器目标 |
| 可选外层 IPv6 | 启动时核验的有线接口稳定全局地址 | 会话作用域、连接 `local_addrs`、PF/路由观察、路由器 IPv6 防火墙；AAAA 仅能发布已生效地址 |
| 客户端 IPv4 池 | `10.77.26.0/24` | 地址分配、selectors、PF、观察器、测试 |
| 客户端 IPv6 池 | `fd6d:fe83:ab27:2600::/64` | 地址分配、selectors、NAT66、观察器、测试 |
| 设备身份 | `device01.family.home.arpa` | 客户端证书 SAN、设备 registry、iOS local id |
| DNS | 自选可从家庭宽带访问的递归 DNS | strongSwan 地址池、客户端实际验证 |
| 统计时区 | `Asia/Kuala_Lumpur` | 今日用量与日期边界 |
| 安装目录 | `/usr/local/family-vpn` | 构建 prefix、launchd、权限和维护命令 |

域名地址与服务器证书身份可以不同，但必须保持各自绑定一致。仓库中的 `example.com`、`.invalid`、`192.0.2.0/24` 等只用于示例。内部池也必须检查与家庭网络和客户端网络是否冲突。

**目前这些参数尚未全部收敛到一个运行时配置文件。** 不要只改一份 `swanctl` 文件：连接由 `server/runtime/registry.py` 等模块生成，PF、验证器、设备签发和发布清单共同约束它。按 [服务器源码说明](server-source.md) 的配置点同步修改，再重新生成本地清单和测试。`config.json`/`supervisor-config.json` 的默认关闭值也不是部署向导。

## 3. 编译原生依赖

按 [native-build.md](native-build.md) 获取固定版本、校验 SHA256 并在临时目录构建。使用 `kernel-pfkey` 和 `kernel-pfroute`；不使用 `kernel-libipsec` 作为默认数据路径。上游 macOS 构建说明见 [strongSwan 官方文档](https://docs.strongswan.org/docs/latest/os/macos.html)。

构建 OpenSSL、strongSwan、CRL 验证 helper 后记录自己的架构、SDK、版本和摘要。不同工具链输出不应伪装成原机器二进制的 hash。参考包的源清单核验不等于管理员安装许可或系统部署验收。

## 4. 建立自己的 PKI 和每设备身份

新部署需要新的 CA 私钥、CA 证书、服务器私钥/证书、初始 CRL、设备私钥/证书、独立 serial 和设备地址分配。服务器证书必须满足 IKEv2 身份及用途要求；客户端证书与 registry 的身份、序列号、分配地址对应。

本工程提供证书签发、CRL、设备登记和配置导出实现。已有部署迁移入口会检查 CA/旧证书/收据，因此它不能代替一套空白 PKI 的初始化。移植时应编写匹配本机初始状态的引导步骤并保留校验，不要复制其他人的 CA、伪造旧收据或直接取消撤销检查。

一台设备一个身份。泄露或丢失时单独撤销，避免整个家庭共享一个 P12。`.mobileconfig` 中若含 PKCS#12，其文件本身即可承载登录能力，即使安装时不要求额外证书密码，也必须私下交付；手机仍可能要求锁屏密码确认安装。

参考 [strongSwan iOS 互通说明](https://docs.strongswan.org/docs/latest/interop/ios.html)。配置生成器包含独立 CA payload、设备身份 payload 与 IKEv2 payload，不要只发送一个无对应身份的 VPN 设置段。

## 5. 配置 macOS 数据路径与服务

此工程使用一个专属 PF anchor、IPv4 NAT、IPv6 NAT66、IPsec policy/SA 观察和按设备准入。`0.0.0.0/0` 和 `::/0` 均是隧道业务的选择范围。全局 Internet 转发不等于授予家庭 LAN 或 Mac 管理面的访问权限。

参考逻辑会记录原系统状态、只管理自己拥有的资源，再在停止/恢复时还原。移植须检查现有 PF anchor 位置、其他软件的 PF 规则、系统应用防火墙、IPv6 RA/默认路由及本机接口变化。不要直接覆盖 `/etc/pf.conf`、清空全局 SPD/SA，或以修改全机默认路由代替客户端转发。

部署顺序为：安装自己的原生构建 → 安装已绑定的运行源码和 PKI → 建立 root-owned 配置/权限 → 验证恢复路径 → 短时启动 → 完成单设备数据路径验证 → 安装 launchd 常驻任务。发布参考构建不会自动执行这些系统变更。

## 6. iPhone 全局配置

采用证书认证、手动系统 VPN 开关、IPv4/IPv6 默认流量选择器及 `IncludeAllNetworks`。不添加国家、网站或应用直连规则。按需连接默认关闭，以便用户主动关闭后恢复普通网络。

当前 iOS 配置生成器设置隧道 **MTU1280**。保留这一值作为已测试的起点：外层 IPv6、UDP 和 ESP 还有封装开销，直接套用普通以太网 MTU1500 可能让 TCP 已连接但 TLS 大包无法往返。它是客户端隧道设置，不要求把 Mac 的物理接口全局 MTU 改为 1280；实际路径仍需验证。

Apple 对 `IncludeAllNetworks` 的系统流量范围有例外；启用它时 `EnforceRoutes` 不会进一步增强同一设置。断线保护可能让连接恢复期间无法直接付款或上网。服务器不能保证让 iOS 每次故障都显示“已断开”，也不能替用户在手机上关闭 VPN。详见 [Apple IKEv2 配置字段](https://developer.apple.com/documentation/devicemanagement/vpn/ikev2-data.dictionary) 和 [路由说明](https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic)。

安装后先用蜂窝网络验证公网入口，避免把同一 Wi-Fi 的 NAT 回环表现误当成公网表现。验收项目见 [validation.md](validation.md)。

## 7. DDNS 和监控

先确认核心隧道可用，再按 [DDNS](ddns.md) 和 [监控](monitor.md) 配置。DDNS 口令、站点上传令牌留在各自的 root-only 文件或 Keychain；不要填写进源码。

本机监控仅监听 loopback。远端面板依赖 Sites 的 owner-private 访问控制，**不能把当前路由裸部署到公网并声称已有应用级登录**。源码公开与在线面板私有是两个独立设置。
