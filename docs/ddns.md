# Dynadot 动态 DNS

DDNS 只用来找到家庭入口，不中继 VPN 流量。此组件针对 Dynadot；其他提供商不能仅替换域名后使用。

依赖 macOS 的 Python 3、curl、dig、ifconfig、launchctl，以及可控制的 Dynadot 域名。不要把真实 DDNS 配置、密码或 API 响应放进仓库。

## 配置和构建

```sh
python3 -I -B ddns/check.py
python3 ddns/build.py --domain example.com --subdomain vpn --interface en0
```

第二条命令中的域名必须改成自己的。`example.com` 是保留示例，不会提供可用入口；接口应是 Mac 实际连接家庭路由器的以太网接口。仅构建不会请求网络或修改 DNS。生成目录为 `ddns/build/`，包含所有重新绑定摘要的 helper、安装桥接、scheduler 与操作入口。

源码的 `DOMAIN/HOST/FQDN`、以太网接口以及 Dynadot 权威服务器需与实际账户匹配。构建工具修改前四项；`NAMESERVERS` 默认为 Dynadot 的权威服务器。若域名使用其他托管 DNS，应先改用正确提供商实现，而不是照抄 API。

## 初次安装

1. 在 Dynadot 给自己的目标子域配置 A 记录并开启 Dynamic DNS，自己保存新专用密码。
2. 构建并核对 `ddns/build/helper/update.py` 的域名和接口。
3. 本机打开 `ddns/build/helper/import-DDNS-password.command`。先输入 Mac 管理员密码；仅在隐藏 DDNS 密码提示出现后输入域名凭据。导入验证成功才保存 root-only 配置。
4. 打开 `ddns/build/scheduler/安装并核验DDNS自动更新.command`。它安装独立的 `org.familyvpn.ddns` LaunchDaemon，等待首次正常调度结果；不启动 VPN。
5. 使用同目录的检查入口查看调度状态，再独立查询当前权威 A 记录。已加载任务或退出码 0 不能代替实际 DNS 验证。

凭据文件固定为 `/usr/local/etc/family-vpn/dynadot-ddns.json`，root-only，不纳入公开工程。提供商凭据可能拥有整域权限；本地程序只更新指定子域，不等于服务商给予了单记录权限。

## 行为与限制

- helper 从两路 HTTPS 观测公网 IPv4，核对权威 DNS 后只更新目标子域 A。当前设计要求该入口没有 AAAA；隧道内部仍支持 IPv6。
- launchd 每 60 秒检查是否到期，成功后的更新窗口为 300–330 秒，再加实际调度延迟。失败指数退避到约一小时，不会每秒写 DNS。
- 时钟回拨、重复任务、失败重试和更新冷却有专门处理；离线测试完全模拟 HTTP、密码和服务操作。
- scheduler 与 helper 保持固定摘要绑定。改源码必须重新构建，不能单独换一份文件。
- 已存在未知版本时安装器保留并拒绝覆盖。此公开版本没有为任意旧版本提供自动迁移器。
- 「卸载DDNS自动更新.command」卸载调度，保留 helper、凭据和最后 DNS 记录。删除凭据、撤销服务商密码、删除 DNS 记录是独立操作。
- 纯 IPv6 WAN、CGNAT、其他 DNS 提供商及不同 macOS 的新装需要单独适配。DDNS 不解决运营商入站阻断或跨境丢包。
