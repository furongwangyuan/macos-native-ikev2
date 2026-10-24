# 服务端源码与配置边界

仓库收录当前运行版本的 Python 控制层、证书管理、设备注册、恢复逻辑和发行构建源码。
公开版本已将个人域名、LAN 地址、设备编号及原 CA/配置指纹替换为示例或未绑定值。
**它是完整的维护工程源码参考，不是新 Mac 上可以直接运行的安装包。**

## 本仓库实际支持的命令

```sh
# 只解析源码、检查闭包；不导入或运行服务
python3 -I -B server/tools/build_reference.py --check

# 运行隔离回归，禁止实际 socket 和 subprocess
python3 -I -B tests/server/run.py

# 生成逐文件 SHA256 清单及参考源码包
python3 -I -B server/tools/build_reference.py --output build/reference-server
```

输出目录必须尚不存在，且位于本仓库的 `build/` 下。`REFERENCE-MANIFEST.json`
明确标记 `deployable: false`。它不是已安装状态、证书信任、系统恢复或手机验收的证明。
整个流程不需要管理员密码，也不会修改当前 VPN。

原版源码冻结及发行装配算法保存在 [`server/reference-build`](../server/reference-build)，
其 CLI 已明确禁用。原历史依赖所需的非秘密 manifest 保存在 `server/compat/`。
源码包含算法，不能把参考包复制到系统目录后视为已完成新机部署。

## 配置需要一致更新的位置

| 配置 | 示例 | 涉及源文件 |
|---|---|---|
| 外部服务器域名 | `vpn.example.com` | `runtime/profile_export.py`、DDNS 配置 |
| IKE 服务器身份 | `vpn.family.home.arpa` | `runtime/registry.py`、`swanctl.guardian.conf`、profile/证书生成 |
| LAN IPv4 | `192.0.2.8` | `fleet_policy.py`、`fleet_vici.py`、`native_policy.py`、网络/规则模板 |
| 家庭公网示例 | `203.0.113.8` | `family-vpn*.pf`、初始 profile 工具 |
| 物理接口 | `en0` | 路由校验、PF 模板、守护配置 |
| 隧道 IPv4 池 | `10.77.26.0/24` | `registry.py`、PF/SPD 校验、设备地址分配 |
| 隧道 IPv6 池 | `fd6d:fe83:ab27:2600::/64` | 同上 |
| 每日用量时区 | `Asia/Kuala_Lumpur` | `registry.py`、监控层 |
| 初始设备 | `device01`；测试第二台 `device02` | 初始 registry、设备证书与示例 fixture |

`192.0.2.8` 和 `203.0.113.8` 是文档地址，不能用于真实网络。私有地址池也是示例，
必须避免与服务器或客户端现有网段重叠。外部域名与 IKE 身份是两个不同字段：
profile 的 RemoteIdentifier、服务端 IKE 身份及服务器证书 SAN 必须一致；
外部域名可以只承担找到家庭公网地址的作用。

这些参数原本被冻结在一个受控部署中，尚未统一改成可热加载的配置文件。
改变地址池、接口或域名时，应在隔离副本中一致更新相关生成器、严格验证器、PF 模板
和测试 fixture，并重新生成源码绑定。只改一份 `swanctl.conf` 不够。

## 首次 PKI 与本机信任绑定

`server/provisioning/provision-credentials.py` 保留最初创建 CA、签发服务器和设备身份、
生成 profile 的实现；`--help` 提供明确的子命令。它不会隐式创建身份。
`runtime/enrollment.py`、`profile_export.py`、`staged_issuer.py` 和
`control/device_*.py` 是后续设备生命周期实现。

当前 `control/pki_registry_setup.py` 是**既有部署的迁移代码**：原来会核验指定 CA、
初始设备证书序列号及已撤销旧身份的历史。公开版本将原 CA/profile 指纹改为全零，
保留验证流程供阅读。全零不是有效的信任根，也不能改成“任何证书均通过”。
新部署需要自己的 CA、服务器/设备证书和新的初始化流程；不要伪造旧迁移记录。

原生 OpenSSL、CRL helper、daemon 配置、源码清单和安装历史也有固定哈希绑定。
`native/build_crl_helper.py` 生成的是本次编译的真实哈希，不能直接宣称它等同于历史
构建结果。新安装或迁移应明确绑定本机实际产物，并保留恢复路径。

## 运行维护逻辑仍保留

- 每台设备具有独立证书身份和 IPv4/IPv6 虚拟地址。
- 一台设备加入、重连、退休或撤销时，控制层尽量只收窄该设备的转发。
- 完整 SPD/VICI 观察与实际发布前的再次核验保留；不会把部分观察当作完整清单。
- VICI 完整观察有 48 个 IKE 事件上限；短暂容量失败可进入现有有界恢复，持续超限
  仍可能耗尽恢复次数。不是无限连接容量或完整抗 DoS 保证。
- 明确停止会保留停止意图，不由恢复逻辑擅自重新启用。

macOS 系统网络修改、launchd 安装和证书签发都需要完成独立的部署适配。
本仓库不会为“方便安装”删除这些检查，也不会在源码打包时改变用户机器的网络。

## 验证范围

导出的核心测试运行真实 Python 模块，覆盖多设备隔离、重连/rekey、策略观察交错、
身份冒领、状态清理及资源边界。OS 网络操作使用模拟适配器，测试程序拒绝实际连接
socket 或启动子进程。当前通过的是代码层回归，不能代替真实双手机、双栈泄露、
重启恢复、跨境网络与吞吐量验收。原生构建细节见 [native-build.md](native-build.md)。
