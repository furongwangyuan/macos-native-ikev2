# 可选维护 CLI

维护 helper 让普通用户读取固定状态、有限日志、主机网络检查，以及请求 VPN/监控的有限恢复。它不提供任意 shell 或任意文件读取，也不安装定时任务。VPN 与监控可以不安装这个辅助组件。

## 离线检查和构建

```sh
python3 -I -B maintenance/check.py
python3 maintenance/build-install.py --user YOUR_MAC_SHORT_USERNAME
```

使用当前 Mac 的短用户名，例如 `id -un` 的输出，不是显示姓名。构建只写 `maintenance/build/`，不提升权限；其中包含可审阅 installer、AppleScript 安装入口与摘要清单。默认示例用户名 `example` 只供离线检查。

构建器会将 helper 内容嵌入 installer，生成只授权一个固定 root-owned 程序的 sudoers 规则。审阅生成的 `installer-reviewed.py` 和规则后，才由本机管理员运行：

```sh
sudo /usr/bin/python3 -I -B maintenance/build/installer-reviewed.py
```

安装器校验标准 sudoers include、以 visudo 检查新规则、保留未知既有文件；不修改全局 sudoers，也不允许任意 Python 参数。目标是 `/Library/PrivilegedHelperTools/org.familyvpn.maintenance.py`，状态在 `/private/var/db/family-vpn-maintenance`。

## 使用

```sh
python3 -I -B maintenance/client.py snapshot
python3 -I -B maintenance/client.py network
python3 -I -B maintenance/client.py read-log service-events 0
python3 -I -B maintenance/client.py repair monitor
```

命令形式以 `client.py` 顶部允许集合为准。`repair vpn` 和 `repair monitor` 是会改变已知服务状态的命令；手动停用、未知版本、配置变化、退避或重试预算耗尽时可能拒绝恢复。检查的日志范围有限，不会读取密钥、私有设备配置或任意路径。

helper 依赖核心工程的固定路径、launchd 标签和状态 schema。先安装并验证对应版本核心服务，再启用此工具。这里的测试 mock 系统 I/O，只验证授权范围与恢复判定，不代替目标机安装验收。
