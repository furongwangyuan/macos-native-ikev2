# 源码发布检查

本文件记录公开源码快照的检查，不能替代部署与手机端验收。

所有检查以普通用户运行，没有更改正在使用的 VPN、路由器、PF、launchd、PKI、DDNS 或在线监控站点。原生编译配方在本次发布中进行语法和输入清单检查；未重新编译整套 strongSwan，也未在新 Mac 上安装。

可在干净检出中重跑：

```sh
python3 scripts/check_source.py
python3 -I -B server/tools/build_reference.py --check
python3 -I -B tests/server/run.py
bash -n native/build-native.sh
python3 -I -B monitor/check.py
python3 -I -B ddns/check.py
python3 -I -B maintenance/check.py
node --test monitor/uploader/check-loop.mjs
cd web
npm ci
npm test
```

`check_source.py` 检查文本源码、Python 语法、JSON、相对文档链接和常见凭据格式。它不是能识别一切秘密的证明；发布前另做了部署标识、嵌入资源及第三方许可人工审阅。

`tests/server/run.py` 禁止真实 socket、Popen 和 os.system；其策略/会话测试使用合成状态。监控、DDNS 和维护测试用模拟 IO，不使用真实凭据或发送 DNS 更新。构建输出放在忽略的 `build/` 目录，未作为可安装发行二进制发布。

## 2026-10-25 发布前结果

在从 Git 暂存清单单独导出的干净目录中执行：

| 检查 | 结果 |
| --- | --- |
| 源码/JSON/相对文档链接/常见凭据格式 | 通过 |
| 服务器源码闭包 | 131 个文件，参考包哈希回读一致 |
| 服务器隔离回归 | 20/20 |
| 监控计量及本机读取 | 10 组通过 |
| DDNS 解析/调度/安装模拟 | 44/44 |
| 维护工具 | 51 项检查及 28 组恢复判定通过 |
| 上传器循环 | 7/7 |
| 网页历史模型、SQLite、部署开关 | 16/16 |
| 网页依赖锁安装与生产构建 | 通过，Node 24.19.0 |
| 原生编译脚本语法 | 通过；本轮未全量重新编译 |

干净目录的首次网页测试因尚未安装依赖而失败；补上 `npm ci` 后全部通过，CI 和本文步骤均包含该安装步骤。网页构建提示部分动态路由无法静态分类，未将此提示视为线上路由验收。

独立发布审查检查了 Git 候选文件、Python 嵌入字节、部署标识及许可证。常见凭据扫描不是形式化安全保证；仍禁止将后续生成的真实安装资料提交进 Git。本仓库 CI 使用上面的离线命令，远端 CI 结果以 GitHub Actions 页面为准。
