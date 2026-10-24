# 私有 VPN 监控网站

完整设置见 [监控配置说明](../docs/monitor.md)。本目录包含 Vinext/React 前端、Worker、D1 迁移和测试。实际数据、数据库、站点身份和凭据不在仓库。

```sh
npm ci
npm test
npm run build
```

Node >=24。原始模板工具说明见 `README.upstream.md`。

只能在确认 owner-private 的 Sites dispatch 后启用生产服务。`FAMILY_VPN_PRIVATE_SITES_DEPLOYMENT=owner-private-confirmed` 是防误发布开关，**不是认证实现**。缺少它时生产 Worker 返回 503。迁移到其他平台必须先增加服务端认证与授权。不要把允许开关设好后裸部署。

本机开发可以使用合成数据。`.openai/hosting.json` 没有预置 `project_id`；新站点必须使用自己的 ID、私有策略与空 D1 库，不得复用原用户实例。
