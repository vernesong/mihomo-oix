# Linux 自动防火墙与旧配置兼容

`iptables.enable` 和已有字段保持有效；新增 `iptables.backend` 默认 `auto`
旧 YAML 无需添加 backend，也无需为切换后端改写原来的接口字段
本功能只接管内核内置的 IPv4 TPROXY 自动规则，外部路由插件/脚本需各自适配

| 环境 | auto 选择 |
| --- | --- |
| 有 Firewall4 | nftables，需有 nft 命令和内核支持 |
| 已有 nftables 表 | nftables，避免混入 legacy 规则 |
| nftables 没有活动表，iptables 使用 legacy 实现 | 沿用 iptables，安装了 nft 工具也不改变旧栈 |
| 其余有 nft 的环境 | 优先预检并使用 nftables |
| 没有 nft / Firewall4，有 iptables | iptables |
| 原生预检失败，无 Firewall4、无 nftables 表且有 iptables | 在任何规则写入前尝试 iptables |
| 无工具、权限不足或当前防火墙缺少必要内核能力 | 返回具体错误 |

可用 `backend: iptables` 或 `backend: nftables` 显式覆盖选择
日志会记录 `[TPROXY] Setting firewall completed (backend: ...)`
不会自动安装、替换或卸载系统防火墙

## 保留的旧配置语义

`inbound-interface` 名称容易产生误解：旧实现用它限制本机 OUTPUT、配置网关
转发/NAT，并不限制 PREROUTING
新原生后端保留这一含义：

- 未指定时仍为 `lo`；LAN 的 TCP/UDP 和 DNS 入站仍会接管，不会退化成仅本机
- 本机普通 TCP/UDP 仅对经该接口出站的流量设置代理标记；DNS 重定向保持原范围
- 非 `lo` 时启用 IPv4 转发，并对经该接口转发、源地址非本机的流量做 MASQUERADE
  已开启转发时不重复写 sysctl；像旧版一样，结束时不关闭系统 IPv4 转发
- 保留 Docker 源网段排除、默认私网与用户 IPv4 bypass、代理出站 mark 绕过
  关闭 `dns-redirect` 后，DNS 流量按普通 TPROXY 规则处理
- LAN 场景仍需 `allow-lan: true` 和可接收对应连接的 TPROXY/DNS 监听地址
  不自动猜测接口，也不改写监听设置
参见 [README 配置示例](../README.md#automatic-linux-firewall-configuration)

两条自动路径均为 IPv4，且与 `tun.enable` 互斥
TUN 的 `auto-route` / `auto-redirect` 不受本次变更影响
无效端口、导致回环的原生出站 mark、无效原生 bypass 会报错，
不将过去被忽略的错误当成可用配置

## Firewall4 与生命周期

原生规则位于独立的 `ip mihomo_tproxy` 表
标准 Firewall4 reload/restart 只重建自己的 `inet fw4` 表，
因此不用写入 `/etc/nftables.d`、强制重载 fw4，也不用额外放宽其 INPUT 策略
正常 LAN 放行、WAN 拒绝策略继续生效

内核用 `nft -c -f -` 预检实际规则能力，之后设置策略路由并以单个 nft 事务写入自己的表
依赖 nft、ip、网关模式下的 sysctl，以及内核 TPROXY、FIB、NAT/redirect 支持
无需仅为 divert 快捷匹配额外安装 nft_socket 模块

保留策略路由表/标记 `0x2d0`（720）及默认代理出站 mark 2158；由单个实例独占
规则应用失败会清理成功创建的规则/路由，清理失败保留状态供重试
不会覆盖冲突路由，也不会在清理旧规则时清除新配置明确设置的 routing-mark
旧 iptables 路径同样检查执行结果并反向清理已安装规则；
删除了新建空链后的重复 flush、重复的转发规则和私网列表

原生表不会覆盖其他防火墙表的 DROP/REJECT
自定义的 LAN INPUT/FORWARD 拒绝策略仍需管理员按需求放行；这不等于任意第三方防火墙策略都可以零调整迁移
SIGKILL、断电残留或外部全局 flush 的自动修复不在本次范围内，冲突时会报错，
而不是猜测并删除其他进程的状态

## 可复现验证

常规回归与竞态检查无需网络管理权限：

```sh
CGO_ENABLED=0 SKIP_CONCURRENT_TEST=1 SKIP_INTEROP_TEST=1 go test ./...
CGO_ENABLED=0 SKIP_CONCURRENT_TEST=1 SKIP_INTEROP_TEST=1 go test -tags with_gvisor ./...
go test -race ./listener/tproxy ./config ./hub/executor
```

上面的全量命令与现有发布 CI 一致，跳过单独的高并发与外部互操作测试；
它们不属于本次防火墙场景覆盖范围

真实内核测试对原生 nftables 和 iptables-legacy 使用同一组 TCP/UDP、DNS、
LAN/WAN、默认 lo、网关 NAT、mark、重载和清理场景
只能在可丢弃的 Linux 网络命名空间中运行，
需 nftables、iptables（含 legacy）、iproute2、procps：

```sh
go test -c -o /tmp/tproxy.test ./listener/tproxy
for backend in NFT IPTables; do
  sudo env MIHOMO_TEST_FIREWALL=1 unshare --net /tmp/tproxy.test -test.run "^Test${backend}Kernel$" -test.v
done
```

跨平台时使用 `GOOS=linux GOARCH=<测试容器架构> CGO_ENABLED=0` 编译，
在 `--network none --cap-add NET_ADMIN` 的临时容器内执行
发布工作流的 Linux 测试任务也会在独立网络命名空间中运行这两套内核测试

Firewall4 使用真实 nft 规则模拟正常 LAN 放行/WAN 拒绝，以及仅重建 inet fw4
表的重载流程；不声称已经在反馈用户的 OpenWrt 固件上实测

2026-09-14 本地验证：默认与 `with_gvisor` 全量回归通过，相关包竞态检查通过；
在 LinuxKit 7.0.12、nftables 1.0.6、iptables-legacy 1.8.9 的独立容器中，
两后端各 11 项真实流量场景通过（共 22 项），并检查清理后保留系统表且无残留代理规则

依据：[Linux TPROXY](https://docs.kernel.org/networking/tproxy.html)、
[nftables 手册](https://netfilter.org/projects/nftables/manpage.html)、
[Firewall4 启停脚本](https://github.com/openwrt/firewall4/blob/master/root/sbin/fw4)、
[Firewall4 ruleset 模板](https://github.com/openwrt/firewall4/blob/master/root/usr/share/firewall4/templates/ruleset.uc)
