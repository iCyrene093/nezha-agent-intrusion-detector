# nezha-agent-intrusion-detector

用于在 Linux 服务器上检查哪吒探针 agent 端是否存在入侵痕迹，以及是否存在对外扫描、爆破、代理、DDoS、挖矿等网络攻击迹象。

## 快速使用

```bash
sudo bash nezha_agent_intrusion_detector.sh
```

脚本默认会把详细日志保存到：

```text
/var/log/nezha-agent-intrusion-detector/<hostname>-<timestamp>/
```

如果当前用户无法写入 `/var/log`，会自动回退到 `/tmp/nezha-agent-intrusion-detector/`。

也可以自定义输出目录：

```bash
sudo LOG_ROOT=/root/nezha-check bash nezha_agent_intrusion_detector.sh
```

如需完整保留 SSH `authorized_keys` 原文等敏感配置，可显式开启：

```bash
sudo FULL_SENSITIVE=1 bash nezha_agent_intrusion_detector.sh
```

默认情况下，脚本会对 `authorized_keys` 的 key body 和 comment 做脱敏摘要，降低报告外传时的敏感信息暴露风险。

## 依赖与降级行为

脚本依赖常见 Linux 基础命令，例如 `bash`、`find`、`ps`、`grep`、`awk`、`sed`、`wc`、`mount`、`df`、`date`、`hostname`。

以下命令为可选增强项，缺失时脚本会跳过对应采集并在摘要中显示 collection warning：

- `systemctl` / `journalctl`：systemd 服务和 journal 日志。
- `ss` 或 `netstat`：网络连接。
- `ip`：路由和地址。
- `iptables-save` / `iptables`、`nft`：防火墙规则。

## 检查内容

脚本只做只读采集和启发式分析，不会清理、删除或阻断任何进程/连接。主要检查：

- 哪吒 agent 相关进程、systemd 服务和疑似安装文件。
- 当前进程、近期可执行文件、临时目录可疑载荷。
- cron、systemd、shell profile、SSH authorized_keys 等持久化入口。
- `ss`/`netstat` 网络连接、连接数量、常见攻击端口连接、路由和防火墙规则。
- SSH 登录成功/失败、sudo、内核安全相关日志。
- 常见恶意程序、挖矿、扫描工具 IOC，例如 `xmrig`、`kinsing`、`kdevtmpfsi`、`masscan`、`zmap`、`sshpass` 等。

## 输出结果

运行结束后会在屏幕输出智能分析摘要，包括：

- 风险分数。
- Critical/High/Medium/Low 发现数量。
- 是否建议立即隔离主机。
- 每条发现的类别、原因和证据计数。
- 后续人工复核建议。

详细证据会保存在输出目录：

- `report.txt`：汇总报告和截断后的命令输出。
- `summary.txt`：屏幕分析摘要。
- `findings.tsv`：结构化发现列表。
- `raw/`：每条采集命令的完整原始输出。

## 注意事项

- 建议使用 root 运行，否则部分进程、网络连接、日志和 systemd 信息可能不可见。
- 报告和 raw 证据可能包含主机名、用户名、IP 地址、进程参数、shell 配置、cron/systemd 内容等敏感运维信息；请限制目录权限，不要直接公开上传。
- 默认会脱敏 `authorized_keys` 的密钥正文和注释；如需完整取证，请设置 `FULL_SENSITIVE=1` 并妥善保护输出目录。
- 启发式分析不能替代完整取证；高风险主机建议先隔离、保全镜像和日志，再进行清理或重装。
- 如果发现对外攻击迹象，请优先从云厂商安全组/防火墙限制出站流量，避免证据被破坏。
