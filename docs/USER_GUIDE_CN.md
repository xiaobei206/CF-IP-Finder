# 用户操作指南（详细版）

## 1. 启动和首次设置

1. 使用 Windows 10/11。
2. 下载 Release EXE，或者安装 Python 3.10+（安装包需包含 Tcl/Tk）并解压源码。
3. 源码模式双击 `run.bat`。
4. 需要 VLESS 实测时，在 Xray-core 一栏点击“下载 Xray”或“选择”已有 `xray.exe`。
5. 粘贴自己的 VLESS URI 模板。程序只替换服务器地址，保留原端口、UUID、TLS SNI、WebSocket Host/Path、transport 等已有参数。

## 2. 本地网段模式

在顶部选择“本地网段模式”，每行粘贴一个目标：

```text
65.49.236.0/22
23.106.148.0/22
65.49.236.30-65.49.236.80
65.49.237.84
```

创建任务只建立数据和检查点，不会自动开始。依次点击阶段按钮：

- 扫描 443：TCP 连接探测。并发和连接超时在设置区调整。
- 查 CF 命中：发出明文 HTTP 请求到目标 443，观察 `400`、`Server`、`CF-RAY`、正文内容等。命中后可补充 TLS/Trace 信息。
- PING：ICMP 测试，次数/每次超时/并发均可调。
- TCPING：重复 TCP 443 connect，次数/超时/并发可调。
- VLESS 测速：填写测速 URL，执行完整文件下载；默认下载 URL 为 `http://speedtest.tyo11.jp.leaseweb.net/10mb.bin`。
- 查询 ASN：查 BGP 前缀、起源 ASN、组织 holder 和 RDNS。

## 3. Shodan 导入模式

1. 切换 Shodan 导入模式。
2. 粘贴 IP 清单，或导入 Shodan CSV。软件从文本中提取 IPv4 地址并去重。
3. 创建任务时假设 Shodan 查询已筛选 `port:443`，因此不会再跑 TCP 443 初筛。
4. 点击“查 CF 命中”，然后按需点击 PING、TCPING、VLESS 测速。
5. 最后点击 ASN 按钮。默认 N=30，只选择 VLESS 下载成功的速度前 30 名；可在 `Shodan ASN 前 N` 设置修改。

未命中项会从后续候选视图/阶段中排除，但仍保留为原始导入记录。它们不会因“过滤”而从数据库彻底删除。

## 4. 如何看 CF 命中

- TCP 443 开放不代表 CF。
- 明文 HTTP 请求发送到 HTTPS 端口时返回 `400 The plain HTTP request was sent to HTTPS port`，与 `Server: cloudflare`、有效 CF-RAY 或正文特征组合时可形成候选证据。
- 单独的 `Server: cloudflare` 响应头可被伪造，不能当作绝对证据。
- TLS 探测和 `/cdn-cgi/trace` 是补充信息；如果 HTTP 命中已经成立，TLS 错误不应自动抹掉 HTTP 候选。
- 最终要用自己的 VLESS 模板下载测试。真实下载成功才说明当前配置和网络路径可用。

## 5. PING 与 TCPING 候选漏斗（0.1.4）

两种模式共用同一套筛选逻辑。CF 命中 IP 全部进入 PING；PING 完成后，程序按平均延迟从低到高筛选进入 TCPING 的队列；TCPING 完成后，再按 TCP 443 connect 平均耗时从低到高筛选进入 VLESS 测速的队列。

- PING 前 N→TCPING：默认 500。填正数时取 PING 延迟最低的前 N；填 0 表示全部，包含 PING 无响应、超时或没有延迟值的 IP。
- TCPING 前 N→VLESS：默认 100。填正数时取 TCPING 延迟最低的前 N；填 0 表示全部，包含 TCPING 失败、连接超时或没有延迟值的 IP。
- 正数 N 的筛选按有效延迟升序，延迟缺失的候选放在后面；有效候选不足 N 时，会用延迟缺失的候选补足。
- TCPING 默认重复测试 5 次。相同平均耗时时，以成功率和最大耗时作为次级排序参考。
- 两个候选队列会保存为任务数据库记录和 stages/05_ping_selected.txt、stages/06_tcping_selected.txt。暂停、退出后恢复不会按最新表格排序或新填写的 N 偷偷改变已开始的队列。
- 若某个 TCPING/VLESS 阶段已经完成，再次点击执行会询问是否按当前 N 重新筛选；确认后生成新队列，之前已完成的单 IP 结果保留。
- VLESS 候选严格来自实际进入 TCPING 的那一批 IP；填 0 是这些 TCPING 候选全部（失败/无响应也包括），不会重新扩展到未入选的 CF IP。对于 0.1.2 旧任务，没有保存候选快照时会用已写入 TCPING 结果的 CF IP 兼容恢复。\n- VLESS 速度仍完全按旧版引擎下载文件的实际 MB/s 排名，不混入 PING/TCPING 延迟。

## 6. PING 与 TCPING

- PING 是系统 `ping`，只测试 ICMP 回应；超时或 100% 丢包可能是目标禁 ICMP，不意味着 HTTPS/VLESS 不通。
- TCPING 是重复 TCP connect 到目标 443，统计平均/最小/最大耗时与成功率。
- PING/TCPING 排序可以作为筛选参考，但测速结束后最终优选应看 VLESS 下载速度。

## 7. 表格多选、右键诊断与排序（0.1.5）

点击任意列标题切换升序/降序。当前排序图标会显示方向。数字字段按数字排序，而不是字符串排序；未检测、超时、错误或空值放最后。

阶段的默认排序：CF 命中优先、PING/TCPING 延迟由低到高、VLESS 速度由高到低。手动切换表格排序不会更改数据库内速度，也不会改变 Shodan ASN Top-N 的选取结果。

按住 Ctrl 可多选不连续行，按住 Shift 可选择连续行。右键时：

- 右键已经选中的行：保留当前整个选中组，不会把多选意外清掉。
- 右键未选中的行：选择切换为这一行。
- 右键空白区域：不会打开 IP 操作菜单。

菜单可以对选中的 IP 单独执行 **PING、TCPING、VLESS 下载测速、ASN/BGP 查询**，并可复制或导出选中 IP。手动诊断直接执行准确的选择清单，不受全局 Top-N 候选漏斗影响；结果会逐 IP 写回同一任务数据库，但不会改变全局阶段的完成状态或候选快照。即使某个 IP 没被 Top-N 选中，也可以通过右键直接补测。VLESS 依然使用旧版完整文件下载引擎。

手动 VLESS 测速会先确认一次，因为它可能产生明显网络流量；运行中不能同时启动另一个阶段，暂停/停止按钮仍对本次手动任务有效。

双击 IP 仍可将当前选择的一个或多个 IP 复制到剪贴板，菜单里的“复制选中 IP”也支持多选；“导出选中 IP”可保存为纯文本列表。

## 8. 导出

使用“导出全部结果”输出完整结果文件（CSV/JSON/纯 IP/VLESS 等，以对话框选项为准）；使用“导出 CF 命中 IP”只导出候选地址。导出前可调整表格排序或筛选显示，但需注意各导出类型可能按自身定义的字段排序；以导出文件内容为准。

## 9. 断点恢复

任务数据保存到 `%LOCALAPPDATA%\\CF-IP-Finder\\tasks\\`。关闭后重新启动，使用“恢复上次任务”载入最近任务。SQLite 保存每条 IP 每个阶段的结果；已完成的数据无需全部重跑，当前中断的条目可能会重新处理。

不要手工编辑 `checkpoint.db`。复制任务目录前先退出程序或使用“打开任务目录”后复制整个目录。

## 10. 故障排查

- **窗口无法启动**：检查 Python 是否包含 tkinter；运行源码时可从命令行执行 `py -3 cf_ip_finder.py` 查看错误。
- **PING 全部超时**：确认本机 `ping` 命令存在；目标可能禁 ICMP。仍可继续 TCPING/VLESS。
- **TCP 443 开放但 CF 未命中**：目标可能不是 CF、服务器返回不同内容，或 HTTP 请求被拒绝。查看日志和原始响应摘要。
- **VLESS 全部失败**：先确认 Xray 路径有效、VLESS URI 未截断、SNI/Host/Path 正确、Xray 配置检查通过；使用旧版 CFIPTester 对照。避免在公开日志中贴出含 UUID 的完整 URI。
- **下载速度异常**：用同一测速 URL、同一文件、单节点测速并发 1；确认文件可完整下载、服务器可用且没有其他流量干扰。
- **ASN 无结果**：检查是否点击手动 ASN 按钮、本机能访问 RIPEstat；ASN 数据服务异常不影响之前的扫描/测速数据。

## 11. 隐私

任务目录可能含真实 IP 清单、响应信息和 VLESS UUID。只向可信对象分享去敏后的 CSV；不要上传 `checkpoint.db`、`task_config.json` 或真实 VLESS URI 到公开 GitHub Issue。
