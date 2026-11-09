# CF IP Finder 0.1.3 中文说明

## 项目定位

CF IP Finder 不是 Cloudflare 官方 IP 优选器，而是一个由用户提供扫描范围的 **IPv4 候选发现、CF 特征筛选、连通性诊断和 VLESS 实际下载测速工具**。本地网段模式适合从某家 IDC/ASN 的公告网段中寻找候选；Shodan 模式适合导入现成的 Shodan 搜索结果后快速筛选。

## 两种模式

### 本地网段模式

输入格式每行一个，支持：

```text
65.49.236.0/22
65.49.236.0-65.49.239.255
65.49.236.30
```

创建任务不会自动运行。按顺序手动执行：

1. **扫描 443**：TCP connect 探测端口。
2. **查 CF 命中**：对 TCP 443 发送明文 HTTP 请求，记录状态码、响应头、正文特征；命中后补充 TLS/Trace 诊断，但 TLS 失败不会覆盖 HTTP 命中。
3. **PING**：调用系统 ping，记录平均/最小/最大延迟和丢包率。
4. **TCPING**：重复建立 TCP 443 连接，记录平均/最小/最大连接耗时和成功率。
5. **VLESS 测速**：调用随包的旧版 CFIPTester 测速引擎，使用 Xray-core + 本地 SOCKS5 下载指定文件。
6. **查询 ASN/BGP**：查询命中候选的 ASN、路由前缀、注册组织、RDNS 等公开信息。

### Shodan 导入模式

可以粘贴 IP 清单，或导入 Shodan CSV。程序从文本/CSV/JSON 中提取 IPv4 并去重。由于 Shodan 查询已含 `port:443`，导入后把端口状态标为已确认，跳过本地 443 初筛。

手动执行：

1. **查 CF 命中**：仅检查导入 IP 的 CF 特征。
2. **PING**。
3. **TCPING**。
4. **VLESS 测速**。
5. **查询 ASN**：默认只查询 VLESS 成功节点按速度降序排列的前 30 个，可调整 N。

Shodan 未命中项不会参与后续阶段，但仍保留在 SQLite 原始记录中。ASN 默认不自动查询，只有点击 ASN 按钮时才访问 RIPEstat。

## 排序规则

点击任意表头即可排序，再次点击同一表头切换方向：

- 延迟、丢包率等数值字段可升序/降序。
- 下载速度可以升序/降序；阶段完成时默认速度降序。
- IP、ASN、组织、Server 等文本列支持文本排序。
- 空值/未检测/超时值放在有效数值之后，不会当作 0 混排。
- 排序只影响显示，不改变底层数据、阶段候选集和 ASN 前 N 的速度选择规则。

## 参数

- TCP 443/CF 扫描并发：默认 300，程序限制最高 800。
- PING/TCPING 并发：默认 100，程序限制最高 300。
- PING 次数/超时：可独立设置。
- TCPING 次数/超时：可独立设置。
- VLESS 不同 IP 的并发：默认 1，最高 8；建议 1，减少测速互相抢带宽。
- PING 前 N 进入 TCPING：默认 500；填 0 表示全部，包含 PING 无响应 IP。
- TCPING 前 N 进入 VLESS：默认 100；填 0 表示全部，包含 TCPING 失败/无响应 IP。
- ASN 前 N：Shodan 默认 30，范围 1–1000。
- 下载 URL 默认：`http://speedtest.tyo11.jp.leaseweb.net/10mb.bin`。

PING 失败不会淘汰 CF 命中 IP。完成 PING 后，按延迟升序生成 TCPING 队列；前 N 填 0 时全部进入，包括无响应 IP。TCPING 完成后按 connect 延迟升序生成 VLESS 队列；前 N 填 0 时全部进入，包括 TCPING 失败 IP。最终是否可用以 VLESS 代理能否成功下载为准。

## 安装和运行

- Windows 10/11。
- 源码运行：Python 3.10+，需安装带 tkinter 的发行版；运行时不依赖第三方 Python 包。
- 双击 `run.bat`，或在命令行执行 `py -3 cf_ip_finder.py`。
- 首次 VLESS 测速前，在界面中下载 Xray-core 或选择已有 `xray.exe`。
- 如需单文件 EXE，在 Windows 上运行 `build_exe.bat`。

## 数据文件与断点恢复

默认数据目录：`%LOCALAPPDATA%\\CF-IP-Finder\\tasks\\`。每个任务包含 SQLite WAL 数据库、任务配置、阶段 JSONL 文件及日志。数据库使用 WAL + FULL 同步；每条 IP 结果独立提交；阶段文件通过临时文件写入、fsync 和原子替换生成。打开软件时可继续最新任务。不要把真实任务目录提交到 Git，因为其中可能包含 VLESS UUID 和用户输入的 IP 清单。

## 本地自检

```powershell
py -3 cf_ip_finder.py --self-test
python -m unittest discover -s tests -v
```

这些是离线逻辑测试；没有替代真实网络扫描或真实节点测速。
