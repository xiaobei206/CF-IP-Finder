# Session Handoff — CF IP Finder

**当前仓库版本：0.1.7（发布验证中/以 GitHub Release 状态为准）**  
**当前主分支：`main`**  
**当前开发基线：v0.1.7 Tkinter 启动布局修复**

## 1. 当前实现摘要

### v0.1.6 新增行为

- 一键挑选必须由用户明确点击。本地流程：TCP 443 → CF → PING → TCPING → VLESS；Shodan 流程：CF → PING → TCPING → VLESS。ASN/BGP 仍手动。
- 不使用 Shodan API、不扩展目标 CIDR/IP；一键流程只使用当前任务中已有目标。
- 五项可选过滤：443 未开放、CF 未命中、PING 丢包、TCPING 成功率不足、VLESS 失败。过滤只影响后续候选资格，原始 IP 与检测结果保留在 SQLite。
- 结果视图：全部 / 可用候选 / 已过滤；右键支持手动保留、恢复自动筛选、手动排除。
- 瞬态失败默认重试一次，最多可配置 3 次；尝试写入 SQLite attempt_history。VLESS 测试参数元数据加入完整 CSV。
- 结果按 IP 原位更新，阶段完成和进度刷新不会自动重排；排序只由表头点击触发。
- 继续保持 cf_ip_tester_legacy.py 不变。


CF IP Finder 是 Windows Tkinter 应用，Python 3.10+，运行时仅使用标准库。主程序 `cf_ip_finder.py`，旧版 VLESS 引擎 `cf_ip_tester_legacy.py`。

### 本地网段模式

- 输入多行 CIDR、起止地址、单 IP；IPv4 解析和去重。
- 手动阶段：TCP 443 → 明文 HTTP / CF 特征 → PING → TCPING → VLESS 实际下载 → ASN/BGP。
- 每个阶段有独立入口；创建任务不自动运行完整流程。

### Shodan 导入模式

- 支持粘贴 IP/CSV/JSON 文本或导入 CSV 文件。
- 解析并去重 IPv4；导入时标记 `port_status=open`、`port_source=Shodan 导入确认 443`，跳过重复 443 初筛。
- CF 未命中 IP 不参与 Ping/TCPing/VLESS，但仍留在任务数据库原始记录中。
- Shodan ASN 手动启动，默认只查 VLESS 成功并按速度排名前 N（默认 30）的 IP。

### 候选漏斗（0.1.3）

- PING 对全部 CF 命中 IP 执行，不因 ICMP 无响应删除候选。
- ping_top_n 默认 500，0 表示全部（含 PING 无响应）；正数按 PING 延迟升序取前 N。
- tcping_top_n 默认 100，0 表示全部（含 TCPING 失败/无响应）；正数按 TCP connect 平均延迟升序取前 N，成功率/最大耗时作并列次序参考。
- TCPING 和 VLESS 的队列分别固定存入 SQLite stage_selections / stage_candidates，并写入 05_ping_selected.txt、06_tcping_selected.txt。运行中断后恢复不重新计算；阶段已完成后再次点击并确认才会重新生成快照。
- VLESS 阶段仍调用 cf_ip_tester_legacy.py，速度排名与 Ping/TCPing 完全分离。

### 排序和导出

- 表格任意列表头点击切换升序/降序，空值始终最后。
- 阶段完成时设置有用的默认排序：CF 候选优先、PING/TCPING 延迟升序、VLESS 速度降序。
- 导出完整 CSV、纯 IP、按测速 IP 替换的 VLESS URI、CF 候选 IP。

### 持久化

- SQLite WAL + `synchronous=FULL`，单条结果提交。
- `stages/` 里按阶段写 JSONL，使用临时文件及原子替换。
- 默认数据目录 Windows `%LOCALAPPDATA%\\CF-IP-Finder\\tasks\\`；非 Windows 为 `~/.cf-ip-finder/tasks/`。
- 0.1.0/0.1.1 任务表字段有安全迁移逻辑。

## 2. VLESS 测速重要背景

`cf_ip_tester_legacy.py` 来自用户之前满意的 `CFIPTester_0.1.0.zip`。Finder 0.1.0 曾重写测速并出现严重退化：SOCKS5 固定长度读取不完整、固定时长循环请求、缺少下载完整性验证、Xray config 预检缺失、漏支持 HTTPUpgrade/XHTTP、异常资源清理弱等。0.1.1 起恢复复用 legacy tester，0.1.2 继续保持。

任何接手者不要再另写一套 VLESS 下载测速实现。先完整阅读 `cf_ip_tester_legacy.py` 并按 protocol 要求回归测试。

## 3. 本次导入仓库时确认的离线检查

在 0.1.2 源码包上已运行：

```text
python -m py_compile cf_ip_finder.py cf_ip_tester_legacy.py
python cf_ip_finder.py --self-test
```

自检输出：

```text
Self-test passed: CIDR/Shodan import, stage checkpoints, Ping/TCPing schema, ASN top-N ordering, exports, legacy VLESS template, and manual stage runner.
```

这只表示离线逻辑自检通过，不代表 Windows GUI 实机、Xray 真实代理下载或用户 ISP 线路已验证。

## 4. 当前已知限制

- 当前只支持 IPv4；Shodan JSON/CSV 是通过文本中的 IPv4 提取，不是完整 Shodan API 客户端。
- Shodan 模式基于用户导入结果，不查询 Shodan，不自动扩大扫描范围。
- CF-400 / `Server: cloudflare` 是候选特征，不能独立证明目标一定是可用的 CF 反代。
- PING 结果受 ICMP 策略影响，只作诊断。
- TCPING 只测 TCP connect，不代表代理性能。
- ASN/BGP 是 RIPEstat 公共路由观测，不等于当前 ISP 的真实路径或精品线路类型。
- VLESS 真实测速需要外部 `xray.exe` 和有效模板；不同 transport/security 的支持继承自 legacy tester。
- v0.1.2、v0.1.3、v0.1.4 均已由 GitHub Actions 成功完成 Windows EXE 构建和 Release；0.1.5 已发布；Actions run 42659741800 的 Windows/Ubuntu 验证、Windows EXE 构建和 Release 发布全部成功，EXE、源码 ZIP 与 SHA256SUMS 已核实存在。

## 5. 下一步建议

按优先级：

1. 确认首次 GitHub Actions Windows 构建和 Release 资产均成功。
2. 让用户在 Windows 10/11 实机使用 0.1.4：导入真实 Shodan 样本，观察 CF 命中数量、PING/TCPING 排序、VLESS 下载、ASN 前 30 和断点恢复。
3. 根据真实反馈修复，不要预先大规模重构。
4. 补充独立单元测试，特别是 HTTP 响应解析、CF 命中判定、排序空值、SQLite 突然停止恢复、Shodan ASN Top-N。
5. 研究长任务 UI 响应和大量结果表格刷新性能；必要时批量 UI 刷新但保持数据库单 IP 持久化。
6. 检查 Windows onefile PyInstaller 下 `tkinter`、下载 Xray、临时目录和用户数据路径行为。

## 6. 新 GPT 接手动作

先读 `AI_BOOTSTRAP_PROMPT.md` 和 `AI_DEVELOPMENT_PROTOCOL.md`，再检查 `main`、`VERSION`、GitHub Releases 和 Actions；不要让用户再次提供源码 ZIP。仓库本身就是源代码。完成接手总结后按用户明确的目标直接继续。

## 7. v0.1.5 交付摘要

- 结果表启用 Ctrl/Shift 多选和右键上下文菜单，支持手动 PING、TCPING、VLESS 下载测速、ASN/BGP 查询。
- 手动诊断只执行选中 IP，逐 IP 更新数据库结果；不更改全局阶段状态、active_stage、候选队列及快照。
- 表格刷新/排序后按 IP 恢复可见选择；支持复制和导出所选 IP。
- VLESS 手动测试复用旧版 legacy tester；未改动 cf_ip_tester_legacy.py。
- 新增离线回归测试。请继续核实本轮 Release Action 的 Windows 构建、Release tag 与 EXE/Source ZIP/SHA256SUMS 资产；真实网络和用户 VLESS 链路仍需 Windows 实机测试。


## 6. v0.1.6 发布验证

- Release: https://github.com/xiaobei206/CF-IP-Finder/releases/tag/v0.1.6
- Release workflow run: 43008149682；Ubuntu / Windows 离线验证、Windows EXE 构建、源码 ZIP、SHA256SUMS 和 GitHub Release 均成功。
- Release tag v0.1.6 指向 commit 25af7cbd2796cd5edbb2a2222038d2a79d8739af；main HEAD 同一提交。
- Windows EXE SHA256: 6de1a1ad63988cd5db8ca050d4c4feeb449d161a9bc004531694bded8a947456。
- Source ZIP SHA256: 55062f8e3f62f10d4ef223b98feb2bb5426b8fba419695dae44758b39074cce6。
- cf_ip_tester_legacy.py blob SHA 保持 cccb85c79f679942d3b3beeb86434ea051fa7d65。
- CI 验证不等于用户网络环境的真实 CF/VLESS 节点实测；这部分仍需在用户 Windows 机器上测试。


## v0.1.7 修复说明

- 修复 Tkinter 启动异常：stages LabelFrame 的直接子控件不再混用 pack/grid，阶段网格移入独立 stage_grid 子容器。
- 发布仍为 PyInstaller one-file portable EXE，双击运行，不是安装程序。
- Windows Actions 增加 Tk 根窗口和 App 初始化冒烟测试。
