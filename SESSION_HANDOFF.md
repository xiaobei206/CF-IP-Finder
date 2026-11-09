# Session Handoff — CF IP Finder

**当前仓库版本：0.1.4（已发布）**  
**当前主分支：`main`**  
**当前开发基线：0.1.4 两级候选漏斗边界修正**

## 1. 当前实现摘要

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
- v0.1.2、v0.1.3、v0.1.4 均已由 GitHub Actions 成功完成 Windows EXE 构建和 Release；当前最新版本为 0.1.4。

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

## 7. 下一版本计划 — 0.1.5 选中 IP 右键诊断

本轮目标是在结果表增加真正支持 Ctrl/Shift 多选的上下文菜单，为当前选中的 IP 直接执行 PING、TCPING、VLESS 完整文件测速或 ASN/BGP 查询，并支持复制/导出所选 IP。

关键边界：
- 右键位于已选行时保留整个选择组；右键未选行时切换为该行单选；空白区域不弹出行操作菜单。
- 手动诊断只对明确选中的 IP 执行，不受全局 Top-N 队列限制；结果逐 IP 写回既有 SQLite 字段。
- 手动诊断不得更改全局 stages 状态、active_stage、stage_selections / stage_candidates 或候选快照文件。
- 定期刷新结果表时按 IP 稳定 iid 恢复选择，避免刷新后多选丢失。
- VLESS 必须继续调用 cf_ip_tester_legacy.py 原有的配置预检和完整文件下载实现，不复制、不重写旧引擎。
- 全局阶段与手动诊断互斥，保留现有暂停/停止交互。
