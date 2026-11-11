# Development Log — CF IP Finder

本文件为累积日志，只追加，不覆盖历史记录。详细版本说明见 `CHANGELOG_CN.md`。

## 2026-11-09 — 0.1.2

- 建立 Local CIDR 与 Shodan Import 双模式。
- 两种模式采用统一的手动分阶段工作台，不自动将所有步骤串行跑到底。
- Shodan 导入后将 TCP 443 标记为外部已确认，跳过本地端口重扫。
- CF 未命中记录留在本地任务库中，但不进入后续 PING/TCPING/VLESS/ASN 候选。
- 增加独立 PING、TCPING 阶段和测量字段。
- 表格各列支持点击升序/降序，空值置后；默认阶段排序符合用户期望。
- Shodan ASN 手动触发，默认按 VLESS 成功速度选择前 30 名；不受 UI 排序影响。
- 继续复用从 CFIPTester 0.1.0 提取的 legacy VLESS/Xray/SOCKS5 完整文件下载测速实现。
- 离线 `py_compile` 与 `--self-test` 通过。真实 Windows/Xray 网络测试仍需用户实机验证。

## 2026-11-04 — 0.1.1

- 从历史文件库恢复 `CFIPTester_0.1.0.zip` 中的 legacy VLESS 下载测试核心。
- 替换 Finder 0.1.0 的固定时长循环下载实现。
- 增加独立 CF 命中 IP 和 CF-400 命中 IP 导出入口。

## 2026-11-03 — 0.1.0

- 首版实现 IPv4 CIDR/范围/单 IP 解析、并发 TCP 443、Shodan 风格明文 HTTP 400/CF 头特征、TLS/Trace、SQLite WAL 检查点、VLESS/Xray 测速和 CSV/TXT/JSON 导出。
- 后续用户反馈测速体验退化；问题根因和修复方向在 `SESSION_HANDOFF.md` 与 AI protocol 中保留，避免重复犯错。

## Initial repository onboarding

- 将 0.1.2 完整源码与交接文档导入 `xiaobei206/CF-IP-Finder`。
- 初始化 GitHub Actions：Linux/Windows 离线自检，Windows PyInstaller 构建与 tag/release 流程。


## 2026-11-10 — v0.1.3 两级候选漏斗
- 在 Local CIDR 与 Shodan Import 共同加入 PING→TCPING→VLESS 三级漏斗。
- PING 前 N 默认 500、TCPING 前 N 默认 100；两个字段的 0 均代表全部，包含对应阶段没有延迟/失败的 IP。
- 候选排序仅用各自源阶段的统计指标：PING 平均延迟升序；TCPING 平均 connect 延迟升序，成功率与最大延迟只用作并列参考；不把前两阶段数值混入 VLESS 下载排名。
- 新增 stage_selections / stage_candidates 表和 05_ping_selected.txt / 06_tcping_selected.txt。数据库是权威快照；暂停/恢复始终沿用已保存的候选集合。完成后再次点击阶段并确认才重算队列。
- 没有修改 cf_ip_tester_legacy.py；VLESS 实测仍由历史 CFIPTester 完整文件下载引擎完成。
- 新增 8 项漏斗单元测试；等待 GitHub Actions 对 Windows/Ubuntu 执行编译、自检、单元测试并打包 Windows EXE。


## 2026-11-10 — v0.1.4 队列边界修正
- 发布后代码审阅发现：当第一级 PING Top-N 小于 CF 命中数量时，speed 队列曾以所有 CF candidates 作为查询基础。N=0 可能把没有进入 TCPING 的 IP 也送入 VLESS，超出了“全部 TCPING 候选”的语义。
- 修正为优先以持久化的 `stage_candidates(target_stage='tcping')` 作为 VLESS 的唯一来源，0=全部包含这个 cohort 中 TCPING 失败/无响应项，但不会扩张到未入选 CF IP。
- 对 0.1.2 任务增加兼容：旧任务无 TCPING selection snapshot，回退到已写入 `tcping_status` 的 CF 候选作为已测 TCPING 集合。
- 新增两个回归测试：VLESS 0=全部仍限于真实 TCPING cohort；旧数据库无 snapshot 可以恢复。
- `cf_ip_tester_legacy.py` 未修改。


## 2026-11-10 — v0.1.5 选中 IP 右键诊断

- 结果表使用 extended selection，支持 Ctrl/Shift 多选，并加入右键菜单的 PING、TCPING、VLESS、ASN/BGP 操作。
- 右键已选行保持多选；右键未选行改为单选；右键空白区域不触发行操作。
- 新增 ManualSelectionRunner：仅处理调用时明确传入的 IP 列表，结果逐 IP 保存，但不更改 stages、active_stage、stage_selections / stage_candidates 或全局阶段快照。
- 表格以 IP 作为稳定 iid，刷新后恢复可见选中项；复制和导出都支持当前多选 IP。
- VLESS 手动测试仍调用 legacy_tester.parse_vless_link、validate_xray_config 和 test_one_ip，保持旧版配置预检及完整文件下载流程。
- 新增 tests/test_manual_selection.py，验证直接选集与全局 Top-N 队列独立、ASN 不受 Shodan 默认 Top-N 限制，以及 VLESS 调用旧引擎。
- 代码改动提交 8a5502376968af2ff9978aff2a19913e13f931fb 已通过 Windows/Ubuntu 离线编译、自检和单元测试；正式 Release 的 Windows 构建与资产由本次版本提交工作流验证。

- Release 验证完成：v0.1.5 由 Actions run 42659741800 成功构建和发布；Ubuntu/Windows 离线验证、Windows EXE 打包、源码 ZIP、SHA256SUMS 与 GitHub Release 发布均成功。Release：https://github.com/xiaobei206/CF-IP-Finder/releases/tag/v0.1.5。用户本机真实网络/VLESS 性能仍未由 CI 覆盖。


## 2026-11-11 — 0.1.6 一键挑选与自动过滤

- 增加本地与 Shodan 两种显式一键挑选流程；Shodan 跳过已确认 443，本地执行 TCP 443；ASN/BGP 不纳入一键流程。
- 新增可选剔除条件和结果视图，保留 SQLite 原始 IP 与阶段测量数据；支持单 IP 手动保留/恢复筛选/手动排除。
- 阶段执行新增瞬态错误重试与持久化 attempt history；VLESS 结果记录测试参数元数据。
- 结果表按稳定 IP 行原位更新；不因阶段进度自动排序。
- 增加自动流程暂停/停止后的整条流程恢复逻辑。
- 保持 legacy VLESS 下载引擎文件不变。


## 2026-11-11 — v0.1.6 发布结果

- Release workflow run 43008149682 成功：Ubuntu 与 Windows 离线验证通过，Windows PyInstaller one-file 构建通过，源码 ZIP、SHA256SUMS 和 GitHub Release 发布通过。
- 正式 Release：https://github.com/xiaobei206/CF-IP-Finder/releases/tag/v0.1.6。
- Windows EXE SHA256：6de1a1ad63988cd5db8ca050d4c4feeb449d161a9bc004531694bded8a947456。
- Source ZIP SHA256：55062f8e3f62f10d4ef223b98feb2bb5426b8fba419695dae44758b39074cce6。
- legacy VLESS 引擎文件 SHA 与 v0.1.5 完全相同；未修改旧测速实现。
- 仍需用户在 Windows 实机上用真实 VLESS 模板、Xray 和当前网络进行最终连通性/速度验证。


## 2026-11-11 — v0.1.7 Tkinter 启动修复

- 用户实机反馈 v0.1.6 启动时报 Tkinter geometry manager 冲突：同一 stages LabelFrame 先 pack 一键按钮，再 grid 阶段 cell。
- 将 stages 内部布局拆成 auto_row 与 stage_grid 两个子容器，分别使用 pack / grid，避免一个父容器混用布局管理器。
- 增加 Windows Tk 窗口初始化冒烟测试。
- 明确发布文件由 PyInstaller --onefile --windowed 构建，为单文件便携应用，不是安装器。
