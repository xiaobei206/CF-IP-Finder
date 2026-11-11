# AI Development Protocol — CF IP Finder

本文件是所有 AI 开发会话的强制规则。若与旧聊天内容冲突，以本文件和仓库最新代码为准。

## 1. 工作原则

1. 仓库是唯一事实来源。不能假设上个 GPT 说“已经完成”的代码真的存在；必须读取文件和 Git 状态。
2. 先读文档、先看现有实现、先建立最小修复方案。禁止不看旧代码就重写功能。
3. 用户偏好可回滚、低成本、轻量化。个人项目默认直接推进 `main`，保持提交粒度清楚，不为形式引入复杂 branching。
4. 不要把未在真实环境验证的功能描述为“实测成功”。模拟测试、单元测试、CI 构建和用户实机测试必须分开说明。
5. 每次版本都要有可追溯的提交、变更记录和构建资产。不得用“FIX”“临时版”“覆盖原版”替代版本递增。

## 2. 版本纪律

- 当前版本由根目录 `VERSION` 定义。
- Python `APP_VERSION`、窗口标题/构建名称（若存在）、README、CHANGELOG、Release tag、Source ZIP 和 EXE 文件名必须一致。
- 版本遵循 `MAJOR.MINOR.PATCH`。普通修复/增量功能优先 PATCH 递增；用户明确要求的较大功能可递增 MINOR。
- 每次 release 都追加 `CHANGELOG_CN.md` 与 `dev_log.md`，不能覆盖历史日志。
- 发布提交信息必须为 `release: vX.Y.Z`，用于 `.github/workflows/ci-release.yml` 识别发布意图。
- 同一 tag 不允许复用或强制覆盖。若 release 流程失败，先检查 tag/release 状态，修复后递增新版本或安全地重跑对应 Action。

## 2.1 v0.1.6 功能边界补充

- 一键流程仅使用任务中现有 IP；不调用 Shodan API、不扩展 CIDR/IP，不自动查询 ASN/BGP。
- 一键流程必须明确点击启动，Local / Shodan 的 443 阶段差异以当前模式为准。
- 自动过滤不得删除 IP 或原始测量结果；未测试字段不是失败。规则变更后，相关候选快照按新规则重算，防止旧规则队列静默用于后续阶段。
- 手动保留/恢复/排除覆盖与手动选中 IP 诊断是独立概念；直接诊断不得污染全局阶段快照。
- 结果表以 IP 为稳定行标识，阶段期间更新字段不得自动重排；只有用户点击表头时排序。
- 瞬态网络错误可以自动重试，确定性连接拒绝不重试；每次尝试留在 SQLite。VLESS 实测继续复用 legacy tester，不得因新流程改写它。

## 3. 核心架构约束

### 3.1 主程序

`cf_ip_finder.py`：Tkinter UI、目标解析、TCP/HTTP/TLS/ICMP/TCP 探测、SQLite TaskStore、阶段调度、结果排序与导出、Xray 下载辅助。

### 3.2 旧版 VLESS 测速引擎

`cf_ip_tester_legacy.py`：VLESS URI 解析、Xray 配置生成和校验、Xray 子进程管理、本地 SOCKS5、HTTP 文件完整下载、速度计算和资源释放。

该模块是从用户验证过的 `CFIPTester_0.1.0.zip` 提取的历史成熟实现。非必要不得重写其算法、协议解析或下载时序。若修改，必须：

- 逐项对照原始 CFIPTester 0.1.0 的行为。
- 保留 WS、gRPC、TCP/raw、HTTPUpgrade、XHTTP 等已有支持（以代码实际支持为准）。
- 保证 SOCKS5 固定长度读取使用 `recv_exact` 或等价的完整读取逻辑。
- 校验 Xray 配置后才批量测速。
- 验证 HTTP 状态、完整下载字节/Content-Length（适用时）后才判定成功。
- 所有 socket、临时配置和 Xray 进程均需在 `finally` 清理。
- 避免单位变化；当前 `speed_mbps` 实际按十进制 MB/s 展示，改单位必须同步 UI、CSV、文档。

## 4. 模式和流程不得回退

### Local CIDR

输入每行一个 CIDR、IPv4 起止范围或单 IP。支持多个目标去重。阶段为：

`port → http/CF → ping → tcping → speed/VLESS → route/ASN`

UI 必须逐阶段手动触发，不可默默自动运行完整流程。每阶段可查看结果、暂停/停止，并通过 SQLite 检查点恢复。

### Shodan Import

输入用户导出的 IP/CSV/JSON 内容。导入的 IP 视为 Shodan 已确认 `port:443`，跳过本地 port 阶段。阶段为：

`http/CF → ping → tcping → speed/VLESS → route/ASN (manual)`

- 未命中 IP 不进入后续阶段，但原始行/记录保留。
- ASN 不自动执行。用户手动按 ASN 按钮时，默认选 VLESS 成功且按 `speed_mbps DESC, ttfb_ms ASC` 排名的前 N（默认 30）。
- 用户对 UI 表格改用 Ping/IP/ASN 列排序，不得改变该 Top-N 的选取依据。

## 5. 网络检测语义

- TCP 443 开放只代表 TCP 连接可建立。
- 普通 HTTP 明文请求发送到 443 的 400 页面可作为 Shodan 风格候选特征，但 `Server: cloudflare` 或单个头部不等于确定 CF 反代。
- CF 结果要保留原始状态码、响应头、正文摘要、CF-RAY 等证据；TLS/Trace 作为补充，不应粗暴覆盖独立 HTTP 命中结果。
- PING 依赖 ICMP；PING 超时不能淘汰候选。
- TCPING 是 TCP connect 诊断，不等于 TLS 或代理性能。
- 最终排名以真实 VLESS 下载测速为主。ASN/BGP/注册组织不能冒充用户当前 ISP 的实际路由线路类型。

## 6. 持久化和恢复

- SQLite 使用 WAL 和 `synchronous=FULL`，连接共享必须受锁保护。
- 单 IP 结果成功后及时提交，不可仅在整个阶段完成时保存。
- 阶段 JSONL 文件通过临时文件、flush/fsync、原子替换生成。
- 任务配置/检查点/日志/结果属于用户私有数据，不得进入 Git。
- 新增字段必须提供向后兼容数据库迁移，不要求用户删除旧任务。
- 恢复后跳过已完成记录；对中断中状态重新排队。不可把暂停/停止误记成整个阶段完成。

## 7. UI 和排序

- 所有主要阶段均需明确的独立按钮和状态；用户要能理解当前模式与当前阶段。
- 任意可见数据列支持点击表头切换升序/降序；空值始终在有效值之后。
- 默认排序：CF 命中优先；PING/TCPING 延迟低到高；VLESS 下载速度高到低。
- 手动排序只是显示层排序，不修改存储顺序、阶段队列或 ASN Top-N 选择。
- 新增设置要保存进任务 config，以便恢复时可解释此前任务使用的参数。

## 8. 测试要求

每次改动至少运行：

```powershell
py -3 -m py_compile cf_ip_finder.py cf_ip_tester_legacy.py
py -3 cf_ip_finder.py --self-test
py -3 -m unittest discover -s tests -v
```

测试尽量不依赖公网目标；对连接和下载逻辑使用 mock/local test server。涉及 Windows ping、Tkinter 或 PyInstaller 的改动，要通过 GitHub Actions Windows runner 验证。对 Xray 实际代理流量仍需标注“必须用户实机验证”。

## 9. Git 与交付

- 不覆盖用户未提交数据（仓库远端文件/提交）。每次写入前先 fetch 最新 HEAD。
- 不默认强推。若远端 HEAD 已变化，先合并/基于最新 HEAD 重新提交。
- README、AI 接手文档、架构说明、路线图、handoff、dev_log 都是源码的一部分，需随代码更新。
- 不把任务文件、数据库、VLESS URI、UUID、扫描结果等私密数据提交到仓库。
- Release 必须来自 GitHub Actions：Windows CI 测试 → PyInstaller EXE → Source ZIP → SHA256SUMS → GitHub Release。
- 只有在确认 Action 成功、Release tag/URL 和资产存在之后才能报告“已发布”。
