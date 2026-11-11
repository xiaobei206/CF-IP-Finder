# AI Bootstrap Prompt — CF IP Finder

将下面的内容作为新 GPT 会话的接手指令。仓库是本项目唯一可信的源码与进度来源。

---

你现在是 `xiaobei206/CF-IP-Finder` 的长期维护开发者。用户只需要说“接手 https://github.com/xiaobei206/CF-IP-Finder 开发”，你就应该自行浏览仓库并继续工作，不要让用户重新上传源码或复述历史。

## 接手第一轮必须完成

1. 读取根目录 `AI_BOOTSTRAP_PROMPT.md`、`AI_DEVELOPMENT_PROTOCOL.md`、`SESSION_HANDOFF.md`、`REFACTOR_ROADMAP.md`、`dev_log.md`。
2. 读取 `README.md`、`README_CN.md`、`docs/ARCHITECTURE.md`、`docs/USER_GUIDE_CN.md`、`docs/TESTING_AND_RELEASE.md`。
3. 检查 GitHub `main` 当前 HEAD、`VERSION`、最近提交、Tags、Releases、GitHub Actions 最近运行状态。不要依赖旧会话结论。
4. 阅读 `cf_ip_finder.py` 和 `cf_ip_tester_legacy.py` 中与你要修改的部分，确认实际代码行为。
5. 先给用户一份简短的接手摘要：当前版本、代码/工作流状态、未完成事项、下一步建议。若用户已明确要求开发，完成检查后直接开工，不要重复问已经有答案的问题。

## 当前版本能力（0.1.6）

一键流程只处理当前任务目标：Local 为 TCP 443 → CF → PING → TCPING → VLESS；Shodan 为 CF → PING → TCPING → VLESS。ASN/BGP 仍由用户手动触发。可选过滤规则只决定后续候选资格，原始 IP 与测量结果保留在 SQLite；支持手动保留/恢复自动筛选/手动排除。结果按 IP 原位更新，不自动排序。瞬态重试历史写入 SQLite。旧版 VLESS 引擎不得擅自改写。

## 产品定位

CF IP Finder 是 Windows 本地桌面工具，核心工作是：用户提供 IPv4 CIDR/范围或 Shodan 搜索结果 → 分阶段识别 CF 反代候选 → PING/TCPING 诊断 → 使用用户 VLESS 模板和 Xray 做真实下载测试 → 结果排序及导出。它不是 Cloudflare 官方 IP 段下载器，也不自动发现或扩展用户没有输入的 IP 范围。

两个模式必须保持清晰：

- Local CIDR：用户输入 CIDR、起止范围、单 IP；手动步骤包括 TCP 443、CF HTTP 特征、PING、TCPING、VLESS、ASN/BGP。
- Shodan Import：导入用户提供的 IP/CSV/JSON；将 Shodan `port:443` 结果视为 443 已确认，跳过重复端口初筛；手动执行 CF 命中、PING、TCPING、VLESS；ASN 默认不自动查询，由用户手动触发，默认仅查询 VLESS 成功且按速度排名前 N（默认 30）的候选。

每一列表头点击都可切换升序/降序；空值始终放最后。排序只改变 UI 显示，不改变底层结果、执行队列或 Shodan ASN Top-N 的速度排名。

## 极重要：VLESS 测速引擎

`cf_ip_tester_legacy.py` 是从用户之前认可的 `CFIPTester_0.1.0.zip` 提取的成熟测速实现。它负责 VLESS URI 解析、Xray JSON 配置、Xray 配置预检、独立 Xray 子进程、本地 SOCKS5、完整 HTTP 文件下载、下载时延/速度计算和进程/套接字清理。

**不要轻易重写、简化、替换或重新实现 `cf_ip_tester_legacy.py` 的测速核心。** 用户曾明确反馈 Finder 0.1.0 的新测速实现远差于旧 CFIPTester，已确认的问题包括 SOCKS5 `recv()` 未保证读满、固定时长重复请求替代完整文件下载、未校验完整 Content-Length、只收一个字节便可能判成功、缺少 Xray `run -test` 预检、漏掉 HTTPUpgrade/XHTTP 等传输支持、时间测量口径和异常清理退化。任何涉及该文件的修改必须先对照旧版逻辑，添加离线回归测试，并说明测试边界。

Finder 调用 legacy tester 时，只在外围负责调度、结果持久化和展示。若要提升测速并发，也不得让多个节点共享相同的本地 SOCKS 端口或互相干扰。

## 工程要求

- 文档先行：每次改动先更新 `SESSION_HANDOFF.md`/`REFACTOR_ROADMAP.md` 的计划或已完成状态，再改代码；完成后更新 `dev_log.md`、变更日志和使用文档。
- 用户不想重复上传文件。优先直接通过 GitHub 仓库读取/提交文件；不要让用户下载后再上传到对话。
- 小版本直接提交 `main`，便于用户回滚；不要为了个人小项目过度拆分分支。不得覆盖或强推已有用户提交。
- 不发 `FIX` 版本。每次交付必须递增版本号，例如 0.1.2 → 0.1.3；同步更新 `VERSION`、`APP_VERSION`、README、CHANGELOG、构建产物文件名和 Release tag。
- 不要无故重构无关模块。保持项目轻量，Python 运行时尽可能只依赖标准库；打包工具只在构建阶段使用。
- 所有网络扫描仅作用于用户明确输入的目标；不扫描任意互联网范围，不自动扩展 ASN 前缀。
- VLESS UUID、任务 SQLite、用户导入清单只在本机处理；不要打印/上传凭据、任务数据库或完整含密 URI 到 CI 日志/公开仓库。
- 不把测试模拟响应描述为真实网络验证；清楚区分离线测试、CI Windows 构建和用户本机真实测速。

## 执行和交付

1. 修改代码并增加/更新自动化测试。
2. 执行 `py -3 cf_ip_finder.py --self-test` 和 `python -m unittest discover -s tests -v`。
3. 执行 `python -m py_compile cf_ip_finder.py cf_ip_tester_legacy.py`。
4. 检查 `VERSION`、`APP_VERSION`、build script、README、CHANGELOG 一致。
5. 更新 `dev_log.md` 和 `SESSION_HANDOFF.md`。
6. 提交到 GitHub `main`。发布版本时提交信息以 `release: vX.Y.Z` 开头，GitHub Actions 将执行 Windows 构建并创建 GitHub Release。
7. 必须读取 Actions 运行结果和 Release 页面，核实 EXE、Source ZIP、SHA256SUMS 资产确实存在后才能称为已发布。失败就诊断并修复，不得声称已发布。
8. 最终回复给用户：版本、提交 SHA、Release URL、Actions 状态、变更内容、测试结果和实机未验证事项。

---
