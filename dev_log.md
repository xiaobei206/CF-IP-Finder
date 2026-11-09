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
