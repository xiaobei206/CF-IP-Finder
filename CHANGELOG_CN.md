# 更新日志

## 0.1.4 — 2026-11-10

- 修正 VLESS 候选集合边界：0=全部现在严格指向实际进入 TCPING 的队列成员（包含 TCPING 失败/无响应），不会把未进入 TCPING 的其他 CF 命中 IP 带入 VLESS。
- 对 0.1.2 历史任务提供兼容回退：没有保存过 TCPING 候选快照时，以已完成 TCPING 结果的 CF 候选作为历史 TCPING 集合。
- 增加队列边界和旧任务升级兼容回归测试；VLESS 旧版测速引擎仍保持原样。


## 0.1.3 — 2026-11-10

### 新增
- 在 Local CIDR 与 Shodan Import 两种模式中加入三级漏斗：CF 命中全部保留并 PING；PING 延迟升序筛选后执行 TCPING；TCPING connect 延迟升序筛选后执行 VLESS 完整文件下载测速。
- 新增 PING 前 N→TCPING（默认 500）与 TCPING 前 N→测速（默认 100）设置；填 0 表示全部，不过滤无响应/失败候选。
- 将两级候选队列持久化到 SQLite，并在任务目录生成 05_ping_selected.txt、06_tcping_selected.txt 快照；暂停、关闭和恢复均沿用既有队列。
- 对已完成的 TCPING/VLESS 阶段再次执行时，允许用户确认按当前 N 重新筛选；已有单 IP 检测结果不会被清除。
- 增加候选排名、0=全部、队列快照、断点恢复和旧任务数据库兼容测试。

### 保持不变
- VLESS 测速仍使用 cf_ip_tester_legacy.py 的原始完整文件下载实现；本版本未修改旧测速引擎。
- 不把 Ping/TCPing 延迟混入 VLESS 下载速度排名；VLESS 最终排序仍按真实下载速度。
- 不自动扩大用户授权范围，不调用 Shodan API，不自动查询 ASN。


## 0.1.2 — 2026-11-09

- 增加本地网段模式与 Shodan 导入模式。
- 统一为每阶段独立按钮，创建任务后不自动执行全部流程。
- Shodan 导入跳过重复 TCP 443 初筛；CF 未命中不进入后续步骤但保留原始记录。
- 增加 PING、TCPING 独立检测和结果字段。
- 表格每列支持升序/降序，空值始终排后。
- Shodan ASN 查询默认只选择 VLESS 成功速度前 30，可调整 N；本地模式可手动查询所有 CF 候选。
- 继续调用 CFIPTester 0.1.0 提取的旧版 VLESS/Xray/SOCKS5 完整文件下载测速引擎。
- SQLite 任务迁移、阶段检查点和导出逻辑保留。

## 0.1.1

- 恢复旧版 VLESS 完整文件下载测速引擎。
- 增加独立 CF 命中 IP 与 CF-400 命中 IP 导出。

## 0.1.0

- 首版：CIDR/范围解析、TCP 443 扫描、Shodan 风格明文 HTTP/CF 特征探测、TLS/Trace、SQLite 检查点、VLESS/Xray 测速和结果导出。
