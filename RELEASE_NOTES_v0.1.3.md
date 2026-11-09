# CF IP Finder v0.1.3

## 候选漏斗与队列恢复

- PING 对全部 CF 命中 IP 执行，PING 无响应不会被提前淘汰。
- 新增 PING 前 N→TCPING（默认 500）与 TCPING 前 N→VLESS（默认 100）。
- 两个筛选值都支持 **0=全部**：包括 PING 无响应和 TCPING 失败/无响应的候选。
- 正数 N 按相应阶段的平均延迟升序筛选；缺失延迟排在后面。
- SQLite 固定保存两级候选快照，任务目录同时保存 05_ping_selected.txt 与 06_tcping_selected.txt。
- 暂停、停止、程序关闭或重启后恢复，均沿用原队列；已完成阶段只有在用户再次点击并确认后才重新筛选。
- 旧版 CFIPTester VLESS 完整文件下载引擎保持不变，未修改 cf_ip_tester_legacy.py。

## 测试说明

GitHub Actions 将执行 Ubuntu 与 Windows 的编译、自检、单元测试和版本一致性检查，并在 Windows runner 上构建 EXE。CI 不代替用户真实 ISP/VLESS 节点的实机下载验证。
