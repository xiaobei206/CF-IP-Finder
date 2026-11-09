# CF IP Finder v0.1.4

## 队列边界修正

- VLESS 队列严格来自实际进入 TCPING 的候选集。
- 当 TCPING 前 N=0 时，包含这个 TCPING 候选集里的所有 IP，包括失败/无响应项；不会把未进入 TCPING 的其他 CF 命中 IP 带进 VLESS。
- 兼容 0.1.2 历史任务：旧任务没有持久化候选快照时，以已完成 TCPING 结果的 CF 候选作为历史 TCPING 集合。
- 新增两项回归测试。旧版 CFIPTester 完整文件测速引擎未修改。
