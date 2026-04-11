# Crypto优化方案反馈记录

本文件记录所有被拒绝的优化方案、拒绝理由和反馈意见，供后续方案提出时参考学习。

---

## 2026-04-11: Round-Robin Request ID Hint

### 方案概述
在 `hisi_zip_req_q` 结构体中添加 `next_req_id` 字段，使用 `find_next_zero_bit()` 替代 `find_first_zero_bit()` 实现round-robin式的请求ID分配。

### 提出的优化点
- 减少平均搜索距离（FIFO场景下从 N/2 降至约 1）
- 改善缓存局部性
- 无额外锁开销

### 拒绝理由
`find_next_zero_bit()` 内部使用分块查找，时间复杂度接近 O(1)，不是线性查找。该优化方案提升不大，没有明显意义。

### 学习要点
1. **深入理解底层实现**：在优化某个函数调用前，需先了解其内部实现机制。`find_next_zero_bit()` 并非简单的线性遍历，而是分块查找。
2. **避免表面优化**：不要仅凭函数名或表面逻辑判断性能瓶颈，需有实际数据支撑。
3. **关注真正的问题**：如果底层实现已经很高效，则上层的"优化"往往没有意义。

### 相关代码
```c
// 原始实现
req_id = find_first_zero_bit(req_q->req_bitmap, req_q->size);

// 提议的优化（被拒绝）
hint = req_q->next_req_id;
req_id = find_next_zero_bit(req_q->req_bitmap, req_q->size, hint);
if (req_id >= req_q->size)
    req_id = find_first_zero_bit(req_q->req_bitmap, req_q->size);
```

---

<!-- 后续反馈记录将添加在下方 -->

