# 交易未被打包诊断指南

## 问题描述

当交易的 RPC 返回 `Ready` 状态但交易一直没有被执行时，可能的原因有两个：

1. **交易未进入 PackingPool** - 虽然在 deferred_pool 中，但还不符合打包条件
2. **交易在 PackingPool 中但未被选中** - 在打包池中但因某种原因没被采样打包

## 诊断方法

### 方法 1：查看诊断日志

编译时启用 DEBUG 日志级别，运行节点时查看以下关键日志标记：

```bash
# 启用 DEBUG 日志
RUST_LOG=debug cargo run

# 查找以下日志关键字：
# [ReadinessRecalc] - 就绪状态重新计算
# [Packing] - 打包阶段的详细日志
```

### 方法 2：通过代码诊断（在内部调用）

在交易池模块中调用诊断函数：

```rust
// 在 transaction_pool_inner 中
let diagnosis = pool.diagnose_tx_packing_failure(&tx_hash)?;
println!("{}", diagnosis);
```

输出格式示例：

```
TxHash: 0x...
Sender: cfx:...
Nonce: 5
===== Pool Status =====
InBuckets(deferred_pool): true
InPackingPool: true
AddressHasReadyTxs: true
NumReadyTxsForAddress: 3
===== Account State =====
StateNonce: 3
StateBalance: 1000000000000000000
===== Diagnosis =====
Tx is in packing_pool but not being selected. Possible reasons:
1. Gas price too low: 1 Gwei (check against current base price)
2. Not selected by random sampling algorithm
3. Block gas/size limits preventing packing
4. Validity check failing (epoch, etc)
```

## 如何读懂诊断输出

### Case 1: InBuckets=false
**问题**：交易不在 deferred_pool 中
- 交易可能已被删除或从未成功插入
- 检查：交易是否因费用不足被拒绝？

### Case 2: InBuckets=true, AddressHasReadyTxs=false
**问题**：地址没有就绪交易
- Nonce 不连续：前面有缺失的 nonce
- 余额不足：交易总成本超过账户余额
- **诊断**：检查是否有前置交易未确认或余额变化

### Case 3: InBuckets=true, AddressHasReadyTxs=true, InPackingPool=false
**问题**：地址有就绪交易，但这个交易不在 PackingPool 中
- 可能被前面的交易所阻挡（PackingPool 只保留最长有效前缀）
- gas_price < 前面交易的 gas_price（违反单调递增约束）
- **诊断**：检查账户的第一笔交易状态

### Case 4: InBuckets=true, InPackingPool=true, 但仍未被打包
**问题**：交易在 PackingPool 中但未被采样
- **原因 1**：Gas Price 太低
  - 检查当前 base price 是否上升
  - 交易 gas_price 是否 < tx_min_price
- **原因 2**：随机采样未选中
  - PackingPool 使用随机采样算法
  - 低 gas_price 交易被选中概率低
- **原因 3**：区块限制
  - Gas limit 已满
  - 交易大小超过剩余空间
- **原因 4**：验证失败
  - Epoch height 过期（OldEpochHeight）
  - 赞助状态不一致（OutdatedStatus）

## 日志解读示例

### 日志 1：未进入 PackingPool
```
[ReadinessRecalc] No ready tx found for addr=cfx:..., clearing packing pool. 
                   state_nonce=5, balance=0
```
**含义**：账户余额为 0，无法形成就绪交易链

### 日志 2：Pending 状态被触发
```
[Packing] Tx status=Pending (may be valid in future): 
           sender=cfx:..., nonce=5, hash=0x...
```
**含义**：交易验证失败但可能在将来有效（如等待硬分叉启用新功能）

### 日志 3：Gas Price 不足
```
[Packing] Tx not packed: gas_price=1 Gwei < tx_min_price=50 Gwei, 
           sender=cfx:..., nonce=5, hash=0x...
```
**含义**：设置的 gas_price 太低，无法打包

### 日志 4：区块限制
```
[Packing] Block gas limit exhausted: gas=100000 > rest_gas_limit=50000, 
           sender=cfx:..., nonce=5, hash=0x...
```
**含义**：区块 gas 已满，该交易需要等待下一个区块

### 日志 5：成功打包
```
[Packing] Tx packed successfully: sender=cfx:..., nonce=5, 
           gas=21000, size=128, hash=0x...
```
**含义**：交易被成功选中打包

## 快速排查清单

- [ ] 检查 RPC 返回的 `first_tx_status` 是否真的是 `Ready`？
  - 如果是 `Pending(OldEpochHeight)`：Epoch 已过期，需要重新发送
  - 如果是 `Pending(OutdatedStatus)`：赞助状态不准确，需要等待或重新发送
  
- [ ] 检查账户当前 nonce：
  - `cfx_getAccount` 或 RPC 中的 `state_nonce` 是多少？
  - 交易 nonce 是否 > state_nonce？
  
- [ ] 检查账户余额：
  - 余额是否足以支付交易成本 + gas 费用？
  - 包含所有待执行交易的成本吗？
  
- [ ] 检查 gas price：
  - 当前 base price 是多少？
  - 交易 gas_price 是否 >= base price？
  
- [ ] 检查前置交易：
  - 是否有更低 nonce 的交易未确认？
  - 这些交易是否满足就绪条件？

## 添加更多诊断日志

如果需要更详细的日志，可以在以下位置增加：

1. **`packing_sampler` 入口**（`deferred_pool/mod.rs` 第 110 行）
   - 记录采样开始时的参数
   - 记录 tx_min_price 计算过程

2. **`fast_recheck` 验证**（`verification.rs`）
   - 记录每个验证检查点的结果
   - 记录 Epoch/EIP 状态检查

3. **`recalculate_readiness` 过程**（`deferred_pool/mod.rs` 第 288 行）
   - 记录就绪范围计算细节
   - 记录 PackingPool 的增量更新过程
