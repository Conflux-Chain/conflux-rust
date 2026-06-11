# Genesis Block Transactions

The Conflux genesis block contains eight transactions, each serving a specific purpose:

- Transaction 0: Writes the genesis message on-chain: `"The Times 28/Oct/2020 Fees for current accounts as negative rates loom"`
- Transaction 1: Deploys the `CREATE2FACTORY` contract
- Transactions 2 & 3: Deploy the `TWO_YEAR_UNLOCK` and `FOUR_YEAR_UNLOCK` contracts respectively
- Transactions 4-7: Deploy the `INVESTOR_FUND`, `TEAM_FUND`, `ECO_FUND`, and `COMMUNITY_FUND` contracts respectively

All transactions are in Core Space.

## Transaction Parameters

The sender of transaction 0 is the zero address. The sender of transactions 1-7 is `GENESIS_ACCOUNT_ADDRESS` (`0x1949000000000000000000000000000000001001`).

Before execution, `GENESIS_ACCOUNT_ADDRESS` is funded with `5,000,000,000 CFX + 100 CFX` (derived from the `GENESIS_TOKEN_COUNT_IN_CFX` constant) to cover gas costs and value transfers for subsequent transactions.

| # | Purpose | nonce | gas | gas_price | storage_limit | value | action |
|---|---------|-------|-----|-----------|---------------|-------|--------|
| 0 | Genesis message | 0 | 0 | 0 | 0 | 0 | Call (zero address) |
| 1 | CREATE2FACTORY | 0 | 300,000 | 1 | 512 | 0 | Create |
| 2 | TWO_YEAR_UNLOCK | 1 | 2,800,000 | 1 | 16,000 | 800,000,000 CFX | Create |
| 3 | FOUR_YEAR_UNLOCK | 2 | 5,000,000 | 1 | 32,000 | 4,200,000,000 CFX | Create |
| 4 | INVESTOR_FUND | 3 | 400,000 | 1 | 1,000 | 0 | Create |
| 5 | TEAM_FUND | 4 | 400,000 | 1 | 1,000 | 0 | Create |
| 6 | ECO_FUND | 5 | 400,000 | 1 | 1,000 | 0 | Create |
| 7 | COMMUNITY_FUND | 6 | 400,000 | 1 | 1,000 | 0 | Create |

Only transactions 2 and 3 carry value (transferring 800 million and 4.2 billion CFX into the unlock contracts respectively). Transactions 4-7 only deploy fund contracts and carry no value.

After each contract deployment, the contract's admin is set to `Address::zero()`. After all transactions are executed, `GENESIS_ACCOUNT_ADDRESS` is cleaned up (account state is reset to empty).

## Special Characteristics

These transactions are not submitted externally. Instead, they are hardcoded in the client code (`genesis_block.rs`) and have the following special characteristics:

1. Transaction 0 has gas and gasPrice set to 0, and is never actually executed — its execution result is hardcoded directly
2. Execution results of all transactions are stored in memory only and are not persisted to the DB
3. **The genesis block's receipt_root is computed from empty receipts, excluding these transactions' receipts**
4. All transactions are signed via `fake_sign`, with v/r/s set to 0x0/0x1/0x1

## RPC Behavior for Genesis Data

Genesis transaction execution results are not persisted to the DB. On node startup, if the `execute_genesis` config is set to true (the default), all genesis transactions are re-executed and the results are stored in memory. In this case, genesis block data can be returned normally.

If `execute_genesis` is set to false, genesis transactions are not executed on startup, and the following RPC responses are affected:

1. `cfx_getBlockByEpochNumber` and other block-fetching endpoints: the returned block's `gasUsed` is null, and transaction fields `blockHash`, `transactionIndex`, `status`, `contractCreated` are all null
2. `cfx_getTransactionByHash`: returned transaction's `status` and `contractCreated` are null
3. `cfx_getEpochReceipts` and `cfx_getTransactionReceipt`: returned receipt is null

> Note: The above applies to non-light node RPC behavior only.

## Genesis Transaction Traces

Genesis transaction trace data returned via RPC is always empty.
