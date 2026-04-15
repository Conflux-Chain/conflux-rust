# Stratum Protocol Workflow Documentation

## Overview

Stratum is a mining protocol implemented in the Conflux client for communication between mining pools and miners. The protocol is based on JSON-RPC 2.0 standard and communicates over TCP connections.

## JSON-RPC Interfaces

### 1. mining.subscribe

**Description**: Miners subscribe to mining jobs and register with the pool

**Method Name**: `mining.subscribe`

**Parameters**:
- `worker_id` (String): Worker identifier
- `secret` (String): Secret key (if server has secret verification configured)

**Request Example**:
```json
{
    "jsonrpc": "2.0",
    "method": "mining.subscribe",
    "params": ["miner1", ""],
    "id": 1
}
```

**Request Example with Secret**:
```json
{
    "jsonrpc": "2.0",
    "method": "mining.subscribe",
    "params": ["miner1", "test_secret"],
    "id": 1
}
```

**Return Result**:
- Success: `true` - Worker successfully registered
- Failure: `false` - Secret verification failed or other errors

**Success Response Example**:
```json
{
    "jsonrpc": "2.0",
    "result": true,
    "id": 1
}
```

**Failure Response Example**:
```json
{
    "jsonrpc": "2.0",
    "result": false,
    "id": 1
}
```

### 2. mining.submit

**Description**: Miners submit mining results (shares)

**Method Name**: `mining.submit`

**Parameters**: Array format containing the following fields
- `worker_id` (String): Worker identifier
- `job_id` (String): Job identifier
- Other mining-related parameters (such as nonce, hash, etc.)

**Request Example**:
```json
{
    "jsonrpc": "2.0",
    "method": "mining.submit",
    "params": [
        "test_miner",
        "job_id",
        "0x1",
        "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    ],
    "id": 2
}
```

**Return Result**: Array format
- Success: `[true]`
- Failure (invalid solution): `[false, "error reason"]`
- Failure (other errors): `[false]`

**Success Response Example**:
```json
{
    "jsonrpc": "2.0",
    "result": [true],
    "id": 2
}
```

**Failure Response Example (Invalid Solution)**:
```json
{
    "jsonrpc": "2.0",
    "result": [false, "Invalid solution: reason"],
    "id": 2
}
```

**Failure Response Example (Other Errors)**:
```json
{
    "jsonrpc": "2.0",
    "result": [false],
    "id": 2
}
```

### 3. mining.notify

**Description**: Server pushes new mining jobs to miners (server-initiated push)

**Method Name**: `mining.notify`

**Push Message Format**:
```json
{
    "id": 17,
    "method": "mining.notify",
    "params": { "00040008", "100500" }
}
```

**Notes**:
- This is a server-initiated notification, not a response to a miner request
- `id`: Notification counter, starting from 16 and incrementing
- `params`: Contains specific parameters for the mining job (format determined by the specific PoW algorithm)

## Workflow

### 1. Miner Connection Flow

```
Miner                                   Server
  |                                       |
  |------ TCP Connection ---------------->|
  |                                       |
  |------ mining.subscribe -------------->|
  |       ["worker_id", "secret"]         |
  |                                       |
  |                                       |--- Verify secret (if configured)
  |                                       |--- Register worker
  |                                       |
  |<----- Return true/false --------------|
  |                                       |
```

### 2. Job Push Flow

```
Server                                  Miner1, Miner2, ...
  |                                       |
  |--- New block/job generated            |
  |                                       |
  |--- push_work_all()                    |
  |    - Increment notification counter   |
  |    - Construct mining.notify message  |
  |                                       |
  |------ mining.notify ----------------->|
  |       (push to all registered miners) |
  |                                       |
  |                                       |--- Receive job
  |                                       |--- Start mining
  |                                       |
```

### 3. Result Submission Flow

```
Miner                                   Server
  |                                       |
  |--- Found solution                     |
  |                                       |
  |------ mining.submit ----------------->|
  |       [worker_id, job_id, ...]        |
  |                                       |
  |                                       |--- Verify solution
  |                                       |--- Call JobDispatcher.submit()
  |                                       |
  |<----- Return [true] or [false, msg] --|
  |                                       |
```

### 4. Error Handling Flow

```
1. Secret verification failure
   - mining.subscribe returns false
   - Worker is not registered in workers list

2. Invalid solution
   - mining.submit returns [false, "error reason"]
   - Log warning

3. Miner disconnection
   - Detected during push_work_all when connection fails
   - Remove miner from workers list
   - Log debug message

4. Other submission errors
   - mining.submit returns [false]
   - Log warning
```

## Security Mechanism

### Secret Verification

The server can configure a secret (H256 type hash value), and miners need to provide the correct secret when subscribing:

1. Server stores the Keccak hash of the secret
2. Miner provides the original secret string
3. Server performs Keccak hash on the miner's provided secret
4. Compare hash values, allow subscription only if verification passes

**Code Implementation**:
```rust
if let Some(valid_secret) = self.secret {
    let hash = keccak(secret);
    if hash != valid_secret {
        return to_value(&false);
    }
}
```

## Protocol Features

1. **Based on JSON-RPC 2.0**: Standardized RPC protocol
2. **TCP Long Connection**: Maintains connection for server-initiated job pushes
3. **Bidirectional Communication**: Supports both client requests and server pushes
4. **Secret Verification**: Optional security mechanism
5. **Automatic Cleanup**: Automatically detects and cleans up disconnected connections
6. **Asynchronous Processing**: Uses async/await to handle requests

## Important Notes

1. All JSON-RPC messages must end with a newline character `\n`
2. Secret uses Keccak hash algorithm for verification
3. Notification counter starts from 16 to avoid conflicts with client request IDs
4. Workers are automatically cleaned up on next job push after disconnection
5. Submitted parameters must be a string array; non-string parameters are filtered out
