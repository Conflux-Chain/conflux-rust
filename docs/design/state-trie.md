# State Trie

State Trie is used in blockchain networks to store the entire world state, typically organized using MPT (Merkle Patricia Trie) data structures. In Ethereum, all account basic states (balance, nonce, code_hash, storage_root) are stored in the leaf nodes of the state tree, with each contract account's storage data stored separately using an MPT.

Conflux's state storage method differs from Ethereum in several ways:

1. Account basic states and contract storage data are stored in a single MPT tree.
2. Core Space accounts and eSpace accounts are also stored in the same MPT tree.
3. Additionally, the MPT tree stores Core Space account VoteList data and DepositList data (currently no longer used).
4. Contract account Code is also stored in the MPT tree.

In summary, Conflux uses one massive MPT to store all global state data, including account basic information, code, storage, VoteList, and DepositList.

## StorageKey

The core functionality of MPT trees is to support key/value storage and retrieval. Conflux actually implements storing different types of data in the same MPT through different encoding rules.
The StorageKey data type is defined as follows:

```rust
pub enum StorageKey<'a> {
    AccountKey(&'a [u8]),
    StorageRootKey(&'a [u8]),
    StorageKey {
        address_bytes: &'a [u8],
        storage_key: &'a [u8],
    },
    CodeRootKey(&'a [u8]),
    CodeKey {
        address_bytes: &'a [u8],
        code_hash_bytes: &'a [u8],
    },
    DepositListKey(&'a [u8]),
    VoteListKey(&'a [u8]),
}
```

The main data in each of the above keys is the account address bytes array. Different types of keys can be encoded into different MPT keys and used to store different data:

- AccountKey: Used to store account basic information such as nonce, balance, code_hash, etc.
- StorageRootKey: Used to store StorageLayout information, currently has no practical use
- StorageKey: Used to store contract storage data
- CodeRootKey: Used to store contract account code hash
- CodeKey: Used to store contract account code data
- DepositListKey: Used to store Core Space account DepositList information (currently no longer used)
- VoteListKey: Used to store Core Space account VoteList information (currently no longer used)

### Encoding

Assuming there's an account address `0x8fb79782e14c082bfbb91692bf071187866007d2`, let's see what different types of keys look like after encoding:

```sh
# AccountKey directly uses the address itself
8fb79782e14c082bfbb91692bf071187866007d2

# StorageRootKey adds b"data"(64617461) after the address
8fb79782e14c082bfbb91692bf071187866007d2 + 64617461

# StorageKey adds b"data" after the address, then adds the contract storage key
# Assuming the storage key is 0000000000000000000000000000000000000000000000000000000000000008
8fb79782e14c082bfbb91692bf071187866007d2 + 64617461 + 0000000000000000000000000000000000000000000000000000000000000008

# CodeRootKey adds b"code"(636f6465) after the address
8fb79782e14c082bfbb91692bf071187866007d2 + 636f6465

# CodeKey adds b"code" after the address, then adds the code hash
# Assuming the code hash is 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acf
8fb79782e14c082bfbb91692bf071187866007d2 + 636f6465 + 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acf

# DepositKey adds b"deposit"(6465706f736974) after the address
8fb79782e14c082bfbb91692bf071187866007d2 + 6465706f736974

# VoteListKey adds b"vote"(766f7465) after the address
8fb79782e14c082bfbb91692bf071187866007d2 + 766f7465
```

The above encoding is for Core Space accounts. eSpace is slightly different, specifically inserting b"\x81"(81) after the address bytes:

```sh
# AccountKey
8fb79782e14c082bfbb91692bf071187866007d2 + 81

# StorageRootKey
8fb79782e14c082bfbb91692bf071187866007d2 + 81 + 64617461

# StorageKey
# Assuming the storage key is 0000000000000000000000000000000000000000000000000000000000000008
8fb79782e14c082bfbb91692bf071187866007d2 + 81 + 64617461 + 0000000000000000000000000000000000000000000000000000000000000008

# CodeRootKey
8fb79782e14c082bfbb91692bf071187866007d2 + 81 + 636f6465

# CodeKey
# Assuming the code hash is 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acf
8fb79782e14c082bfbb91692bf071187866007d2 + 81 + 636f6465 + 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acf

# DepositKey
8fb79782e14c082bfbb91692bf071187866007d2 + 81 + 6465706f736974

# VoteListKey
8fb79782e14c082bfbb91692bf071187866007d2 + 81 + 766f7465
```

For specific encoding implementation, refer to the StorageKeyWithSpace::to_key_bytes method.

## DeltaMpt and IntermediaMpt

In terms of implementation, Conflux's state tree consists of three trees:

1. DeltaMpt: An incremental Merkle Patricia Trie used to store incremental data of state changes.
2. IntermediaMpt: An intermediate state Merkle Patricia Trie that represents intermediate states between snapshots.
3. Snapshot: Data state snapshots.

When accessing certain data states, the overall access flow (hierarchy) is: DeltaMpt (current changes) → IntermediaMpt (intermediate states) → Snapshot (snapshot states).

The encoding method for DeltaMpt and IntermediaMpt keys differs slightly from regular MPT encoding. Overall, it has an additional padding process.
The basic length of regular MPT keys is the account address bytes length of 20, while delta MPT key basic length is 32. The specific method is as follows:

1. First, there's a padding data with length 32.
2. Concatenate the first 12 bits of padding data with address data to form 32 bits.
3. Calculate keccak hash of the result from step 2.
4. Concatenate the first 12 bits of the hash result with the address to form the final basic key.

The encoding method for extended keys is the same as regular keys.

```sh
# AccountKey
b41eca2cce25321f5ecf85540888000000000000000000000000000000000004 + 81

# StorageRootKey
b41eca2cce25321f5ecf85540888000000000000000000000000000000000004 + 81 + 64617461

# StorageKey
# Assuming the storage key is 0000000000000000000000000000000000000000000000000000000000000008
b41eca2cce25321f5ecf85540888000000000000000000000000000000000004 + 81 + 64617461 + 0000000000000000000000000000000000000000000000000000000000000008

# CodeRootKey
b41eca2cce25321f5ecf85540888000000000000000000000000000000000004 + 81 + 636f6465

# CodeKey
# Assuming the code hash is 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acf
b41eca2cce25321f5ecf85540888000000000000000000000000000000000004 + 81 + 636f6465 + 0x405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5acf

# DepositKey
b41eca2cce25321f5ecf85540888000000000000000000000000000000000004 + 81 + 6465706f736974

# VoteListKey
b41eca2cce25321f5ecf85540888000000000000000000000000000000000004 + 81 + 766f7465
```

## Considerations

1. Following Ethereum's approach by storing account basic data and contract storage data in separate tries would greatly reduce the size of the state trie and significantly speed up traversal.
2. The special flag (0x81) used to distinguish spaces, if placed at the front position, could enable searching only for data from a specific space in prefix search operations, which should also improve search speed.
3. Currently, Conflux's state search method is prefix search, meaning that given 0x01, it can search for all addresses starting with 0x01. Geth and Reth's search method is to find a cursor given an arbitrary address 0x0888000000000000000000000000000000000004, then iterate through all account addresses greater than that address.
