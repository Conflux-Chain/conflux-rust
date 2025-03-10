# EIP-7702 Test Plan

## Authorization List Behavior Check

Authorization List Related

- [ ] Test empty authorization list (blocked by web3 api)
- [ ] Nonce
    - [ ] Duplicate nonce
    - [ ] Skip nonce
- [x] ChainID
    - [x] Incorrect ChainID (fail)
    - [x] ChainID is 0 (success)

(Note: Failed authorization behavior is no-op)

Multiple Authorization Related

- [ ] Consider four steps: Set → Set to Another → Set to zero → Set
- [ ] Intersperse storage modification operations between different sets (Note: Authorization changes and setting to 0 do not affect storage)
- [ ] Adjacent steps may/may not be in the same epoch

(Based on code implementation, there may be corner case bugs here. Consider designing fuzzy tests or traversing all possible permutations.)

Call Related

- [x] Normal call
- [ ] Proxy points to address without code
- [x] Proxy points to precompiled address
- [ ] Proxy points to Proxy address (e.g. ERC-1967)

Same Transaction Behavior

- [x] Call in same transaction as authorization
- [x] Create contract in same transaction as authorization
- [x] Call after creation in same transaction as authorization
- [x] Call after creation in same transaction as authorization, with suicide in function

Suicide Related

- [x] Contract being called contains suicide

Trace Related

- [ ] If EOA address A authorizes contract B, and contract B calls address C, trace should show A → C, without B (or check geth behavior)

## Per Test Case Check

(Consider adding to each test case)

Opcode Related

- [x] EXTCODESIZE, EXTCODEHASH behave as expected

Call Related

- [x] Calling EOA account with code behaves as expected
    - [ ] Check through balance to verify using EOA address balance not code address balance
- [ ] EOA can normally initiate private key signed transactions