---
id: internal_contract
title: Internal Contract
custom_edit_url: https://github.com/Conflux-Chain/conflux-rust/edit/master/internal_contract/README.md
keywords:
  - conflux
  - contract
---


- [AdminControl contract](#admincontrol-contract)
  - [Overview](#overview)
  - [Examples](#examples)
- [SponsorWhitelistControl contract](#sponsorwhitelistcontrol-contract)
  - [Overview](#overview-1)
  - [Sponsorship Replacement](#sponsorship-replacement)
  - [Add Sponsor Balance](#add-sponsor-balance)
  - [Whitelist maintenance](#whitelist-maintenance)
  - [Examples](#examples-1)
- [Staking Contract](#staking-contract)
  - [Overview](#overview-2)
  - [Interest Rate](#interest-rate)
  - [Locking and Voting Power](#locking-and-voting-power)
  - [Examples](#examples-2)

(**IMPORTANT: the interfaces are changed in Tethys mainnet. This document is synced with the newest version.**)

Conflux introduces several built-in internal contracts for better system maintenance and on-chain governance. Now Conflux has three internal contracts: `AdminControl` contract, `SponsorWhitelistControl` contract and `Staking` contract. These contracts provide solidity function apis defined [here](https://github.com/Conflux-Chain/conflux-rust/tree/master/internal_contract/contracts). These function can only be called via `CALL` or `STATICCALL` operation. Using operation `CALLCODE` or `DELEGATECALL` to interact with internal contracts will trigger an error.

The addresses of these three internal contracts are list as follows:
- AdminControl: `0x0888000000000000000000000000000000000000`
- SponsorWhitelistControl: `0x0888000000000000000000000000000000000001`
- Staking: `0x0888000000000000000000000000000000000002`

All the example code in this document will use [js-conflux-sdk](https://github.com/Conflux-Chain/js-conflux-sdk). The solidity function apis are list [here](https://github.com/Conflux-Chain/conflux-rust/tree/master/internal_contract/contracts).

# AdminControl contract

## Overview

The `AdminControl` contract is a debug tool for contract development. When a contract is created during a transaction, the sender for the current transaction will become the contract admin automatically.

The `admin` address can transfer the administrator rights to another **normal address** or **zero address** by calling interface `setAdmin(address contractAddr, address newAdmin)`. A contract can never be an admin. 

The admin of a contract has several administrator rights. It can call interface `destroy(address contractAddr)` to destroy contract, just like a contract calling `suicide()` function. The SponsorWhitelist internal contract provides some functions can only be called by admin address. These functions can update the whitelist in sponsor mechanism. They will be introduced later. 

**Note: For all the interfaces requiring administrator rights, no matter the execution success or not, no error or exception will be triggered during internal contract execution.** For example, if a non-admin address tries to transfer the admin address to itself, this transaction will success but nothing will be changed. 

ConfluxScan may mark a contract as debug mode if the contract has non-zero admin address. **So remember, if you think the contract is ready for production environment, you should set admin address to zero.**


The `AdminControl` contract also provides a query interface `getAdmin(address contractAddr)` which can be called by anyone. 

**Corner cases:**
1. The admin is set at the start of contract creation. So if sender `A` creates contract `B` and set admin to `C` during contract construction, the admin will be `C` when the contract is deployed. 
2. However, if sender `A` calls contract `B`, then contract `B` creates contract `C` and then set admin to `D` during contract contraction, then the set will fail because the admin of `C` is `A` and the sender for creating `C` is `B`. 
3. But, Conflux introduces a special policy. In case 2, if `D` is zero address, the set admin will success. This means that a contract can declare "I don't need admin" during contract creation. 

## Examples

Consider you have deployed a contract whose address is `contract_addr`. The administrator can call `AdminControl.setAdmin(contract_addr, new_admin)` to change the administrator and call `AdminControl.destroy(contract_addr)` to kill the contract. 

```javascript
const PRIVATE_KEY = '0xxxxxxx';
const cfx = new Conflux({
  url: 'https://test.confluxrpc.com',
  logger: console,
  networkId: 1,
});
const account = cfx.wallet.addPrivateKey(PRIVATE_KEY); // create account instance

const admin_contract = cfx.InternalContract('AdminControl')
// to change administrator
admin_contract.setAdmin(contract_addr, new_admin).sendTransaction({
  from: account,
}).confirmed();

// to kill the contract
admin_contract.destroy(contract_addr).sendTransaction({
  from: account,
}).confirmed();
```


# SponsorWhitelistControl contract

## Overview

Conflux implements a sponsorship mechanism to subsidize the usage of smart contracts. Thus, a new account with zero balance is able to call smart contracts as long as the execution is sponsored (usually by the operator of Dapps). The built-in SponsorControl contract is introduced to record the sponsorship information of smart contracts. 

When a message call happens, Conflux does not check sponsorship again. For example, if normal address `A` calls contract `B` and contract `B` calls contract `C`, Conflux only checks whether address `A` is sponsored by contract `B`. If `A` is sponsored, `B` will afford all the gas and/or collateral during the transaction execution, including the message call from `B` to `C`. In other words, only a transaction sender could be sponsored.  

The **SponsorControl** contract keeps the following information for each user-established contract:
+ `sponsor_for_gas`: this is the account that provides the subsidy for gas consumption;
+ `sponsor_for_collateral`: this is the account that provides the subsidy for collateral for storage;
+ `sponsor_balance_for_gas`: this is the balance of subsidy available for gas consumption;
+ `sponsor_balance_for_collateral`: this is the balance of subsidy available for collateral for storage;
+ `sponsor_limit_for_gas_fee`: this is the upper bound for the gas fee subsidy paid for every sponsored transaction;
+ `whitelist`: this is the list of normal accounts that are eligible for the subsidy, where a special all-zero address refers to all normal accounts. Only the contract itself and the admin have the authority to change this list.

There are two resources that can be sponsored: gas consumption and storage collateral.

+ *For gas consumption*: If a transaction calls a contract with non-empty `sponsor_for_gas` and the sender is in the `whitelist` of the contract and the gas fee specified by the transaction is within the `sponsor_limit_for_gas_fee`, the gas consumption of the transaction is paid from the `sponsor_balance_for_gas` of the contract (if it is sufficient) rather than from the sender’s balance, and the execution of the transaction would fail if the `sponsor_balance_for_gas` cannot afford the gas consumption. Otherwise, the sender should pay for the gas consumption.
+ *For storage collateral*: If a transaction calls a contract with non-empty `sponsor_balance_for_collateral` and the sender is in the `whitelist` of the contract,  the collateral for storage incurred in the execution of the transaction is deducted from `sponsor_balance_for_collateral` of the contract, and the owner of those modified storage entries is set to the contract address accordingly. Otherwise, the sender should pay for the collateral for storage incurred in the execution.

When a contract is created, its `sponsor_for_gas` and `sponsor_for_collateral` will be initialized by zero address, and the sponsor balance will be initialized by 0. Both sponsorship for gas and for collateral can be updated by calling the SponsorControl contract. The current sponsor can call this contract to transfer funds to increase the sponsor balances directly, and the current sponsor for gas is also allowed to increase the `sponsor_limit_for_gas_fee` without transferring new funds. Other normal accounts can replace the current sponsor by calling this contract and providing more funds for sponsorship.

## Sponsorship Replacement

To replace the `sponsor_for_gas` of a contract, the new sponsor should call function `setSponsorForGas(address contractAddr, uint upperBound)` and transfer to the internal contract a fund. The following conditions are required to replace sponsor for gas:

1. The transferred fund should more than the current `sponsor_balance_for_gas` of the contract.
2. The new value for `sponsor_limit_for_gas_fee` (specified the `upperBound` parameter) should be no less than the old sponsor’s limit unless the old `sponsor_balance_for_gas` cannot afford the old `sponsor_limit_for_gas_fee`.
3. The transferred fund should be >= 1000 times of the new limit, so that it is sufficient to subsidize at least `1000` transactions calling the contract.

If the above conditions are satisfied, the remaining `sponsor_balance_for_gas` will be refunded to the old `sponsor_for_gas`, and the fund transferred to the internal contract will be added to the `sponsor_balance_for_gas` of the contract. Then the `sponsor_for_gas` and `sponsor_limit_for_gas_fee` will be updated according to the new sponsor’s specification. Otherwise, an exception will be triggered. 

The replacement of `sponsor_for_collateral` is similar except that there is no analog of the limit for gas fee. The function is `setSponsorForCollateral(address contractAddr)`. The new sponsor should transfer a fund more than the fund provided by the current sponsor for collateral of the contract. Then the current `sponsor_for_collateral` will be fully refunded, i.e. the sum of `sponsor_balance_for_collateral` and the total collateral for storage used by the contract, and both collateral sponsorship fields are changed as the new sponsor’s request accordingly. 

Conflux also allows a contract account to be a sponsor. 

## Add Sponsor Balance  

The sponsor can provide additional sponsor balance without sponsorship replacement. In this case, the sponsor should also interact with function `setSponsorForGas(address contractAddr, uint upperBound)` or `setSponsorForCollateral(address contractAddr)`, and meet all the requirements except condition 1. If requirements are satisfied, the transferred fund will be added to sponsor balance and the `sponsor_limit_for_gas_fee` will be updated accordingly.

## Whitelist maintenance

Only the contract itself or contract admin can update the contract whitelist. The sponsors have no rights for changing whitelist. 

A contract can call function `addPrivilege(address[] memory)` to any addresses to the whitelist. It means that if the `sponsor_for_gas` is set, the contract will pay the gas fee for the accounts in the whitelist, and if the `sponsor_for_collateral` is set, the contract will pay the CFS (collateral for storage) for the accounts in the whitelist. The zero address is a special address `0x0000000000000000000000000000000000000000`. If this address is added to whitelist, all the transactions calling this contract will be sponsored. A contract can call this function `removePrivilege(address[] memory)` to remove some normal account address from the whitelist. Remove a non-existent address will not cause an error or exception. 

**Corner cases:**
1. A contract address can also be added to the whitelist, but it is meaningless because only the transaction sender could be sponsored. 

The admin of a contract can use the interfaces `addPrivilegeByAdmin(address contractAddr, address[] memory addresses)` and `removePrivilegeByAdmin(address contractAddr, address[] memory addresses)` to maintain the whitelist.

## Examples

Suppose you have a simple contract like this.
```solidity
pragma solidity >=0.4.15;

import "https://github.com/Conflux-Chain/conflux-rust/blob/master/internal_contract/contracts/SponsorWhitelistControl.sol";

contract CommissionPrivilegeTest {
    mapping(uint => uint) public ss;

    function add(address account) public payable {
        SponsorWhitelistControl cpc = SponsorWhitelistControl(0x0888000000000000000000000000000000000001);
        address[] memory a = new address[](1);
        a[0] = account;
        cpc.addPrivilege(a);
    }

    function remove(address account) public payable {
        SponsorWhitelistControl cpc = SponsorWhitelistControl(0x0888000000000000000000000000000000000001);
        address[] memory a = new address[](1);
        a[0] = account;
        cpc.removePrivilege(a);
    }

    function foo() public payable {
    }

    function par_add(uint start, uint end) public payable {
        for (uint i = start; i < end; i++) {
            ss[i] = 1;
        }
    }
}
```

After deploying the contract and the address is `contract_addr`, if someone wants to sponsor the gas consumption, he/she can send a transaction like below:
```javascript
const PRIVATE_KEY = '0xxxxxxx';
const cfx = new Conflux({
  url: 'https://test.confluxrpc.com',
  logger: console,
  networkId: 1,
});
const account = cfx.wallet.addPrivateKey(PRIVATE_KEY); // create account instance

const sponsor_contract = cfx.InternalContract('SponsorWhitelistControl');
sponsor_contract.setSponsorForGas(contract_addr, your_upper_bound).sendTransaction({
  from: account,
  value: your_sponsor_value
}).confirmed();
```

As for sponsor the storage collateral, you can simply replace the function `setSponsorForGas(contract_addr, your_upper_bound)` to `setSponsorForCollateral(contract_addr)`.

After that you can maintain the `whitelist` for your contract using `addPrivilege` and `removePrivilege`. The special address `0x0000000000000000000000000000000000000000` with all zeros means everyone is in the `whitelist`. You need to use it carefully.

```javascript
you_contract.add(white_list_addr).sendTransaction({
  from: account,
})

you_contract.remove(white_list_addr).sendTransaction({
  from: account,
})
```

After that the accounts in `whiltelist` will pay nothing while calling `you_contract.foo()` or `you_contract.par_add(1, 10)`.


# Staking Contract

## Overview

Conflux introduces the staking mechanism for two reasons: first, staking mechanism provides a better way to charge the occupation of storage space (comparing to “pay once, occupy forever”); and second, this mechanism also helps in defining the voting power in decentralized governance.

At a high level, Conflux implements a built-in **Staking** contract to record the staking information of all accounts, for both normal addresses and smart contracts. By sending a transaction to this contract, users (both external users and smart contracts) can deposit/withdraw funds, which is also called stakes in the contract. The interest of staked funds is issued at withdrawal, and depends on both the amount and staking period of the fund being withdrawn.

A user (or a contract) can deposit balance for staking by calling `deposit(uint amount)` and then `amount` Drip will be moved from its `balance` to `stakingBalance`. Notice that this function is non-payable, the user only needs to specify the amount to be staked without transferring any funds to internal contract and the minimum deposit amount is `1 CFX`.

The user can also withdraw balance by `withdraw(uint amount)`. The caller can call this function to withdraw some tokens from the Conflux Internal Staking Contract. This will also trigger interest settlement. The staking capital and staking interest will be transferred to the user's balance in time. All the withdrawal applications will be processed on a first-come-first-served basis according to the sequence of staking orders.

## Interest Rate

The annualized staking interest rate is currently set to 4.08%. Compound interest is implemented in the granularity of blocks.

When executing a transaction sent by account `addr` at block `B` to withdraw a fund of value `v` deposited at block `B'`, the interest is calculated as follows:

```
interest issued = v * (1 + 4% / 63072000)^T - v
```

where `T = BlockNo(B)−BlockNo(B')` is the staking period measured by the number of blocks, and `63072000` is the expected number of blocks generated in `365` days with the target block time `0.5` seconds.

## Locking and Voting Power 

By locking the staking balance, the user can obtain *vote power* for further on-chain governance. With function `voteLock(uint amount, uint unlock_block_number)`, the account makes a promise that This process resembles making promise that "My `stakingBalance` will always have at least `amount` Drip before the block with block number `unlock_block_number`". The account can make multiple promises, like "I will always at least 10 CFX in this year, and then always stake at least 5 CFX in the next year."  **Once the promise has been made, there is no way to cancel it!** But the account can overwrite old promise by locking more balance. Whenever the account tries to withdraw `stakingBalance`, the internal contract will check whether the rest balance matches the locking promise. 

Here we introduce the detailed logic for locking balance by illustrating several examples. Suppose the current block number is `base`, Conflux will generate about `x` blocks in the rest of this year and `y` blocks in the next year. Since Conflux generates two block per second, `y` approximately equals to `2 * 60 * 60 * 24 * 365`. And the value of `x` depends on when you read this article.

1. If an account has 10 CFX in `stakingBalance`, and it calls `voteLock(100 * 10^18, base + x)`, then the transaction will  fail because this account tries to lock 100 CFX with insufficient `stakingBalance`.   
2. However, if this account calls `voteLock(8 * 10^18, base + x)`, the transaction will success.
3. After that, if this account calls `voteLock(6 * 10^18, base + x + y)`, the transaction will also success. It means that 8 - 6 = 2 CFX will be unlocked until the end of this year, and another 6 CFX will be locked until the end of next year. 
4. Then, if this account calls `voteLock(0, base + x)`, nothing will happen. The transaction will not trigger an error during execution. The internal contract will regard this call as a meaningless promise: the account will stake at least 0 CFX. The old promises made in step 2 and step 3 will still hold.
5. If this account calls `voteLock(9 * 10^18, base + x + y)`, the old two promises will be overwritten because "locking 9 CFX until the end of the next year" is a stronger promise.

Locking does not have any influence on the stake interest. When the account withdraw staking balance successfully, the staking interest will be computed as usual. 

At any time, each locked Drip will be assigned a *vote power* from 0 to 1 according to its unlock time. The Drips to be unlocked in more than one year will have a full vote power. See section 8.3.2 in the [Conflux Protocol Specification](https://conflux-protocol.s3-ap-southeast-1.amazonaws.com/tech-specification.pdf) for more details.

## Examples

```javascript
const PRIVATE_KEY = '0xxxxxxx';
const cfx = new Conflux({
  url: 'https://test.confluxrpc.com',
  logger: console,
  networkId: 1,
});
const account = cfx.wallet.addPrivateKey(PRIVATE_KEY); // create account instance

const staking_contract = cfx.InternalContract('Staking');
// deposit some amount of tokens
staking_contract.deposit(your_number_of_tokens).sendTransaction({
  from: account,
}).confirmed();

// withdraw some amount of tokens
staking_contract.withdraw(your_number_of_tokens).sendTransaction({
  from: account,
}).confirmed();

// lock some tokens until some block number
staking_contract.voteLock(your_number_of_tokens, your_unlock_block_number).sendTransaction({
  from: account,
}).confirmed();
```
