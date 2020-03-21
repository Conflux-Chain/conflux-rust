# Conflux Internal Contract

## AdminControl

The contract address is `0x6060de9e1568e69811c4a398f92c3d10949dc891`.

+ `set_admin(address contract, address admin)`: Set the administrator of contract `contract` to `admin`. The caller should be the administrator of `contract` and it should be a normal account. Caller should make sure that `contract` should be an address of a contract and `admin` should be a normal account address. Otherwise, the call will fail.

+ `destroy(address contract)`: Perform a suicide of the contract `contract`. The caller should be the administrator of `contract` and it should be a normal account. If the collateral for storage of the contract is not zero, the suicide will fail. Otherwise, the `balance` of `contract` will be refunded to the current administrator, the `sponsor_balance_for_gas` will be refunded to `sponsor_for_gas`, the `sponsor_balance_for_collateral` will be refunded to `sponsor_for_collateral`.

## SponsorWhitelistControl

The contract address is `0x8ad036480160591706c831f0da19d1a424e39469`.

+ `set_sponsor_for_gas(address contract, uint upper_bound)`: If someone wants to sponsor the gas fee for a contract with address `contract`, he/she (it should be a normal account) should call this function and in the meantime transfer some tokens to the address `0x8ad036480160591706c831f0da19d1a424e39469`. The parameter `upper_bound` is the upper bound of the gas fee the sponsor will pay for a single transaction. The sponsor could be replaced if the new sponsor transfers more tokens and sets a larger upper bound. The current sponsor can also call the function to transfer more tokens to sponsor the contract. The `upper_bound` can be changed to a smaller one if current sponsor balance is less than the `upper_bound`.
+ `set_sponsor_for_collateral(address contract_addr)`: If someone wants to sponsor the CFS (collateral for storage) for a contract with address `contract`, he/she (it should be a normal account) should call this function and in the meantime transfer some tokens to the address `0x8ad036480160591706c831f0da19d1a424e39469`. The sponsor could be replaced if the new sponsor transfers more tokens. The current sponsor can also call the function to transfer more tokens to sponsor the contract.
+ `add_privilege(address[] memory)`: A contract can call this function to add some normal account address to the whitelist. It means that if the `sponsor_for_gas` is set, the contract will pay the gas fee for the accounts in the whitelist, and if the `sponsor_for_collateral` is set, the contract will pay the CFS (collateral for storage) for the accounts in the whitelist. A special address `0x0000000000000000000000000000000000000000` could be used if the contract wants to add all account to the whitelist.
+ `remove_privilege(address[] memory)`: A contract can call this function to remove some normal account address from the whitelist.

## Staking

The contract address is `0x843c409373ffd5c0bec1dddb7bec830856757b65`.

+ `deposit(uint amount)`: The caller can call this function to deposit some tokens to Conflux Internal Staking Contract. The current annual interest rate is 4%.
+ `withdraw(uint amount)`: The caller can call this function to withdraw some tokens to Conflux Internal Staking Contract. It will trigger a interest settlement. The staking capital and staking interest will be transferred to the user's balance in time. Withdrawal fee will be designed in linearly gradient-type from 0-0.05%. The fee is 0.05% of one-day staking and 0 of staking more than one year. All the withdrawal fees will be burned. All the withdrawal applications will be processed on a first-come-first-served basis according to the sequence of staking orders.
+ `lock(uint amount, uint duration)`: This function is related with Voting Rights in Conflux. Staking users can choose the voting amount and locking maturity by locking a certain amount of CFX in a certain maturity from staking.