---
id: internal_contract_zh_cn
title: 内置合约
custom_edit_url: https://github.com/Conflux-Chain/conflux-rust/edit/master/internal_contract/README_zh_cn.md
keywords:
  - conflux
  - contract
---

## 管理与控制

合约地址为`0x8060de9e1568e69811c4a398f92c3d10949dc891`。

+ `set_admin(address contract, address admin)`: 设置`admin`为合约`contract`的管理员。函数调用者应为合约`contract`的管理员且账号状态正常。调用者要确保`contract`字段确实写入了合约地址且`admin`字段是正常的账户地址。否则，调用失败。

+ `destroy(address contract)`: 销毁合约`contract`。函数调用者应为合约`contract`的管理员且账号状态正常。若合约担保非0，则销毁合约失败.否则，合约`contract`的`balance`退还给现任管理者处。`sponsor_balance_for_gas`将会退还到`sponsor_for_gas`，`sponsor_balance_for_collateral`则会退还到`sponsor_for_collateral`。

## 赞助人白名单控制

合约地址为`0x8ad036480160591706c831f0da19d1a424e39469`.

+ `set_sponsor_for_gas(address contract, uint upper_bound)`: 如果有人希望向合约地址`contract`赞助燃料费用, 他/她（也可以是合约账户）可以在调用该函数的同时向地址`0x8ad036480160591706c831f0da19d1a424e39469`传输代币，参数`upper_bound`是指赞助者为单笔交易支付的燃料费用上限。传输的代币量至少为参数`upper_bound`的1000倍。 赞助者可能会被赞助更多代币同时设置更高的上界参数的赞助者所替换。当前赞助者也可以调用该函数并向该合约传输更多代币。在当前赞助者账户余额小于参数`upper_bound`时 ，`upper_bound`值将被动态调低。
+ `set_sponsor_for_collateral(address contract_addr)`: 如果有人希望向地址为`contract`的合约赞助担保金， 他/她（也可以是合约账户）可以在调用该函数的同时向地址 `0x8ad036480160591706c831f0da19d1a424e39469`传输代币。赞助者可能会被传输更多代币的新赞助者替换而当前赞助者也可通过调用该函数向合约传输更多代币。
+ `add_privilege(address[] memory)`: 合约可通过调用该函数向白名单中加入部分正常账户地址。这意味着，若 `sponsor_for_gas`被设置，合约会向白名单内的账户支付燃料费用，若`sponsor_for_collateral`被设置，则合约会向白名单内账户支付担保金。合约可通过使用特殊地址`0x0000000000000000000000000000000000000000`，能够将所有账户加入到白名单中。
+ `remove_privilege(address[] memory)`: 合约可通过调用该函数从白名单中移除正常账户。

## 权益质押

合约地址为`0x843c409373ffd5c0bec1dddb7bec830856757b65`.

+ `deposit(uint amount)`: 调用者可以通过调用该函数将部分代币存入Conflux内嵌的权益质押合约。目前的年化利率为4%。
+ `withdraw(uint amount)`: 调用者可通过调用该函数从Conflux内嵌的权益质押合约中提取代币。运行该函数将会触发利息结算。权益质押资金和利息将会及时转入到用户账户中。
+ `vote_lock(uint amount, uint unlock_block_number)`: 该函数与Conflux的投票权益相关。权益质押用户可以通过选择投票数额及锁定的到期日锁定一定数目的CFX费用。参数`unlock_block_number`会以创世区块产生以来的区块数目度量。