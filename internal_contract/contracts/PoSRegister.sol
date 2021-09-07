// SPDX-License-Identifier: MIT
pragma solidity >=0.5.0;

interface PoSRegister {
/**
 * @dev 注册 PoS 账户
 * @param indentifier 被注册账户的 PoS 地址
 * @param votePower 注册票数
 * @param blsPubKey BLS 公钥
 * @param vrfPubKey VRF 公钥
 * @param blsPubKeyProof BLS 公钥的合法性证明，用于防止某类攻击，conflux-rust 全节点生成
 */
function register(bytes32 indentifier, uint64 votePower, bytes calldata blsPubKey, bytes calldata vrfPubKey, bytes[2] calldata blsPubKeyProof) external;

/**
 * @dev 为 msg.sender 绑定的账户追加投票权
 * @param votePower 注册票数
 */
function increaseStake(uint64 votePower) external;

/**
 * @dev 为 msg.sender 解锁全部 PoS 票数
 */
function retire(uint64 votePower) external;

/**
 * @dev 查询给定 PoS 账户锁仓情况，返回"总抵押票数"和"已解锁票数"
 * @param identifier PoS 地址
 */
function getVotes(bytes32 identifier) external view returns (uint, uint);

/**
 * @dev 查询给定 PoS 账户绑定的 PoW 地址
 * @param identifier PoS 地址
 */
function identifierToAddress(bytes32 identifier) external view returns (address);

/**
 * @dev 查询给定 PoW 地址绑定的 PoS 地址
 * @param addr PoW 地址
 */
function addressToIdentifier(address addr) external view returns (bytes32);

/**
 * @dev register 函数执行成功时产生一个 Register 事件
 */
event Register(bytes32 indexed identifier, bytes blsPubKey, bytes vrfPubKey);

/**
 * @dev increaseStake 函数执行成功时产生一个 IncreaseStake 事件
 */
event IncreaseStake(bytes32 indexed identifier, uint64 votePower);

/**
 * @dev retire 函数执行成功时产生一个 Retire 事件
 */
event Retire(bytes32 indexed identifier, uint64 votePower);
}