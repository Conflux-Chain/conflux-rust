// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::account_entry::OverlayAccount;
use crate::{hash::KECCAK_EMPTY, parameters::staking::*};
use cfx_types::{Address, H256, U256};
use primitives::{Account, DepositInfo, StakingVoteInfo};

#[test]
fn test_overlay_account_create() {
    let address = Address::zero();
    let account = Account {
        address,
        balance: 0.into(),
        nonce: 0.into(),
        code_hash: KECCAK_EMPTY,
        staking_balance: 0.into(),
        collateral_for_storage: 0.into(),
        accumulated_interest_return: 0.into(),
        deposit_list: Vec::new(),
        staking_vote_list: Vec::new(),
        admin: Address::zero(),
    };
    // test new from account 1
    let overlay_account = OverlayAccount::new(&address, account, 0);
    assert!(overlay_account.deposit_list().is_empty());
    assert!(overlay_account.staking_vote_list().is_empty());
    assert_eq!(*overlay_account.address(), address);
    assert_eq!(*overlay_account.balance(), 0.into());
    assert_eq!(*overlay_account.withdrawable_staking_balance(), 0.into());
    assert_eq!(*overlay_account.nonce(), 0.into());
    assert_eq!(*overlay_account.staking_balance(), 0.into());
    assert_eq!(*overlay_account.collateral_for_storage(), 0.into());
    assert_eq!(*overlay_account.accumulated_interest_return(), 0.into());
    assert_eq!(overlay_account.code_hash(), KECCAK_EMPTY);
    assert_eq!(overlay_account.reset_storage(), false);
    let account = Account {
        address,
        balance: 101.into(),
        nonce: 55.into(),
        code_hash: KECCAK_EMPTY,
        staking_balance: 11111.into(),
        collateral_for_storage: 455.into(),
        accumulated_interest_return: 2.into(),
        deposit_list: Vec::new(),
        staking_vote_list: Vec::new(),
        admin: Address::zero(),
    };

    // test new from account 2
    let overlay_account = OverlayAccount::new(&address, account, 1);
    assert!(overlay_account.deposit_list().is_empty());
    assert!(overlay_account.staking_vote_list().is_empty());
    assert_eq!(*overlay_account.address(), address);
    assert_eq!(*overlay_account.balance(), 101.into());
    assert_eq!(*overlay_account.nonce(), 55.into());
    assert_eq!(*overlay_account.staking_balance(), 11111.into());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        11111.into()
    );
    assert_eq!(*overlay_account.collateral_for_storage(), 455.into());
    assert_eq!(*overlay_account.accumulated_interest_return(), 2.into());
    assert_eq!(overlay_account.code_hash(), KECCAK_EMPTY);
    assert_eq!(overlay_account.reset_storage(), false);

    // test new basic
    let overlay_account =
        OverlayAccount::new_basic(&address, 1011.into(), 12345.into());
    assert!(overlay_account.deposit_list().is_empty());
    assert!(overlay_account.staking_vote_list().is_empty());
    assert_eq!(*overlay_account.address(), address);
    assert_eq!(*overlay_account.balance(), 1011.into());
    assert_eq!(*overlay_account.nonce(), 12345.into());
    assert_eq!(*overlay_account.staking_balance(), 0.into());
    assert_eq!(*overlay_account.withdrawable_staking_balance(), 0.into());
    assert_eq!(*overlay_account.collateral_for_storage(), 0.into());
    assert_eq!(*overlay_account.accumulated_interest_return(), 0.into());
    assert_eq!(overlay_account.code_hash(), KECCAK_EMPTY);
    assert_eq!(overlay_account.reset_storage(), false);
    assert_eq!(overlay_account.is_contract(), false);
    assert_eq!(overlay_account.is_basic(), true);

    // test new contract
    let mut overlay_account =
        OverlayAccount::new_contract(&address, 5678.into(), 1234.into(), true);
    assert!(overlay_account.deposit_list().is_empty());
    assert!(overlay_account.staking_vote_list().is_empty());
    assert_eq!(*overlay_account.address(), address);
    assert_eq!(*overlay_account.balance(), 5678.into());
    assert_eq!(*overlay_account.nonce(), 1234.into());
    assert_eq!(*overlay_account.staking_balance(), 0.into());
    assert_eq!(*overlay_account.withdrawable_staking_balance(), 0.into());
    assert_eq!(*overlay_account.collateral_for_storage(), 0.into());
    assert_eq!(*overlay_account.accumulated_interest_return(), 0.into());
    assert_eq!(overlay_account.code_hash(), KECCAK_EMPTY);
    assert_eq!(overlay_account.reset_storage(), true);
    assert_eq!(overlay_account.is_contract(), true);
    overlay_account.inc_nonce();
    assert_eq!(*overlay_account.nonce(), 1235.into());
}

#[test]
fn test_deposit_and_withdraw() {
    let address = Address::zero();
    let account = Account {
        address,
        balance: 0.into(),
        nonce: 0.into(),
        code_hash: KECCAK_EMPTY,
        staking_balance: 0.into(),
        collateral_for_storage: 0.into(),
        accumulated_interest_return: 0.into(),
        deposit_list: Vec::new(),
        staking_vote_list: Vec::new(),
        admin: Address::zero(),
    };
    let interest_rate_per_block =
        *INITIAL_ANNUAL_INTEREST_RATE / U256::from(BLOCKS_PER_YEAR);
    let mut overlay_account = OverlayAccount::new(&address, account, 0);
    // add balance 2 * 10^15
    overlay_account.add_balance(&2_000_000_000_000_000u64.into());
    assert_eq!(
        *overlay_account.balance(),
        U256::from(2_000_000_000_000_000u64)
    );
    assert_eq!(*overlay_account.staking_balance(), U256::zero());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::zero()
    );
    // deposit
    overlay_account.deposit(
        1_000_000_000_000_000u64.into(), /* amount */
        interest_rate_per_block,
        1, /* deposit_time */
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(1_000_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_000_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_000_000_000_000_000u64)
    );
    overlay_account.deposit(
        100_000_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(2),
        2, /* deposit_time */
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(900_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_100_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_100_000_000_000_000u64)
    );
    overlay_account.deposit(
        10_000_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(3),
        3, /* deposit_time */
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(890_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_110_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_110_000_000_000_000u64)
    );
    overlay_account.deposit(
        1_000_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(4),
        4, /* deposit_time */
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(889_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_111_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_111_000_000_000_000u64)
    );
    overlay_account.deposit(
        100_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(5),
        5, /* deposit_time */
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(888_900_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_111_100_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_111_100_000_000_000u64)
    );
    overlay_account.deposit(
        10_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(6),
        6, /* deposit_time */
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(888_890_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_111_110_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_111_110_000_000_000u64)
    );
    overlay_account.deposit(
        1_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(7),
        7, /* deposit_time */
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(888_889_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_111_111_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_111_111_000_000_000u64)
    );
    assert_eq!(overlay_account.deposit_list().len(), 7);

    // add storage
    assert_eq!(*overlay_account.collateral_for_storage(), U256::from(0));
    overlay_account.add_collateral_for_storage(&11116.into());
    assert_eq!(
        *overlay_account.collateral_for_storage(),
        U256::from(11_116)
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(888_888_999_988_884u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_111_111_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_111_111_000_000_000u64)
    );

    // sub storage
    overlay_account.sub_collateral_for_storage(&11116.into());
    assert_eq!(*overlay_account.collateral_for_storage(), U256::zero());
    assert_eq!(
        *overlay_account.balance(),
        U256::from(888_889_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(1_111_111_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(1_111_111_000_000_000u64)
    );

    // withdraw
    // 500_000_000_000_000 from `block_number = 1`
    let (interest, service_charge) = overlay_account.withdraw(
        500_000_000_000_000u64.into(), /* amount */
        interest_rate_per_block,
        1, /* withdraw_time */
    );
    assert_eq!(interest, U256::zero());
    assert_eq!(service_charge, U256::from(250_000_000_000u64));
    assert_eq!(*overlay_account.accumulated_interest_return(), U256::zero());
    assert_eq!(
        *overlay_account.balance(),
        U256::from(1_388_639_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(611_111_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(611_111_000_000_000u64)
    );
    assert_eq!(overlay_account.deposit_list().len(), 7);
    assert_eq!(
        overlay_account.deposit_list()[0].amount,
        U256::from(500_000_000_000_000u64)
    );

    // 500_000_000_000_000 from `block_number = 1`
    let (interest, service_charge) = overlay_account.withdraw(
        500_000_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(BLOCKS_PER_YEAR + 1),
        BLOCKS_PER_YEAR + 1, /* withdraw_time */
    );
    assert_eq!(interest, U256::from(20_000_000_000_000u64));
    assert_eq!(service_charge, U256::zero());
    assert_eq!(
        *overlay_account.accumulated_interest_return(),
        U256::from(20_000_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(1_908_639_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(111_111_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(111_111_000_000_000u64)
    );
    assert_eq!(overlay_account.deposit_list().len(), 6);
    assert_eq!(
        overlay_account.deposit_list()[0].amount,
        U256::from(100_000_000_000_000u64)
    );

    // 100_000_000_000_000 from `block_number = 2`
    // 10_000_000_000_000 from `block_number = 3`
    // 250_000_000_000 from `block_number = 4`
    let (interest, service_charge) = overlay_account.withdraw(
        110_250_000_000_000u64.into(), /* amount */
        interest_rate_per_block * U256::from(100),
        100, /* withdraw_time */
    );
    assert_eq!(interest, U256::from(6_845_508u64));
    assert_eq!(service_charge, U256::from(55_124_914_430u64));
    assert_eq!(
        *overlay_account.accumulated_interest_return(),
        U256::from(20_000_006_845_508u64)
    );
    assert_eq!(
        *overlay_account.balance(),
        U256::from(2_018_833_881_931_078u64)
    );
    assert_eq!(
        *overlay_account.staking_balance(),
        U256::from(861_000_000_000u64)
    );
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(861_000_000_000u64)
    );
    assert_eq!(overlay_account.deposit_list().len(), 4);
    assert_eq!(
        overlay_account.deposit_list()[0].amount,
        U256::from(750_000_000_000u64)
    );
}

fn check_ordered_feature(staking_vote_list: &Vec<StakingVoteInfo>) {
    for i in 1..staking_vote_list.len() {
        assert!(
            staking_vote_list[i - 1].unlock_time
                < staking_vote_list[i].unlock_time
        );
        assert!(staking_vote_list[i - 1].amount > staking_vote_list[i].amount);
    }
}

#[test]
fn test_vote_lock() {
    let address = Address::zero();
    let mut account = Account {
        address,
        balance: 0.into(),
        nonce: 0.into(),
        code_hash: KECCAK_EMPTY,
        staking_balance: 10000000.into(),
        collateral_for_storage: 0.into(),
        accumulated_interest_return: 0.into(),
        deposit_list: Vec::new(),
        staking_vote_list: Vec::new(),
        admin: Address::zero(),
    };
    account.deposit_list.push(DepositInfo {
        amount: 10000000.into(),
        deposit_time: 0,
        accumulated_interest_rate: 0.into(),
    });
    account.staking_vote_list.push(StakingVoteInfo {
        amount: 100000.into(),
        unlock_time: 10,
    });
    account.staking_vote_list.push(StakingVoteInfo {
        amount: 10000.into(),
        unlock_time: 30,
    });
    account.staking_vote_list.push(StakingVoteInfo {
        amount: 1000.into(),
        unlock_time: 100,
    });
    account.staking_vote_list.push(StakingVoteInfo {
        amount: 100.into(),
        unlock_time: 500,
    });

    let overlay_account = OverlayAccount::new(&address, account.clone(), 0);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9900000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 4);
    let overlay_account = OverlayAccount::new(&address, account.clone(), 10);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9990000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 3);
    let overlay_account = OverlayAccount::new(&address, account.clone(), 11);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9990000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 3);
    let overlay_account = OverlayAccount::new(&address, account.clone(), 30);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9999000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 2);
    let overlay_account = OverlayAccount::new(&address, account.clone(), 499);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9999900)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 1);
    let overlay_account = OverlayAccount::new(&address, account.clone(), 500);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(10000000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 0);

    let mut overlay_account = OverlayAccount::new(&address, account.clone(), 0);
    overlay_account.lock(U256::from(1000), 20);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9900000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 4);
    overlay_account.lock(U256::from(100000), 10);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9900000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 4);
    overlay_account.lock(U256::from(1000000), 11);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9000000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 4);
    assert_eq!(overlay_account.staking_vote_list()[0].unlock_time, 11);
    overlay_account.lock(U256::from(1000000), 13);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(9000000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 4);
    assert_eq!(overlay_account.staking_vote_list()[0].unlock_time, 13);
    overlay_account.lock(U256::from(2000000), 40);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(8000000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 3);
    assert_eq!(overlay_account.staking_vote_list()[0].unlock_time, 40);
    overlay_account.lock(U256::from(10), 600);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(8000000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 4);
    assert_eq!(overlay_account.staking_vote_list()[3].unlock_time, 600);
    overlay_account.lock(U256::from(1000), 502);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(8000000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 3);
    assert_eq!(overlay_account.staking_vote_list()[0].unlock_time, 40);
    assert_eq!(overlay_account.staking_vote_list()[1].unlock_time, 502);
    overlay_account.lock(U256::from(3000000), 550);
    check_ordered_feature(&overlay_account.staking_vote_list());
    assert_eq!(
        *overlay_account.withdrawable_staking_balance(),
        U256::from(7000000)
    );
    assert_eq!(overlay_account.staking_vote_list().len(), 2);
    assert_eq!(overlay_account.staking_vote_list()[0].unlock_time, 550);
    assert_eq!(overlay_account.staking_vote_list()[1].unlock_time, 600);
}

#[test]
fn test_clone_overwrite() {
    let address = Address::zero();
    let account1 = Account {
        address,
        balance: 1000.into(),
        nonce: 123.into(),
        code_hash: KECCAK_EMPTY,
        staking_balance: 10000000.into(),
        collateral_for_storage: 23.into(),
        accumulated_interest_return: 456.into(),
        deposit_list: vec![DepositInfo {
            amount: 1234.into(),
            deposit_time: 333,
            accumulated_interest_rate: 5.into(),
        }],
        staking_vote_list: vec![StakingVoteInfo {
            amount: 1236.into(),
            unlock_time: 335,
        }],
        admin: Address::zero(),
    };

    let account2 = Account {
        address,
        balance: 1001.into(),
        nonce: 124.into(),
        code_hash: KECCAK_EMPTY,
        staking_balance: 10000001.into(),
        collateral_for_storage: 24.into(),
        accumulated_interest_return: 457.into(),
        deposit_list: vec![DepositInfo {
            amount: 1235.into(),
            deposit_time: 334,
            accumulated_interest_rate: 6.into(),
        }],
        staking_vote_list: vec![StakingVoteInfo {
            amount: 1237.into(),
            unlock_time: 338,
        }],
        admin: Address::zero(),
    };

    let mut overlay_account1 =
        OverlayAccount::new(&address, account1.clone(), 0);
    let mut overlay_account2 =
        OverlayAccount::new(&address, account2.clone(), 0);
    assert_eq!(account1, overlay_account1.as_account());
    assert_eq!(account2, overlay_account2.as_account());

    overlay_account1.set_storage(H256::zero(), H256::zero(), address);
    assert_eq!(account1, overlay_account1.as_account());
    assert_eq!(overlay_account1.storage_changes().len(), 1);
    assert_eq!(overlay_account1.ownership_changes().len(), 1);
    let overlay_account = overlay_account1.clone_basic();
    assert_eq!(account1, overlay_account.as_account());
    assert_eq!(overlay_account.storage_changes().len(), 0);
    assert_eq!(overlay_account.ownership_changes().len(), 0);
    let overlay_account = overlay_account1.clone_dirty();
    assert_eq!(account1, overlay_account.as_account());
    assert_eq!(overlay_account.storage_changes().len(), 1);
    assert_eq!(overlay_account.ownership_changes().len(), 1);

    overlay_account2.set_storage(H256::zero(), H256::zero(), address);
    overlay_account2.set_storage(
        H256::from_low_u64_le(1),
        H256::zero(),
        address,
    );
    overlay_account1.overwrite_with(overlay_account2);
    assert_ne!(account1, overlay_account1.as_account());
    assert_eq!(account2, overlay_account1.as_account());
    assert_eq!(overlay_account1.storage_changes().len(), 2);
    assert_eq!(overlay_account1.ownership_changes().len(), 2);
}
