use crate::transaction_pool::TransactionPoolError;

use super::{DeferredPool, InsertResult, TxWithReadyInfo};
use crate::keylib::{Generator, KeyPair, Random};
use cfx_types::{Address, AddressSpaceUtil, Space, U256};
use primitives::{
    transaction::{native_transaction::NativeTransaction, Eip155Transaction},
    Action, SignedTransaction, Transaction,
};
use std::sync::Arc;

fn new_test_tx(
    sender: &KeyPair, nonce: usize, gas_price: usize, gas: usize, value: usize,
    space: Space,
) -> Arc<SignedTransaction> {
    let tx: Transaction = match space {
        Space::Native => NativeTransaction {
            nonce: U256::from(nonce),
            gas_price: U256::from(gas_price),
            gas: U256::from(gas),
            action: Action::Call(Address::random()),
            value: U256::from(value),
            storage_limit: 0,
            epoch_height: 0,
            chain_id: 1,
            data: Vec::new(),
        }
        .into(),
        Space::Ethereum => Eip155Transaction {
            nonce: U256::from(nonce),
            gas_price: U256::from(gas_price),
            gas: U256::from(gas),
            action: Action::Call(Address::random()),
            value: U256::from(value),
            chain_id: Some(1),
            data: Vec::new(),
        }
        .into(),
    };
    Arc::new(tx.sign(sender.secret()))
}

fn new_test_tx_with_ready_info(
    sender: &KeyPair, nonce: usize, gas_price: usize, value: usize,
    packed: bool,
) -> TxWithReadyInfo {
    let gas = 50000;
    let transaction =
        new_test_tx(sender, nonce, gas_price, gas, value, Space::Native);
    TxWithReadyInfo::new(transaction, packed, U256::from(0), 0)
}

#[test]
fn test_deferred_pool_insert_and_remove() {
    let mut deferred_pool = DeferredPool::new_for_test();

    // insert txs of same sender
    let alice = Random.generate().unwrap();
    let alice_addr_s = alice.address().with_native_space();
    let bob = Random.generate().unwrap();
    let bob_addr_s = bob.address().with_native_space();
    let eva = Random.generate().unwrap();
    let eva_addr_s = eva.address().with_native_space();

    let alice_tx1 = new_test_tx_with_ready_info(
        &alice, 5, 10, 100, false, /* packed */
    );
    let alice_tx2 = new_test_tx_with_ready_info(
        &alice, 6, 10, 100, false, /* packed */
    );
    let bob_tx1 =
        new_test_tx_with_ready_info(&bob, 1, 10, 100, false /* packed */);
    let bob_tx2 =
        new_test_tx_with_ready_info(&bob, 2, 10, 100, false /* packed */);
    let bob_tx2_new =
        new_test_tx_with_ready_info(&bob, 2, 11, 100, false /* packed */);

    assert_eq!(
        deferred_pool.insert(alice_tx1.clone(), false /* force */),
        InsertResult::NewAdded
    );

    assert_eq!(deferred_pool.contain_address(&alice_addr_s), true);

    assert_eq!(deferred_pool.contain_address(&eva_addr_s), false);

    assert_eq!(deferred_pool.remove_lowest_nonce(&eva_addr_s), None);

    assert_eq!(deferred_pool.contain_address(&bob_addr_s), false);

    assert_eq!(
        deferred_pool.insert(alice_tx2.clone(), false /* force */),
        InsertResult::NewAdded
    );

    assert_eq!(deferred_pool.remove_lowest_nonce(&bob_addr_s), None);

    assert_eq!(
        deferred_pool.insert(bob_tx1.clone(), false /* force */),
        InsertResult::NewAdded
    );

    assert_eq!(deferred_pool.contain_address(&bob_addr_s), true);

    assert_eq!(
        deferred_pool.insert(bob_tx2.clone(), false /* force */),
        InsertResult::NewAdded
    );

    assert_eq!(
        deferred_pool.insert(bob_tx2_new.clone(), false /* force */),
        InsertResult::Updated(bob_tx2.clone())
    );

    assert_eq!(
        deferred_pool.insert(bob_tx2.clone(), false /* force */),
        InsertResult::Failed(TransactionPoolError::HigherGasPriceNeeded {
            expected: *bob_tx2_new.gas_price() + U256::one()
        })
    );

    assert_eq!(
        deferred_pool.get_lowest_nonce(&bob_addr_s),
        Some(&(1.into()))
    );

    assert_eq!(
        deferred_pool.remove_lowest_nonce(&bob_addr_s),
        Some(bob_tx1.clone())
    );

    assert_eq!(
        deferred_pool.get_lowest_nonce(&bob_addr_s),
        Some(&(2.into()))
    );

    assert_eq!(deferred_pool.contain_address(&bob_addr_s), true);

    assert_eq!(
        deferred_pool.remove_lowest_nonce(&bob_addr_s),
        Some(bob_tx2_new.clone())
    );

    assert_eq!(deferred_pool.get_lowest_nonce(&bob_addr_s), None);

    assert_eq!(deferred_pool.contain_address(&bob_addr_s), false);
}

#[test]
fn test_deferred_pool_recalculate_readiness() {
    let mut deferred_pool = super::DeferredPool::new_for_test();

    let alice = Random.generate().unwrap();
    let alice_addr_s = alice.address().with_native_space();

    let gas = 50000;
    let tx1 = new_test_tx_with_ready_info(
        &alice, 5, 10, 10000, true, /* packed */
    );
    let tx2 = new_test_tx_with_ready_info(
        &alice, 6, 10, 10000, true, /* packed */
    );
    let tx3 = new_test_tx_with_ready_info(
        &alice, 7, 10, 10000, true, /* packed */
    );
    let tx4 = new_test_tx_with_ready_info(
        &alice, 8, 10, 10000, false, /* packed */
    );
    let tx5 = new_test_tx_with_ready_info(
        &alice, 9, 10, 10000, false, /* packed */
    );
    let exact_cost = 4 * (gas * 10 + 10000);

    deferred_pool.insert(tx1.clone(), false /* force */);
    deferred_pool.insert(tx2.clone(), false /* force */);
    deferred_pool.insert(tx4.clone(), false /* force */);
    deferred_pool.insert(tx5.clone(), false /* force */);

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            5.into(),
            exact_cost.into(),
        ),
        None
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            7.into(),
            exact_cost.into(),
        ),
        None
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            8.into(),
            exact_cost.into(),
        ),
        Some(tx4.transaction.clone())
    );

    deferred_pool.insert(tx3.clone(), false /* force */);
    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            4.into(),
            exact_cost.into(),
        ),
        None
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            5.into(),
            exact_cost.into(),
        ),
        Some(tx4.transaction.clone())
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            7.into(),
            exact_cost.into(),
        ),
        Some(tx4.transaction.clone())
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            8.into(),
            exact_cost.into(),
        ),
        Some(tx4.transaction.clone())
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            9.into(),
            exact_cost.into(),
        ),
        Some(tx5.transaction.clone())
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            10.into(),
            exact_cost.into(),
        ),
        None
    );

    assert_eq!(
        deferred_pool.recalculate_readiness_with_local_info(
            &alice_addr_s,
            5.into(),
            (exact_cost - 1).into(),
        ),
        None
    );
}
