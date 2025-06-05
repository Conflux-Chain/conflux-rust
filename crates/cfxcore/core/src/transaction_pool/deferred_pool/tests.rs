use crate::transaction_pool::TransactionPoolError;

use super::{DeferredPool, InsertResult, TxWithReadyInfo};
use crate::{
    keylib::{Generator, KeyPair, Random},
    verification::PackingCheckResult,
};
use cfx_types::{Address, AddressSpaceUtil, AddressWithSpace, Space, U256};
use cfxkey::Secret;
use primitives::{
    transaction::{
        native_transaction::NativeTransaction, Eip155Transaction,
        TypedNativeTransaction,
    },
    Action, SignedTransaction, Transaction,
};
use std::{str::FromStr, sync::Arc};

const PRIVATE_KEY: &str =
    "74806d258099decd5f5bd500f5b318aaaa0a8a289f8dcb10a9609966d8a0e442";

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

pub fn const_account_with_native_space() -> AddressWithSpace {
    let secret = Secret::from_str(&PRIVATE_KEY).unwrap();
    let key_pair = KeyPair::from_secret(secret).unwrap();
    // return a Native Space address
    key_pair.address().with_native_space()
}

pub fn create_signed_transaction(
    nonce: U256, gas_limit: U256, gas_price: u64, sender: AddressWithSpace,
    private_key: &str,
) -> Result<SignedTransaction, Box<dyn std::error::Error>> {
    let secret = Secret::from_str(&private_key).unwrap();

    let receiver = &sender;
    // create a tx
    let typetx = TypedNativeTransaction::Cip155(NativeTransaction {
        nonce,
        gas_price: U256::from(gas_price),
        gas: U256::from(gas_limit),
        action: Action::Call(receiver.address),
        value: U256::from(1_000_000u64),
        storage_limit: 0_u64,
        epoch_height: 0,
        chain_id: 1, // Testnet chain ID
        data: vec![],
    });

    let transaction = Transaction::Native(typetx);
    // sign the tx
    let signed_tx = transaction.sign(&secret);

    Ok(signed_tx)
}

fn create_tx_with_ready_info(
    nonce: U256, gas_limit: U256, gas_price: u64, sender: AddressWithSpace,
    private_key: &str,
) -> TxWithReadyInfo {
    // 1.create signed_tx
    let signed_tx = create_signed_transaction(
        nonce,
        gas_limit,
        gas_price,
        sender,
        private_key,
    )
    .unwrap();

    // 2. create TxWithReadyInfo
    let transaction = Arc::new(signed_tx);
    let packed = false;
    let sponsored_gas = U256::from(0);
    let sponsored_storage = 0_u64;
    let tx_with_ready_info = TxWithReadyInfo::new(
        transaction,
        packed,
        sponsored_gas,
        sponsored_storage,
    );
    tx_with_ready_info
}

#[test]
fn test_packing_sampler_valid_transaction() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx1 = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        10000,
        addr,
        PRIVATE_KEY,
    );
    let tx_clone = tx1.clone();
    dpool.insert(tx1, false);

    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );
    assert!(dpool.has_ready_tx(&addr));
    let validity = |_: &SignedTransaction| PackingCheckResult::Pack;
    let (txs, gas_used, size_used) = dpool.packing_sampler(
        Space::Native,
        U256::from(15000000),
        40000,
        10,
        U256::from(20),
        validity,
    );

    assert_eq!(txs.len(), 1);
    assert_eq!(gas_used, U256::from(21000));
    assert!(size_used <= 15000000);
    assert_eq!(txs[0], tx_clone.transaction);
}

#[test]
fn test_insert_new_transaction() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );

    let result = dpool.insert(tx, false);
    assert!(matches!(result, InsertResult::NewAdded));
    assert!(dpool.contain_address(&addr));
    assert!(dpool.check_sender_and_nonce_exists(&addr, &U256::from(0)));
}

#[test]
fn test_insert_replace_transaction() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx1 = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    let tx2 = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        200,
        addr,
        PRIVATE_KEY,
    ); // Higher gas price

    dpool.insert(tx1, false);
    let result = dpool.insert(tx2, false);
    assert!(matches!(result, InsertResult::Updated(_)));
    assert_eq!(dpool.count_less(&addr, &U256::from(1)), 1);
}

#[test]
fn test_packing_sampler_empty_limits() {
    let mut dpool = DeferredPool::new_for_test();
    let validity = |_: &SignedTransaction| PackingCheckResult::Pack;
    let (txs, gas_used, size_used) = dpool.packing_sampler(
        Space::Native,
        U256::from(0),
        0,
        0,
        U256::from(50),
        validity,
    );

    assert!(txs.is_empty());
    assert_eq!(gas_used, U256::from(0));
    assert_eq!(size_used, 0);
}

#[test]
fn test_estimate_packing_gas_limit() {
    let dpool = DeferredPool::new_for_test();
    let (gas_limit, price_limit) = dpool.estimate_packing_gas_limit(
        Space::Native,
        U256::from(100_000),
        U256::from(100),
        U256::from(50),
    );

    assert!(gas_limit <= U256::from(200_000)); // gas_target * 2
    assert!(price_limit >= U256::from(50)); // At least min_base_price
}

#[test]
fn test_mark_packed() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );

    dpool.insert(tx, false);
    let result = dpool.mark_packed(addr, &U256::from(0), true);
    assert!(result);

    let result = dpool.check_tx_packed(addr, U256::from(0));
    assert!(result);
}

#[test]
fn test_remove_lowest_nonce() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx1 = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    let tx2 = create_tx_with_ready_info(
        U256::from(1),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );

    dpool.insert(tx1.clone(), false);
    dpool.insert(tx2, false);

    let removed = dpool.remove_lowest_nonce(&addr).unwrap();
    assert_eq!(removed.nonce(), &U256::from(0));
    assert_eq!(dpool.count_less(&addr, &U256::from(2)), 1);
}

#[test]
fn test_recalculate_readiness_with_local_info() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx1 = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    let tx2 = create_tx_with_ready_info(
        U256::from(1),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );

    dpool.insert(tx1, false);
    dpool.insert(tx2, false);

    let result = dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );
    assert!(result.is_some());
    assert!(dpool.has_ready_tx(&addr));
}

#[test]
fn test_get_bucket() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    dpool.insert(tx, false);
    let result = dpool.get_bucket(&addr).unwrap();
    let gas_limit = result.get_lowest_nonce_tx().unwrap().gas_limit();
    assert_eq!(*gas_limit, U256::from(21000));
}

#[test]
fn test_clear_bucket() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    dpool.insert(tx, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );
    assert!(!dpool.buckets.is_empty());
    assert!(dpool.packing_pool.in_space(Space::Native).len() == 1);
    dpool.clear();
    assert!(dpool.buckets.is_empty());
    assert!(dpool.packing_pool.in_space(Space::Native).len() == 0);
}
