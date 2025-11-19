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
use rand::RngCore;
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

pub struct TestAccount {
    pub private_key: String,
    pub account: AddressWithSpace,
}

impl TestAccount {
    pub fn new(private_key: String, account: AddressWithSpace) -> Self {
        TestAccount {
            private_key,
            account,
        }
    }
}

pub fn random_account_with_native_space() -> TestAccount {
    let secret = generate_conflux_private_key().unwrap();
    let key_pair = KeyPair::from_secret(secret.clone()).unwrap();
    // return a Native Space address and private key
    // Note: This is a random key pair, not the one from PRIVATE_KEY
    let pk_tmp = String::from(&secret.to_hex());
    let pk = &pk_tmp[..];
    TestAccount::new(String::from(pk), key_pair.address().with_native_space())
}

fn generate_conflux_private_key() -> Option<Secret> {
    let mut rng = rand::rng();
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Secret::from_slice(&bytes)
}

#[test]
fn test_500k_tx_packing() {
    let mut dpool = DeferredPool::new_for_test();
    for i in 0..500000 {
        let test_account = random_account_with_native_space();
        let addr = test_account.account;
        let pky = test_account.private_key;
        let tx = create_tx_with_ready_info(
            U256::from(i),
            U256::from(21000),
            100,
            addr,
            &pky,
        );
        dpool.insert(tx, false);
    }
    assert_eq!(dpool.buckets.len(), 500000);
}

#[test]
fn test_500kp_tx_packing() {
    let mut dpool = DeferredPool::new_for_test();
    for i in 0..500200 {
        let test_account = random_account_with_native_space();
        let addr = test_account.account;
        let pky = test_account.private_key;
        let tx = create_tx_with_ready_info(
            U256::from(i),
            U256::from(21000),
            100,
            addr,
            &pky,
        );
        dpool.insert(tx, false);
    }
    assert_eq!(dpool.buckets.len(), 500200);
}

#[test]
fn test_get_pending_info() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    let signtx = create_signed_transaction(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    )
    .unwrap();

    dpool.insert(tx, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );
    assert!(!dpool.buckets.is_empty());
    assert!(dpool.packing_pool.in_space(Space::Native).len() == 1);
    let pending_info = dpool.get_pending_info(&addr, &U256::from(0)).unwrap();
    assert!(pending_info.0 == 1);
    assert_eq!(pending_info.1, Arc::new(signtx));
}

#[test]
fn test_get_pending_tx() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );

    let tx1 = create_tx_with_ready_info(
        U256::from(1),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    let tx2 = create_tx_with_ready_info(
        U256::from(2),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    let tx_clone = tx.clone();
    dpool.insert(tx, false);
    dpool.insert(tx1, false);
    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );
    assert!(!dpool.buckets.is_empty());
    assert!(dpool.packing_pool.in_space(Space::Native).len() == 1);
    let pending_tx = dpool.get_pending_transactions(
        &addr,
        &U256::from(0),
        &U256::from(0),
        &U256::from(1_000_000_000_000_000u64),
    );
    assert_eq!(pending_tx.0.len(), 3);
    assert_eq!(pending_tx.0[0], &tx_clone);
}

#[test]
fn test_last_succ_nonce() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
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
    dpool.insert(tx, false);
    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(1),
        U256::from(1_000_000_000_000_000u64),
    );
    let result = dpool.last_succ_nonce(addr, U256::from(0));
    assert_eq!(result.unwrap(), U256::from(2));
}

#[test]
fn test_ready_account_number() {
    let mut dpool = DeferredPool::new_for_test();
    for _i in 0..200 {
        let test_account = random_account_with_native_space();
        let addr = test_account.account;
        let pky = test_account.private_key;
        let tx = create_tx_with_ready_info(
            U256::from(0),
            U256::from(21000),
            100,
            addr,
            &pky,
        );
        dpool.insert(tx, false);

        dpool.recalculate_readiness_with_local_info(
            &addr,
            U256::from(0),
            U256::from(1_000_000_000_000_000u64),
        );
    }

    let result = dpool.ready_account_number(Space::Native);
    assert_eq!(result, 200);
    dpool.clear();
    let result1 = dpool.ready_account_number(Space::Native);
    assert_eq!(result1, 0);
}

#[test]
fn test_ready_transaction_hashes() {
    let mut dpool = DeferredPool::new_for_test();
    let result0 = dpool.ready_transaction_hashes(Space::Native);
    assert_eq!(result0.into_iter().count(), 0);

    for _i in 0..10 {
        let test_account = random_account_with_native_space();
        let addr = test_account.account;
        let pky = test_account.private_key;
        let tx = create_tx_with_ready_info(
            U256::from(0),
            U256::from(21000),
            100,
            addr,
            &pky,
        );
        dpool.insert(tx, false);

        dpool.recalculate_readiness_with_local_info(
            &addr,
            U256::from(0),
            U256::from(1_000_000_000_000_000u64),
        );
    }

    let result1 = dpool.ready_transaction_hashes(Space::Native);
    assert_eq!(result1.into_iter().count(), 10);
    dpool.clear();
    let result2 = dpool.ready_transaction_hashes(Space::Native);
    assert_eq!(result2.into_iter().count(), 0);
}

#[test]
fn test_ready_transactions_by_space() {
    let mut dpool = DeferredPool::new_for_test();
    let result0 = dpool.ready_transaction_hashes(Space::Native);
    assert_eq!(result0.into_iter().count(), 0);

    for _i in 0..10 {
        let test_account = random_account_with_native_space();
        let addr = test_account.account;
        let pky = test_account.private_key;
        let tx = create_tx_with_ready_info(
            U256::from(0),
            U256::from(21000),
            100,
            addr,
            &pky,
        );
        dpool.insert(tx, false);

        dpool.recalculate_readiness_with_local_info(
            &addr,
            U256::from(0),
            U256::from(1_000_000_000_000_000u64),
        );
    }

    let result1 = dpool.ready_transactions_by_space(Space::Native);
    assert_eq!(result1.into_iter().count(), 10);
    dpool.clear();
    let result2 = dpool.ready_transactions_by_space(Space::Native);
    assert_eq!(result2.into_iter().count(), 0);
}

#[test]
fn test_has_ready_tx() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    assert!(!dpool.has_ready_tx(&addr));
    let tx = create_tx_with_ready_info(
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
    dpool.insert(tx, false);
    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(1),
        U256::from(1_000_000_000_000_000u64),
    );
    assert!(dpool.has_ready_tx(&addr));
    dpool.clear();
    assert!(!dpool.has_ready_tx(&addr));
}

#[test]
fn test_ready_transactions_by_address() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
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
    dpool.insert(tx, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );

    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(1),
        U256::from(1_000_000_000_000_000u64),
    );
    dpool.mark_packed(addr, &U256::from(0), true);
    let result = dpool.ready_transactions_by_address(addr).unwrap();
    assert!(result.len() == 2);
    dpool.clear();
    let result2 = dpool.ready_transactions_by_address(addr);
    assert!(result2 == None);
}

#[test]
fn test_all_ready_transactions() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
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
    dpool.insert(tx, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );

    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(1),
        U256::from(1_000_000_000_000_000u64),
    );
    let result = dpool.all_ready_transactions().count();
    assert_eq!(result, 2);
    dpool.clear();
    let result2 = dpool.ready_transactions_by_address(addr);
    assert!(result2 == None);
}

#[test]
fn test_pending_tx_number() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
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
    dpool.insert(tx, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );

    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(1),
        U256::from(1_000_000_000_000_000u64),
    );

    let get_nonce_and_balance = |addr: &AddressWithSpace| {
        if addr.space == Space::Native {
            (U256::from(0), U256::from(1_000_000_000_000_000u64))
        } else {
            (U256::from(1), U256::from(1_000_000_000_000_000u64))
        }
    };
    let result =
        dpool.pending_tx_number(Some(Space::Native), get_nonce_and_balance);
    assert_eq!(result, 2);
    dpool.clear();
    let result2 =
        dpool.pending_tx_number(Some(Space::Native), get_nonce_and_balance);
    assert!(result2 == 0);
}

#[test]
fn test_eth_content() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
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
    dpool.insert(tx, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );

    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(1),
        U256::from(1_000_000_000_000_000u64),
    );

    let get_nonce_and_balance = |addr: &AddressWithSpace| {
        if addr.space == Space::Native {
            (U256::from(0), U256::from(1_000_000_000_000_000u64))
        } else {
            (U256::from(1), U256::from(1_000_000_000_000_000u64))
        }
    };
    let (result1, _result2) =
        dpool.eth_content(Some(Space::Native), get_nonce_and_balance);
    assert_eq!(result1.get(&addr).unwrap().len(), 2);

    dpool.clear();
    let (_result3, result4) =
        dpool.eth_content(Some(Space::Native), get_nonce_and_balance);
    assert!(result4.len() == 0);
}

#[test]
fn test_eth_content_from() {
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let tx = create_tx_with_ready_info(
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
    dpool.insert(tx, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );

    dpool.insert(tx2, false);
    dpool.recalculate_readiness_with_local_info(
        &addr,
        U256::from(1),
        U256::from(1_000_000_000_000_000u64),
    );

    let (result1, _result2) = dpool.eth_content_from(
        addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );
    assert_eq!(result1.get(&U256::from(0)).unwrap().nonce(), &U256::from(0));
    assert_eq!(result1.len(), 2);
    dpool.clear();
    let (_result3, result4) = dpool.eth_content_from(
        addr,
        U256::from(0),
        U256::from(1_000_000_000_000_000u64),
    );
    assert!(result4.len() == 0);
}

#[test]
fn test_is_in_packing_pool_and_diagnosis() {
    // 测试场景：
    // 1. 插入三个连续nonce的交易（0, 1, 2），使其都进入packing_pool
    // 2. 删除nonce 0，使nonce 1不在packing_pool中
    // 3. 验证is_in_packing_pool()的返回值
    // 4. 调用log_packing_pool_diagnosis()观察诊断输出
    
    let mut dpool = DeferredPool::new_for_test();
    let addr = const_account_with_native_space();
    let state_nonce = U256::from(0);
    let state_balance = U256::from(1_000_000_000_000_000u64);
    
    // 创建三个交易
    let tx0 = create_tx_with_ready_info(
        U256::from(0),
        U256::from(21000),
        100,
        addr,
        PRIVATE_KEY,
    );
    let tx1 = create_tx_with_ready_info(
        U256::from(1),
        U256::from(21000),
        105,
        addr,
        PRIVATE_KEY,
    );
    let tx2 = create_tx_with_ready_info(
        U256::from(2),
        U256::from(21000),
        110,
        addr,
        PRIVATE_KEY,
    );
    
    // 插入交易
    dpool.insert(tx0.clone(), false);
    dpool.insert(tx1.clone(), false);
    dpool.insert(tx2.clone(), false);
    
    // 计算就绪性，使所有交易进入packing_pool
    dpool.recalculate_readiness_with_local_info(&addr, state_nonce, state_balance);
    
    // 验证：所有交易都在packing_pool中
    assert!(dpool.is_in_packing_pool(&addr, &U256::from(0)));
    assert!(dpool.is_in_packing_pool(&addr, &U256::from(1)));
    assert!(dpool.is_in_packing_pool(&addr, &U256::from(2)));
    
    // 删除nonce 0
    dpool.remove_lowest_nonce(&addr);

    // 验证：nonce 0已删除，nonce 1在packing_pool中
    assert!(!dpool.is_in_packing_pool(&addr, &U256::from(0)));
    assert!(dpool.is_in_packing_pool(&addr, &U256::from(1)));
    assert!(dpool.is_in_packing_pool(&addr, &U256::from(2)));

       // 输出诊断信息
    dpool.log_packing_pool_diagnosis(
        &addr,
        state_nonce,  // state_nonce 仍然是 0
        state_balance,
    );
    
    //let state_nonce = U256::from(1);
    // 重新计算，此时state_nonce为0（链上还未执行）
    // 但因为bucket中的最低nonce变成了1，所以nonce 1不再连续，不在packing_pool中
    dpool.recalculate_readiness_with_local_info(
        &addr,
        state_nonce,  // state_nonce 仍然是 0
        state_balance,
    );
    
    // 验证：nonce 0已删除，nonce 1不在packing_pool中
    assert!(!dpool.is_in_packing_pool(&addr, &U256::from(0)));
    assert!(!dpool.is_in_packing_pool(&addr, &U256::from(1)));
    // nonce 2仍然在packing_pool中
    assert!(dpool.is_in_packing_pool(&addr, &U256::from(2)));
    
    // 调用诊断方法，打印诊断信息
    println!("\n========== Test: is_in_packing_pool and log_packing_pool_diagnosis ==========");
    
    // 输出诊断信息
    dpool.log_packing_pool_diagnosis(
        &addr,
        state_nonce,  // state_nonce为2
        state_balance,
    );
    println!("=====================================================================\n");
}


