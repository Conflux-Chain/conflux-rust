// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

/// Hold all top-level components for a type of client.
/// This struct implement ClientShutdownTrait.
pub struct ClientComponents<BlockGenT, Rest> {
    pub data_manager_weak_ptr: Weak<BlockDataManager>,
    pub blockgen: Option<Arc<BlockGenT>>,
    pub other_components: Rest,
}

impl<BlockGenT: 'static + Stopable, Rest> ClientTrait
    for ClientComponents<BlockGenT, Rest>
{
    fn take_out_components_for_shutdown(
        &self,
    ) -> (Weak<BlockDataManager>, Option<Arc<dyn Stopable>>) {
        let data_manager_weak_ptr = self.data_manager_weak_ptr.clone();
        let blockgen: Option<Arc<dyn Stopable>> = match self.blockgen.clone() {
            Some(blockgen) => Some(blockgen),
            None => None,
        };

        (data_manager_weak_ptr, blockgen)
    }
}

pub trait ClientTrait {
    fn take_out_components_for_shutdown(
        &self,
    ) -> (Weak<BlockDataManager>, Option<Arc<dyn Stopable>>);
}

pub mod client_methods {
    pub fn run(
        this: Box<dyn ClientTrait>, exit_cond_var: Arc<(Mutex<bool>, Condvar)>,
    ) -> bool {
        CtrlC::set_handler({
            let e = exit_cond_var.clone();
            move || {
                *e.0.lock() = true;
                e.1.notify_all();
            }
        });

        let mut lock = exit_cond_var.0.lock();
        if !*lock {
            exit_cond_var.1.wait(&mut lock);
        }

        shutdown(this)
    }

    /// Returns whether the shutdown is considered clean.
    pub fn shutdown(this: Box<dyn ClientTrait>) -> bool {
        let (ledger_db, maybe_blockgen) =
            this.take_out_components_for_shutdown();
        drop(this);
        if let Some(blockgen) = maybe_blockgen {
            blockgen.stop();
            drop(blockgen);
        }

        // Make sure ledger_db is properly dropped, so rocksdb can be closed
        // cleanly
        check_graceful_shutdown(ledger_db)
    }

    /// Most Conflux components references block data manager.
    /// When block data manager is freed, all background threads must have
    /// already stopped.
    fn check_graceful_shutdown(
        blockdata_manager_weak_ptr: Weak<BlockDataManager>,
    ) -> bool {
        let sleep_duration = Duration::from_secs(1);
        let warn_timeout = Duration::from_secs(5);
        let max_timeout = Duration::from_secs(10);
        let instant = Instant::now();
        let mut warned = false;
        while instant.elapsed() < max_timeout {
            if blockdata_manager_weak_ptr.upgrade().is_none() {
                return true;
            }
            if !warned && instant.elapsed() > warn_timeout {
                warned = true;
                warn!("Shutdown is taking longer than expected.");
            }
            thread::sleep(sleep_duration);
        }
        eprintln!("Shutdown timeout reached, exiting uncleanly.");
        false
    }
    use super::ClientTrait;
    use cfxcore::block_data_manager::BlockDataManager;
    use ctrlc::CtrlC;
    use parking_lot::{Condvar, Mutex};
    use std::{
        sync::{Arc, Weak},
        thread,
        time::{Duration, Instant},
    };
}

pub fn initialize_txgens(
    consensus: Arc<ConsensusGraph>, txpool: Arc<TransactionPool>,
    sync: Arc<SynchronizationService>, secret_store: SharedSecretStore,
    conf: &Configuration, network_key_pair: KeyPair,
) -> (
    Option<Arc<TransactionGenerator>>,
    Option<Arc<Mutex<DirectTransactionGenerator>>>,
)
{
    // This tx generator directly push simple transactions and erc20
    // transactions into blocks.
    let maybe_direct_txgen_with_contract = if conf.is_test_or_dev_mode() {
        Some(Arc::new(Mutex::new(DirectTransactionGenerator::new(
            network_key_pair,
            &public_to_address(DEV_GENESIS_KEY_PAIR_2.public()),
            U256::from_dec_str("10000000000000000").unwrap(),
            U256::from_dec_str("10000000000000000").unwrap(),
        ))))
    } else {
        None
    };

    // This tx generator generates transactions from preconfigured multiple
    // genesis accounts and it pushes transactions into transaction pool.
    let maybe_multi_genesis_txgen = if let Some(txgen_conf) =
        conf.tx_gen_config()
    {
        let mut multi_genesis_txgen = Arc::new(TransactionGenerator::new(
            consensus.clone(),
            txpool.clone(),
            sync.clone(),
            secret_store.clone(),
        ));

        let txgen_clone = multi_genesis_txgen.clone();
        let join_handle =
            thread::Builder::new()
                .name("txgen".into())
                .spawn(move || {
                    TransactionGenerator::generate_transactions_with_multiple_genesis_accounts(
                        txgen_clone,
                        txgen_conf,
                    );
                })
                .expect("should succeed");
        Arc::get_mut(&mut multi_genesis_txgen)
            .unwrap()
            .set_join_handle(join_handle);
        Some(multi_genesis_txgen)
    } else {
        None
    };

    (maybe_multi_genesis_txgen, maybe_direct_txgen_with_contract)
}

pub use crate::configuration::Configuration;
use cfx_types::U256;
use cfxcore::{
    block_data_manager::BlockDataManager, genesis::DEV_GENESIS_KEY_PAIR_2,
    ConsensusGraph, Stopable, SynchronizationService, TransactionPool,
};
use ethkey::public_to_address;
use keylib::KeyPair;
use parking_lot::Mutex;
use secret_store::SharedSecretStore;
use std::{
    sync::{Arc, Weak},
    thread,
};
use txgen::{DirectTransactionGenerator, TransactionGenerator};
