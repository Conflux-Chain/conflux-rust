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
        let max_timeout = Duration::from_secs(1200);
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
        let multi_genesis_txgen = Arc::new(TransactionGenerator::new(
            consensus.clone(),
            txpool.clone(),
            sync.clone(),
            secret_store.clone(),
        ));
        if txgen_conf.generate_tx {
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
            multi_genesis_txgen.set_join_handle(join_handle);
        }
        Some(multi_genesis_txgen)
    } else {
        None
    };

    (maybe_multi_genesis_txgen, maybe_direct_txgen_with_contract)
}

pub mod delegate_convert {
    use crate::rpc::{
        error_codes::{codes::EXCEPTION_ERROR, invalid_params},
        JsonRpcErrorKind, RpcError, RpcErrorKind, RpcResult,
    };
    use jsonrpc_core::{
        futures::{future::IntoFuture, Future},
        BoxFuture, Error as JsonRpcError, Result as JsonRpcResult,
    };

    pub trait Into<T> {
        fn into(x: Self) -> T;
    }

    impl<T> Into<JsonRpcResult<T>> for JsonRpcResult<T> {
        fn into(x: Self) -> JsonRpcResult<T> { x }
    }

    impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for BoxFuture<T> {
        fn into(x: Self) -> BoxFuture<T> { x }
    }

    impl Into<JsonRpcError> for RpcError {
        fn into(e: Self) -> JsonRpcError {
            match e.0 {
                JsonRpcErrorKind(j) => j,
                RpcErrorKind::InvalidParam(param, details) => {
                    invalid_params(&param, details)
                }
                RpcErrorKind::Msg(_)
                | RpcErrorKind::Decoder(_)
                | RpcErrorKind::FilterError(_)
                | RpcErrorKind::Storage(_) => JsonRpcError {
                    code: jsonrpc_core::ErrorCode::ServerError(EXCEPTION_ERROR),
                    message: format!("Error processing request: {}", e),
                    data: None,
                },
                // We exhausted all possible ErrorKinds here, however
                // https://stackoverflow.com/questions/36440021/whats-purpose-of-errorkind-nonexhaustive
                _ => unreachable!(),
            }
        }
    }

    pub fn into_jsonrpc_result<T>(r: RpcResult<T>) -> JsonRpcResult<T> {
        match r {
            Ok(t) => Ok(t),
            Err(e) => Err(Into::into(e)),
        }
    }

    impl<T> Into<JsonRpcResult<T>> for RpcResult<T> {
        fn into(x: Self) -> JsonRpcResult<T> { into_jsonrpc_result(x) }
    }

    /// Sometimes an rpc method is implemented asynchronously, then the rpc
    /// trait definition must use BoxFuture for the return type.
    ///
    /// This into conversion allow non-async rpc implementation method to
    /// return RpcResult straight-forward. The delegate! macro with  #[into]
    /// attribute will automatically call this method to do the return type
    /// conversion.
    impl<T: Send + Sync + 'static> Into<BoxFuture<T>> for RpcResult<T> {
        fn into(x: Self) -> BoxFuture<T> {
            into_jsonrpc_result(x).into_future().boxed()
        }
    }

    /*
    /// It's a bad idea to convert a BoxFuture return type to a JsonRpcResult
    /// return type for rpc call. Simply imagine how the code below runs.
    impl<T: Send + Sync + 'static> Into<JsonRpcResult<T>> for BoxFuture<T> {
        fn into(x: Self) -> JsonRpcResult<T> {
            thread::Builder::new()
                .name("rpc async waiter".into())
                .spawn(move || x.wait())
                .map_err(|e| {
                    let mut rpc_err = JsonRpcError::internal_error();
                    rpc_err.message = format!("thread creation error: {}", e);

                    rpc_err
                })?
                .join()
                .map_err(|_| {
                    let mut rpc_err = JsonRpcError::internal_error();
                    rpc_err.message = format!("thread join error.");

                    rpc_err
                })?
        }
    }
    */
}

pub use crate::configuration::Configuration;
use cfx_types::U256;
use cfxcore::{
    block_data_manager::BlockDataManager, genesis::DEV_GENESIS_KEY_PAIR_2,
    ConsensusGraph, Stopable, SynchronizationService, TransactionPool,
};
use cfxkey::public_to_address;
use keylib::KeyPair;
use parking_lot::Mutex;
use secret_store::SharedSecretStore;
use std::{
    sync::{Arc, Weak},
    thread,
};
use txgen::{DirectTransactionGenerator, TransactionGenerator};
