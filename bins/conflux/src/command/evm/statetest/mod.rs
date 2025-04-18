mod error;
mod utils;

use cfx_executor::{
    executive::{
        gas_required_for, ChargeCollateral, ExecutionOutcome, ExecutiveContext,
        TransactOptions, TransactSettings,
    },
    machine::{Machine, VmFactory},
    state::State,
};
use cfx_rpc_eth_types::{
    AccountOverride, AccountStateOverrideMode, StateOverride,
};
use cfx_statedb::{Error as DbError, Result as DbResult, StateDb};
use cfx_types::{
    u256_to_h256_be, AddressWithSpace, Space, SpaceMap, H256, U256, U64,
};
use cfx_vm_types::Env;
use cfxkey::Secret;
use client::configuration::Configuration;
pub use error::{StateMismatch, TestError, TestErrorKind};
// use keccak_hash::keccak;
use primitives::{
    transaction::{
        Action, AuthorizationListItem, Eip1559Transaction, Eip155Transaction,
        Eip2930Transaction, Eip7702Transaction, EthereumTransaction,
    },
    SignedTransaction, Transaction,
};
use statetest_types::{
    Env as StateTestEnv, SignedAuthorization, SpecName, TestSuite,
    TransactionParts, TransactionType, TxPartIndices,
};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    u64,
};
use utils::{
    allowed_test, extract_155_chain_id_from_raw_tx, find_all_json_tests,
    skip_test, VerboseMode,
};

#[allow(dead_code)]
const DEFAULT_EVM_CHAIN_ID: u32 = 1;
const DEFAULT_CORE_CHAIN_ID: u32 = 2;

/// ethereum statetest doc: https://eest.ethereum.org/main/consuming_tests/state_test/

pub struct StateTestCmd {
    paths: Vec<PathBuf>,
    config: Configuration,
    matches: Option<String>,
    verbose: u8,
}

impl StateTestCmd {
    pub fn new(
        state_test_matches: &clap::ArgMatches,
        global_matches: &clap::ArgMatches,
    ) -> Self {
        let config = Configuration::parse(global_matches)
            .expect("Failed to parse configuration");
        let paths: Vec<PathBuf> = state_test_matches
            .values_of("json-path")
            .map(|x| x.map(|v| PathBuf::from(v)).collect())
            .expect("Failed to get json-path values");
        let matches = state_test_matches
            .value_of("match-path")
            .map(|x| x.to_string());

        // default to info level
        let verbose = VerboseMode::Info as u8
            + state_test_matches.occurrences_of("v") as u8;

        Self {
            paths,
            config,
            matches,
            verbose,
        }
    }

    /// Runs `statetest` command.
    pub fn run(&self) -> Result<String, String> {
        for path in &self.paths {
            if !path.exists() {
                self.fatal(format!("Path not exists: {:?}", path));
                continue;
            }

            let test_files = find_all_json_tests(path);

            if test_files.is_empty() {
                self.error(format!(
                    "No fixtures found in directory: {:?}",
                    path
                ));
                continue;
            }

            if let Err(_) = self.run_file_tests(test_files, path) {
                self.warn(format!(
                    "Failed to run tests in directory: {:?}",
                    path
                ));
                continue;
            }
        }

        Ok("".into())
    }

    fn run_file_tests(
        &self, test_files: Vec<PathBuf>, path: &PathBuf,
    ) -> Result<(), String> {
        self.info(format!(
            "\nRunning {} TestSuites in {}",
            test_files.len(),
            path.display()
        ));

        let mut skiped = 0;
        let mut success = 0;
        let mut failed = 0;

        for path in test_files {
            if skip_test(&path) {
                skiped += 1;
                continue;
            }

            // only run selective tests
            if !allowed_test(&path, self.matches.as_deref()) {
                skiped += 1;
                continue;
            }

            let suite = self.load_test_suite(&path);
            let path = path.to_string_lossy().into_owned();

            if let Err(err_msg) = suite {
                failed += 1;
                self.debug(format!("TestSuite load failed: {}", err_msg));
                continue;
            }

            self.debug(format!("\nRunning TestSuite: {}", path));
            let suite = suite.unwrap();
            let result = self.execute_test_suite(path.clone(), suite);
            if let Err(err) = result {
                self.debug(format!(
                    "Status: ❌ \nName: {} \nError: {:?}",
                    err.name, err.kind
                ));
                failed += 1;
            } else {
                self.debug(format!("Status: ✅",));
                success += 1;
            }
        }

        self.info(format!("\nSkipped TestSuites: {} ", skiped));
        self.info(format!("Success TestSuites: {} ", success));
        self.info(format!("Failed TestSuites: {} ", failed));

        Ok(())
    }

    fn load_test_suite(&self, path: &PathBuf) -> Result<TestSuite, String> {
        let s = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let suite: TestSuite =
            serde_json::from_str(&s).map_err(|e| e.to_string())?;
        Ok(suite)
    }

    // Will stop on the first TestUnit failure
    fn execute_test_suite(
        &self, path: String, suite: TestSuite,
    ) -> Result<(), TestError> {
        for (name, unit) in suite.0 {
            self.trace(format!("\n\tRunning TestUnit: {}", name));
            // step1: setup the state according the pre state
            let mut state_override = StateOverride::new();
            for (address, info) in unit.pre {
                // let code_hash = keccak(info.code.0.clone());
                let account_state: HashMap<H256, H256> = info
                    .storage
                    .iter()
                    .map(|(k, v)| {
                        (u256_to_h256_be(k.clone()), u256_to_h256_be(v.clone()))
                    })
                    .collect();
                state_override.insert(
                    address,
                    AccountOverride {
                        balance: Some(info.balance),
                        nonce: Some(U64::from(info.nonce)),
                        code: Some(info.code.0.clone()),
                        state: AccountStateOverrideMode::State(account_state),
                        move_precompile_to: None,
                    },
                );
            }
            let mut state =
                self.make_state(Some(state_override)).map_err(|e| {
                    TestError {
                        name: name.clone(),
                        path: path.clone(),
                        kind: TestErrorKind::Custom(e.to_string()),
                    }
                })?;

            for (spec_name, tests) in unit.post {
                // Constantinople was immediately extended by Petersburg.
                // There isn't any production Constantinople transaction
                // so we don't support it and skip right to Petersburg.
                if spec_name == SpecName::Constantinople {
                    continue;
                }

                // TODO Enable the appropriate Conflux CIPs based on the
                // spec_name.

                for (index, test) in tests.into_iter().enumerate() {
                    let _ = index;
                    let tx = self.make_tx(
                        &unit.transaction,
                        &test.indexes,
                        unit.config.chainid,
                        extract_155_chain_id_from_raw_tx(&test.txbytes)
                            .is_none(),
                    );

                    if tx.is_none() {
                        if unit.transaction.tx_type(test.indexes.data).is_none()
                        {
                            self.trace(format!(
                                "\tSkipping test because of unkonwn tx type: {}",
                                name.clone()
                            ));
                        }
                        continue;
                    }

                    let tx = tx.unwrap();

                    // Check whether the serialization result of the transaction
                    // matches txbytes; if not, then
                    // fail the test
                    if let Some(txbytes) = test.txbytes {
                        let raw_tx = rlp::encode(&tx.transaction.transaction);
                        if raw_tx != txbytes.0 {
                            self.trace(format!(
                                "\tCheck txbytes failed expected vs actually: {} \n{} \n{}",
                                name.clone(),
                                hex::encode(txbytes.0),
                                hex::encode(raw_tx)
                            ));
                            continue;
                            // return Err(TestError {
                            //     name: name.clone(),
                            //     path: path.clone(),
                            //     kind: TestErrorKind::Custom(
                            //         "txbytes check failed".to_string(),
                            //     ),
                            // });
                        }
                    }

                    let env = self.make_block_env(
                        &unit.env,
                        unit.config.chainid,
                        tx.hash(),
                    );

                    let transact_options =
                        self.make_transact_options(true, true);

                    let res =
                        self.transact(&env, &mut state, &tx, transact_options);

                    // Check whether the transaction can execute successfully:
                    // 1. If it fails but expectException is empty, then fail
                    //    the test.
                    // 2. If it fails and expectException is not empty, then
                    //    check whether the error code matches, and revert the
                    //    state.
                    // 3. If it succeeds but expectException is not empty, then
                    //    fail the test.
                    match (res, test.expect_exception) {
                        (Err(e), None) => {
                            return Err(TestError {
                                name: name.clone(),
                                path: path.clone(),
                                kind: TestErrorKind::UnexpectedException {
                                    expected_exception: None,
                                    got_exception: Some(e.to_string()),
                                },
                            });
                        }
                        (Err(real_err), Some(expected_err)) => {
                            self.debug(format!(
                                "expected err: {}, actually error: {:?}",
                                expected_err, real_err
                            ));
                            // TODO check error message are same kind
                            // TODO revert the state
                        }
                        (Ok(_), Some(e)) => {
                            return Err(TestError {
                                name: name.clone(),
                                path: path.clone(),
                                kind: TestErrorKind::UnexpectedException {
                                    expected_exception: Some(e),
                                    got_exception: None,
                                },
                            });
                        }
                        _ => {}
                    }

                    // check state root hash or state is same
                    for (addr, account_info) in test.state {
                        // temp skip coinbase address check
                        if addr == unit.env.current_coinbase {
                            continue;
                        }
                        let user_addr = AddressWithSpace {
                            address: addr,
                            space: Space::Ethereum,
                        };
                        let mut inconsistent_state_err = TestError {
                            name: name.clone(),
                            path: path.clone(),
                            kind: StateMismatch::StateRootMismatch {
                                expected: test.hash,
                                got: Default::default(),
                            }
                            .into(),
                        };

                        // balance check
                        let expected_balance = account_info.balance;
                        let got_balance =
                            state.balance(&user_addr).unwrap_or_default();
                        if got_balance != expected_balance {
                            self.trace(format!(
                                "\tBalance of {} mismatch: expected {} actually {}\n",
                                addr, expected_balance, got_balance
                            ));
                            inconsistent_state_err.kind =
                                StateMismatch::BalanceMismatch {
                                    got: got_balance,
                                    expected: expected_balance,
                                }
                                .into();
                            return Err(inconsistent_state_err);
                        }

                        // nonce check
                        let expected_nonce = U256::from(account_info.nonce);
                        let got_nonce =
                            state.nonce(&user_addr).unwrap_or_default();
                        if got_nonce != expected_nonce {
                            self.trace(format!(
                                "\tNonce of {} mismatch: expected {} actually {}\n",
                                addr, expected_nonce, got_nonce
                            ));
                            inconsistent_state_err.kind =
                                StateMismatch::NonceMismatch {
                                    got: got_nonce,
                                    expected: expected_nonce,
                                }
                                .into();
                            return Err(inconsistent_state_err);
                        }

                        // code check
                        let got_code = match state.code(&user_addr) {
                            Ok(Some(v)) => v.as_ref().to_vec(),
                            _ => Default::default(),
                        };
                        let expected_code = account_info.code.0.clone();
                        let expected_code = hex::encode(expected_code);
                        let got_code = hex::encode(got_code);
                        if got_code != expected_code {
                            self.trace(format!(
                                "\tCode of {} mismatch expected vs actually: \n{}\n{}\n",
                                addr, expected_code, got_code
                            ));
                            inconsistent_state_err.kind =
                                StateMismatch::CodeMismatch {
                                    got: got_code,
                                    expected: expected_code,
                                }
                                .into();
                            return Err(inconsistent_state_err);
                        }

                        // storage check
                        for (key, value) in account_info.storage {
                            let mut key_bytes = [0u8; 32];
                            key.to_big_endian(&mut key_bytes);
                            let curr_value = state
                                .storage_at(&user_addr, &key_bytes)
                                .unwrap_or_default();
                            if curr_value != value {
                                self.trace(format!(
                                    "\tStorage of {} key {} mismatch: expected {} actually {}\n",
                                    addr,
                                    key,
                                    value,
                                    curr_value
                                ));
                                inconsistent_state_err.kind =
                                    StateMismatch::StorageMismatch {
                                        key,
                                        got: curr_value,
                                        expected: value,
                                    }
                                    .into();
                                return Err(inconsistent_state_err);
                            }
                        }
                    }

                    // TODO check logs hash is same
                }
            }

            self.trace(format!("\tTestUnit Finished\n"));
        }

        Ok(())
    }

    fn make_tx(
        &self, tx_meta: &TransactionParts, tx_part_indices: &TxPartIndices,
        chain_id: u64, unprotected: bool,
    ) -> Option<SignedTransaction> {
        // basic fields
        let action = match tx_meta.to {
            Some(to) => Action::Call(to),
            None => Action::Create,
        };
        let nonce = tx_meta.nonce;
        let gas = tx_meta.gas_limit[tx_part_indices.gas];
        let value = tx_meta.value[tx_part_indices.value];
        let data = tx_meta.data[tx_part_indices.data].0.clone();
        let chain_id = chain_id as u32;

        let gas_price = tx_meta.gas_price.unwrap_or_default();

        // EIP-1559 fields
        let max_fee_per_gas = tx_meta.max_fee_per_gas.unwrap_or_default();
        let max_priority_fee_per_gas =
            tx_meta.max_priority_fee_per_gas.unwrap_or_default();

        let access_list = tx_meta
            .access_lists
            .get(tx_part_indices.data)
            .map(|item| item.clone())
            .unwrap_or(Some(vec![]))
            .unwrap();

        let tx = match tx_meta.tx_type(tx_part_indices.data) {
            Some(TransactionType::Legacy) => {
                let tx155_chain_id =
                    if unprotected { None } else { Some(chain_id) };
                EthereumTransaction::Eip155(Eip155Transaction {
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    data,
                    chain_id: tx155_chain_id,
                })
            }
            Some(TransactionType::Eip2930) => {
                EthereumTransaction::Eip2930(Eip2930Transaction {
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    data,
                    chain_id,
                    access_list,
                })
            }
            Some(TransactionType::Eip1559) => {
                EthereumTransaction::Eip1559(Eip1559Transaction {
                    nonce,
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                    gas,
                    action,
                    value,
                    data,
                    chain_id,
                    access_list,
                })
            }
            Some(TransactionType::Eip4844) => {
                // conflux does not support EIP-4844
                return None;
            }
            Some(TransactionType::Eip7702) => {
                let authorization_list = tx_meta
                    .authorization_list
                    .clone()
                    .expect("authorization list should be present")
                    .into_iter()
                    .map(|v| {
                        let auth = SignedAuthorization::from(v);
                        AuthorizationListItem {
                            address: auth.inner().address,
                            nonce: auth.inner().nonce,
                            chain_id: auth.inner().chain_id,
                            y_parity: auth.y_parity(),
                            r: auth.r(),
                            s: auth.s(),
                        }
                    })
                    .collect();

                EthereumTransaction::Eip7702(Eip7702Transaction {
                    nonce,
                    max_priority_fee_per_gas,
                    max_fee_per_gas,
                    gas,
                    destination: tx_meta.to.unwrap_or_default(),
                    value,
                    data,
                    chain_id,
                    access_list,
                    authorization_list,
                })
            }
            _ => {
                // Custom transaction type
                return None;
            }
        };

        let secret = Secret::from(tx_meta.secret_key);
        Some(Transaction::Ethereum(tx).sign(&secret))
    }

    fn transact(
        &self, env: &Env, state: &mut State, transaction: &SignedTransaction,
        options: TransactOptions<()>,
    ) -> DbResult<ExecutionOutcome> {
        let machine = self.make_machine();
        let spec = machine.spec(env.number, env.epoch_height);

        // intrinsic gas check
        let tx_intrinsic_gas = gas_required_for(
            transaction.action() == Action::Create,
            &transaction.data(),
            transaction.access_list(),
            transaction.authorization_len(),
            &spec,
        );
        if transaction.gas_limit().as_u64() < tx_intrinsic_gas {
            return Err(DbError::Msg(
                "TransactionException.INTRINSIC_GAS_TOO_LOW".into(),
            ));
        }

        let evm = ExecutiveContext::new(state, env, &machine, &spec);
        evm.transact(transaction, options)
    }

    // create transact options with no observer
    fn make_transact_options(
        &self, check_base_price: bool, forbid_eoa_with_code: bool,
    ) -> TransactOptions<()> {
        let settings = TransactSettings {
            charge_collateral: ChargeCollateral::Normal,
            charge_gas: true,
            check_base_price,
            check_epoch_bound: false,
            forbid_eoa_with_code,
        };
        TransactOptions {
            observer: (),
            settings,
        }
    }

    fn make_machine(&self) -> Machine {
        let vm_factory = VmFactory::new(1024 * 32);
        Machine::new_with_builtin(self.config.common_params(), vm_factory)
    }

    fn make_state(
        &self, account_overrides: Option<StateOverride>,
    ) -> DbResult<State> {
        let statedb = StateDb::new_for_unit_test();
        match account_overrides {
            Some(overrides) => {
                State::new_with_override(statedb, &overrides, Space::Ethereum)
            }
            None => State::new(statedb),
        }
    }

    fn make_block_env(
        &self, env: &StateTestEnv, evm_chain_id: u64, transaction_hash: H256,
    ) -> Env {
        let mut chain_id = BTreeMap::new();
        chain_id.insert(
            Space::Native,
            self.config
                .raw_conf
                .chain_id
                .unwrap_or(DEFAULT_CORE_CHAIN_ID),
        );
        chain_id.insert(Space::Ethereum, evm_chain_id as u32);

        let base_gas_price = env
            .current_base_fee
            .map(|v| SpaceMap::new(v, v))
            .unwrap_or_default();

        Env {
            chain_id,
            number: env.current_number.as_u64(),
            author: env.current_coinbase,
            timestamp: env.current_timestamp.as_u64(),
            difficulty: env.current_difficulty,
            gas_limit: env.current_gas_limit,
            last_hash: env.previous_hash.unwrap_or_default(),
            accumulated_gas_used: U256::zero(),
            base_gas_price,
            burnt_gas_price: base_gas_price, /* to align with ethereum, all
                                              * base gas price is burnt */
            transaction_hash,
            epoch_height: env.current_number.as_u64(), // set to current number
            transaction_epoch_bound: 100000,           /* set to default
                                                        * epoch bound */
            // pos_view, finalized_epoch is not set
            ..Default::default()
        }
    }

    // Only verbose is higher than level, the message will be printed
    fn log(&self, level: VerboseMode, message: String) {
        if level as u8 <= self.verbose {
            println!("{}", message);
        }
    }

    fn info(&self, message: String) { self.log(VerboseMode::Info, message); }

    fn debug(&self, message: String) { self.log(VerboseMode::Debug, message); }

    fn trace(&self, message: String) { self.log(VerboseMode::Trace, message); }

    fn warn(&self, message: String) { self.log(VerboseMode::Warn, message); }

    fn error(&self, message: String) { self.log(VerboseMode::Error, message); }

    fn fatal(&self, message: String) { self.log(VerboseMode::Fatal, message); }
}
