use cfx_execute_helper::estimation::{EstimateExt, EstimateRequest};
use cfx_executor::executive::{
    Executed, ExecutionError, ExecutionOutcome, ToRepackError, TxDropError,
};
use cfx_rpc_eth_types::{
    AccountOverride, BlockId, BlockOverrides, Error, EvmOverrides,
    RpcStateOverride, TransactionRequest,
};
use cfx_rpc_utils::error::{
    errors::{EthApiError, RpcInvalidTransactionError},
    jsonrpc_error_helpers::{geth_call_execution_error, invalid_input_rpc_err},
};
use cfx_types::U256;
use cfx_util_macros::bail;
use cfx_vm_types::Error as VmError;
use cfxcore::{
    errors::{Error as CoreError, Result as CoreResult},
    ConsensusGraph, SharedConsensusGraph,
};
use jsonrpc_core::Error as RpcError;
use primitives::EpochNumber;
use rustc_hex::ToHex;
use solidity_abi::string_revert_reason_decode;
use std::collections::HashMap;

#[derive(Clone)]
pub struct TxExecutor {
    consensus: SharedConsensusGraph,
    max_estimation_gas_limit: Option<U256>,
}

impl TxExecutor {
    pub fn new(
        consensus: SharedConsensusGraph, max_estimation_gas_limit: Option<U256>,
    ) -> Self {
        Self {
            consensus,
            max_estimation_gas_limit,
        }
    }

    pub fn consensus_graph(&self) -> &ConsensusGraph { &self.consensus }

    pub fn convert_block_number_to_epoch_number(
        &self, block_number: BlockId,
    ) -> Result<EpochNumber, String> {
        if let BlockId::Hash { hash, .. } = block_number {
            let consensus_graph = self.consensus_graph();
            match consensus_graph.get_block_epoch_number(&hash) {
                Some(num) => {
                    // do not expose non-pivot blocks in eth RPC
                    let pivot = consensus_graph
                        .get_block_hashes_by_epoch(EpochNumber::Number(num))?
                        .last()
                        .cloned();

                    if Some(hash) != pivot {
                        return Err(format!("Block {} not found", hash));
                    }

                    Ok(EpochNumber::Number(num))
                }
                None => return Err(format!("Block {} not found", hash)),
            }
        } else {
            block_number.try_into().map_err(|e: Error| e.to_string())
        }
    }

    pub fn do_exec_transaction(
        &self, mut request: TransactionRequest,
        block_number_or_hash: Option<BlockId>,
        state_overrides: Option<RpcStateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> CoreResult<(ExecutionOutcome, EstimateExt)> {
        let consensus_graph = self.consensus_graph();

        if request.gas_price.is_some()
            && request.max_priority_fee_per_gas.is_some()
        {
            return Err(RpcError::from(
                EthApiError::ConflictingFeeFieldsInRequest,
            )
            .into());
        }

        if request.max_fee_per_gas.is_some()
            && request.max_priority_fee_per_gas.is_some()
        {
            if request.max_fee_per_gas.unwrap()
                < request.max_priority_fee_per_gas.unwrap()
            {
                return Err(RpcError::from(
                    RpcInvalidTransactionError::TipAboveFeeCap,
                )
                .into());
            }
        }

        let state_overrides = match state_overrides {
            Some(states) => {
                let mut state_overrides = HashMap::new();
                for (address, rpc_account_override) in states {
                    let account_override =
                        AccountOverride::try_from(rpc_account_override)
                            .map_err(|err| {
                                CoreError::InvalidParam(
                                    err.into(),
                                    Default::default(),
                                )
                            })?;
                    state_overrides.insert(address, account_override);
                }
                Some(state_overrides)
            }
            None => None,
        };
        let evm_overrides = EvmOverrides::new(state_overrides, block_overrides);

        let epoch = self.convert_block_number_to_epoch_number(
            block_number_or_hash.unwrap_or_default(),
        )?;

        // if gas_price and gas is zero, it is considered as not set
        request.unset_zero_gas_and_price();

        let estimate_request = EstimateRequest {
            has_sender: request.from.is_some(),
            has_gas_limit: request.gas.is_some(),
            has_gas_price: request.has_gas_price(),
            has_nonce: request.nonce.is_some(),
            has_storage_limit: false,
        };

        let chain_id = self.consensus.best_chain_id();

        let max_gas = self.max_estimation_gas_limit;
        let signed_tx = request.sign_call(chain_id.in_evm_space(), max_gas)?;

        consensus_graph.call_virtual(
            &signed_tx,
            epoch,
            estimate_request,
            evm_overrides,
        )
    }

    pub fn exec_transaction(
        &self, request: TransactionRequest,
        block_number_or_hash: Option<BlockId>,
        state_overrides: Option<RpcStateOverride>,
        block_overrides: Option<Box<BlockOverrides>>,
    ) -> CoreResult<(Executed, U256)> {
        let (execution_outcome, estimation) = self.do_exec_transaction(
            request,
            block_number_or_hash,
            state_overrides,
            block_overrides,
        )?;

        let executed = match execution_outcome {
            ExecutionOutcome::NotExecutedDrop(TxDropError::OldNonce(
                expected,
                got,
            )) => bail!(invalid_input_rpc_err(
                format! {"nonce is too old expected {:?} got {:?}", expected, got}
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::InvalidRecipientAddress(recipient),
            ) => bail!(invalid_input_rpc_err(
                format! {"invalid recipient address {:?}", recipient}
            )),
            ExecutionOutcome::NotExecutedDrop(
                TxDropError::NotEnoughGasLimit { expected, got },
            ) => bail!(invalid_input_rpc_err(
                format! {"not enough gas limit with respected to tx size: expected {:?} got {:?}", expected, got}
            )),
            ExecutionOutcome::NotExecutedDrop(TxDropError::SenderWithCode(
                address,
            )) => bail!(invalid_input_rpc_err(
                format! {"tx sender has contract code: {:?}", address}
            )),
            ExecutionOutcome::NotExecutedToReconsiderPacking(
                ToRepackError::SenderDoesNotExist,
            ) => {
                bail!(RpcError::from(
                    RpcInvalidTransactionError::InsufficientFunds
                ))
            }
            ExecutionOutcome::NotExecutedToReconsiderPacking(e) => {
                bail!(invalid_input_rpc_err(format! {"err: {:?}", e}))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::NotEnoughCash { .. },
                _executed,
            ) => {
                bail!(RpcError::from(
                    RpcInvalidTransactionError::InsufficientFunds
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::NonceOverflow(addr),
                _executed,
            ) => {
                bail!(geth_call_execution_error(
                    format!("address nonce overflow: {})", addr),
                    "".into()
                ))
            }
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(VmError::Reverted),
                executed,
            ) => bail!(geth_call_execution_error(
                format!(
                    "execution reverted: revert: {}",
                    string_revert_reason_decode(&executed.output)
                ),
                format!("0x{}", executed.output.to_hex::<String>())
            )),
            ExecutionOutcome::ExecutionErrorBumpNonce(
                ExecutionError::VmError(e),
                _executed,
            ) => bail!(geth_call_execution_error(
                format!("execution reverted: {}", e),
                "".into()
            )),
            ExecutionOutcome::Finished(executed) => executed,
        };

        Ok((executed, estimation.estimated_gas_limit))
    }
}
