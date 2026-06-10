use cfx_addr::Network;
use cfx_rpc_cfx_types::{Receipt, RpcAddress};
use cfx_types::{Bloom, H256, U256, U64};
use cfxcore::genesis_block::{
    build_genesis_transactions, get_genesis_contract_addresses,
};
use primitives::transaction::Action;

pub struct GenesisBlockMeta {
    pub gas_used: u64,
}

pub fn compute_genesis_tx_receipts(
    chain_id: u32, network: Network, block_hash: H256, state_root: H256,
) -> Vec<Receipt> {
    let genesis_transactions = build_genesis_transactions(chain_id);
    let contract_addresses =
        get_genesis_contract_addresses(&genesis_transactions);

    let mut accumulated_gas = U256::zero();

    genesis_transactions
        .into_iter()
        .enumerate()
        .map(|(index, tx)| {
            let tx_gas = *tx.gas();
            accumulated_gas += tx_gas;
            let tx_gas_price = *tx.gas_price();
            let gas_fee = tx_gas * tx_gas_price;

            let contract_created = contract_addresses[index].and_then(|addr| {
                RpcAddress::try_from_h160(addr.address, network).ok()
            });

            let to = match tx.transaction.unsigned.action() {
                Action::Create => None,
                Action::Call(addr) => {
                    RpcAddress::try_from_h160(addr.clone(), network).ok()
                }
            };

            Receipt {
                transaction_type: Some(U64::from(
                    tx.transaction.unsigned.type_id(),
                )),
                transaction_hash: tx.hash(),
                index: U64::from(index),
                block_hash,
                epoch_number: Some(U64::zero()),
                from: RpcAddress::try_from_h160(tx.sender().address, network)
                    .unwrap_or_else(|_| RpcAddress::null(network).unwrap()),
                to,
                gas_used: tx_gas,
                accumulated_gas_used: Some(accumulated_gas),
                gas_fee,
                effective_gas_price: tx_gas_price,
                contract_created,
                logs: vec![],
                logs_bloom: Bloom::zero(),
                state_root,
                outcome_status: U64::zero(), // success
                tx_exec_error_msg: None,
                gas_covered_by_sponsor: false,
                storage_covered_by_sponsor: false,
                storage_collateralized: U64::from(
                    tx.storage_limit().unwrap_or(0),
                ),
                storage_released: vec![],
                space: Some(tx.space()),
                burnt_gas_fee: None,
            }
        })
        .collect()
}
