use crate::{
    codec::{read_qc5e, read_qc8, read_u32_le, read_u64_le, read_uleb128},
    packet::{
        BlockInput, PacketInput, PosLookupEntry, SenderBaseNonce,
        FLAG_HAS_TRANSACTIONS, FLAG_PIVOT, FLAG_TX_COMPRESSED,
        HEADER_FIXED_LEN, HEADER_LEN, HEADER_OFFSET_COUNT,
    },
};
use anyhow::{anyhow, ensure, Context, Result};
use cfx_types::{Address, AddressSpaceUtil, H256, U256};
use primitives::{
    transaction::{
        Cip1559Transaction, Cip2930Transaction, Eip1559Transaction,
        Eip155Transaction, Eip2930Transaction, Eip7702Transaction,
        EthereumTransaction, NativeTransaction, TypedNativeTransaction,
    },
    AccessListItem, Action, AuthorizationListItem, SignedTransaction,
};
use rlp::Rlp;
use snap::raw::Decoder as SnapDecoder;

pub fn decode_packet(data: &[u8]) -> Result<PacketInput> {
    ensure!(data.len() >= HEADER_LEN, "packet shorter than header");
    let prev_last_hash = H256::from_slice(&data[0..32]);
    let prev_last_deferred_state_root = H256::from_slice(&data[32..64]);
    let first_block_number = read_u64_le(data, 64)?;
    let min_timestamp = read_u64_le(data, 72)?;
    let min_height = read_u64_le(data, 80)?;
    let min_pos_height = read_u32_le(data, 88)? as u64;
    let block_prefix_size = data[92] as usize;
    ensure!(
        matches!(block_prefix_size, 64 | 72 | 80 | 88 | 96),
        "invalid block_prefix_size"
    );

    let offsets = read_offsets(data)?;
    ensure_offsets(&offsets, data.len())?;

    let addresses = decode_addresses(&data[offsets[0]..offsets[1]])?;
    let pos_entries = decode_pos_entries(&data[offsets[1]..offsets[2]])?;
    let difficulties = decode_u256_table(&data[offsets[2]..offsets[3]])?;
    let sender_base_nonces =
        decode_sender_base_nonces(&data[offsets[3]..offsets[4]])?;
    let gas_prices = decode_u256_table(&data[offsets[4]..offsets[5]])?;

    let block_records = decode_block_records(
        data,
        offsets[5],
        offsets[6],
        offsets[7],
        block_prefix_size,
    )?;
    let mut blocks = Vec::with_capacity(block_records.len());
    let mut decoded_txs = Vec::<Vec<SignedTransaction>>::new();
    for (index, record) in block_records.iter().enumerate() {
        let block = decode_block_record(
            record,
            index,
            min_timestamp,
            min_height,
            &addresses,
            &difficulties,
        )?;
        decoded_txs.push(Vec::new());
        blocks.push(block);
    }
    assign_epoch_from_pivots(&mut blocks)?;

    for (index, (record, block)) in
        block_records.iter().zip(blocks.iter_mut()).enumerate()
    {
        if block.flags & FLAG_HAS_TRANSACTIONS != 0 {
            let (transactions, transaction_refs) = decode_tx_payload(
                data,
                offsets[7],
                record.tx_offset_units,
                block.flags,
                block.epoch,
                &addresses,
                &gas_prices,
                &sender_base_nonces,
                &decoded_txs[..index],
            )?;
            block.transactions = transactions;
            block.transaction_refs = transaction_refs;
        }
        decoded_txs[index] = block.transactions.clone();
    }

    Ok(PacketInput {
        prev_last_hash,
        prev_last_deferred_state_root,
        first_block_number,
        min_timestamp,
        min_height,
        min_pos_height,
        addresses,
        pos_entries,
        difficulties,
        sender_base_nonces,
        gas_prices,
        blocks,
    })
}

struct DecodedRecord {
    bytes: Vec<u8>,
    tx_offset_units: u64,
}

impl std::ops::Deref for DecodedRecord {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

fn decode_block_records(
    data: &[u8], block_header_offset: usize, block_body_offset: usize,
    tx_segment_offset: usize, prefix_size: usize,
) -> Result<Vec<DecodedRecord>> {
    let block_count = read_u32_le(data, block_header_offset)? as usize;
    let bitmap_len = block_count.div_ceil(8);
    let bitmap =
        &data[block_header_offset + 4..block_header_offset + 4 + bitmap_len];
    let prefix_total = block_count
        .checked_mul(prefix_size)
        .context("block prefix size overflow")?;
    ensure!(
        block_body_offset + prefix_total <= tx_segment_offset,
        "block prefix area exceeds tx segment"
    );
    let mut overflow_offset = block_body_offset + prefix_total;
    let mut out = Vec::with_capacity(block_count);
    for index in 0..block_count {
        let mut bytes = data[block_body_offset + index * prefix_size
            ..block_body_offset + (index + 1) * prefix_size]
            .to_vec();
        if bitmap[index / 8] & (1 << (index % 8)) != 0 {
            let len = read_uleb128(data, &mut overflow_offset)? as usize;
            ensure!(
                overflow_offset + len <= tx_segment_offset,
                "block overflow exceeds tx segment"
            );
            bytes.extend_from_slice(
                &data[overflow_offset..overflow_offset + len],
            );
            overflow_offset += len;
        }
        let tx_offset_units = peek_tx_offset_units(&bytes)?;
        out.push(DecodedRecord {
            bytes,
            tx_offset_units,
        });
    }
    Ok(out)
}

fn decode_block_record(
    record: &[u8], index: usize, min_timestamp: u64, min_height: u64,
    addresses: &[Address], difficulties: &[U256],
) -> Result<BlockInput> {
    ensure!(record.len() >= 45, "block record too short");
    let hash = H256::from_slice(&record[0..32]);
    let deferred_state_root = h256_prefix(&record[32..36]);
    let deferred_receipts_root = h256_prefix(&record[36..40]);
    let deferred_logs_bloom_hash = h256_prefix(&record[40..44]);
    let flags = record[44];
    let mut offset = 45;
    let author =
        table_get(addresses, read_uleb128(record, &mut offset)? as usize)?;
    let timestamp = min_timestamp + read_uleb128(record, &mut offset)?;
    let difficulty =
        table_get(difficulties, read_uleb128(record, &mut offset)? as usize)?;
    let gas_limit = read_qc5e(record, &mut offset)?.gas_limit();
    let base_price_core = read_qc5e(record, &mut offset)?.base_price(false);
    let base_price_espace = read_qc5e(record, &mut offset)?.base_price(true);
    let height = min_height + read_uleb128(record, &mut offset)?;
    let blame = read_uleb128(record, &mut offset)?;
    let finalized_epoch = read_uleb128(record, &mut offset)?;
    let _tx_segment_offset = read_uleb128(record, &mut offset)?;
    let base_reward = read_qc8(record, &mut offset)?;
    Ok(BlockInput {
        epoch: 0,
        index,
        hash,
        deferred_state_root,
        deferred_receipts_root,
        deferred_logs_bloom_hash,
        flags,
        author,
        timestamp,
        difficulty,
        gas_limit,
        base_price_core,
        base_price_espace,
        height,
        blame,
        finalized_epoch,
        base_reward,
        transactions: Vec::new(),
        transaction_refs: Vec::new(),
    })
}

fn assign_epoch_from_pivots(blocks: &mut [BlockInput]) -> Result<()> {
    let mut group_start = 0usize;
    while group_start < blocks.len() {
        let Some(relative_pivot) = blocks[group_start..]
            .iter()
            .position(|block| block.flags & FLAG_PIVOT != 0)
        else {
            return Err(anyhow!(
                "packet block list has no pivot for final epoch group"
            ));
        };
        let pivot_index = group_start + relative_pivot;
        let epoch = blocks[pivot_index].height;
        for block in &mut blocks[group_start..=pivot_index] {
            block.epoch = epoch;
        }
        group_start = pivot_index + 1;
    }
    Ok(())
}

fn decode_tx_payload(
    data: &[u8], tx_segment_offset: usize, tx_offset_units: u64, flags: u8,
    block_epoch: u64, addresses: &[Address], gas_prices: &[U256],
    sender_base_nonces: &[SenderBaseNonce],
    previous_blocks: &[Vec<SignedTransaction>],
) -> Result<(Vec<SignedTransaction>, Vec<Option<(usize, usize)>>)> {
    let absolute = tx_segment_offset + tx_offset_units as usize * 4;
    ensure!(absolute < data.len(), "tx payload offset out of bounds");
    let mut offset = absolute;
    let payload_len = read_uleb128(data, &mut offset)? as usize;
    ensure!(
        offset + payload_len <= data.len(),
        "tx payload exceeds packet"
    );
    let payload = &data[offset..offset + payload_len];
    let decoded = if flags & FLAG_TX_COMPRESSED != 0 {
        SnapDecoder::new()
            .decompress_vec(payload)
            .context("snappy-decompress tx payload")?
    } else {
        payload.to_vec()
    };
    let rlp = Rlp::new(&decoded);
    let mut out = Vec::new();
    let mut refs = Vec::new();
    for i in 0..rlp.item_count()? {
        let item = rlp.at(i)?;
        let marker: u8 = item.val_at(0)?;
        if marker == 1 {
            let block_index: usize = item.val_at::<u64>(1)? as usize;
            let tx_index: usize = item.val_at::<u64>(2)? as usize;
            out.push(
                previous_blocks
                    .get(block_index)
                    .and_then(|b| b.get(tx_index))
                    .ok_or_else(|| {
                        anyhow!("duplicate tx reference out of range")
                    })?
                    .clone(),
            );
            refs.push(Some((block_index, tx_index)));
        } else {
            out.push(decode_tx_item(
                &item,
                block_epoch,
                addresses,
                gas_prices,
                sender_base_nonces,
            )?);
            refs.push(None);
        }
    }
    Ok((out, refs))
}

fn decode_tx_item(
    item: &Rlp, block_epoch: u64, addresses: &[Address], gas_prices: &[U256],
    sender_base_nonces: &[SenderBaseNonce],
) -> Result<SignedTransaction> {
    let space_marker: u8 = item.val_at(0)?;
    let type_id: u64 = item.val_at(1)?;
    let sender_index = item.val_at::<u64>(2)? as usize;
    let sender = table_get(addresses, sender_index)?;
    let base_nonce = sender_base_nonces
        .iter()
        .find(|entry| entry.sender_index == sender_index)
        .map(|entry| entry.base_nonce)
        .unwrap_or(0);
    let nonce = U256::from(base_nonce + item.val_at::<u64>(3)?);
    let gas_price = decode_price(&item.at(4)?, gas_prices)?;
    let priority_price = decode_price(&item.at(5)?, gas_prices)?;
    let gas = U256::from(item.val_at::<u64>(6)?);
    let action = decode_action(&item.at(7)?, addresses)?;
    let value = decode_u256_bytes(item.val_at::<Vec<u8>>(8)?)?;

    match space_marker {
        0 => {
            let storage_limit = item.val_at(9)?;
            let epoch_delta: u64 = item.val_at(10)?;
            let data = item.val_at::<Vec<u8>>(11)?.into();
            let access_list = optional_list::<AccessListItem>(item, 12)?;
            let epoch_height = block_epoch + epoch_delta;
            let tx = match type_id {
                0 => TypedNativeTransaction::Cip155(NativeTransaction {
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    storage_limit,
                    epoch_height,
                    chain_id: 0,
                    data,
                }),
                1 => TypedNativeTransaction::Cip2930(Cip2930Transaction {
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    storage_limit,
                    epoch_height,
                    chain_id: 0,
                    data,
                    access_list,
                }),
                2 => TypedNativeTransaction::Cip1559(Cip1559Transaction {
                    nonce,
                    max_priority_fee_per_gas: priority_price,
                    max_fee_per_gas: gas_price,
                    gas,
                    action,
                    value,
                    storage_limit,
                    epoch_height,
                    chain_id: 0,
                    data,
                    access_list,
                }),
                _ => {
                    return Err(anyhow!("unsupported native tx type {type_id}"))
                }
            };
            Ok(tx.fake_sign_rpc(sender.with_native_space()))
        }
        2 => {
            let data = item.val_at::<Vec<u8>>(9)?.into();
            let access_list = optional_list::<AccessListItem>(item, 10)?;
            let tx = match type_id {
                0 => EthereumTransaction::Eip155(Eip155Transaction {
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    chain_id: None,
                    data,
                }),
                1 => EthereumTransaction::Eip2930(Eip2930Transaction {
                    chain_id: 0,
                    nonce,
                    gas_price,
                    gas,
                    action,
                    value,
                    data,
                    access_list,
                }),
                2 => EthereumTransaction::Eip1559(Eip1559Transaction {
                    chain_id: 0,
                    nonce,
                    max_priority_fee_per_gas: priority_price,
                    max_fee_per_gas: gas_price,
                    gas,
                    action,
                    value,
                    data,
                    access_list,
                }),
                4 => EthereumTransaction::Eip7702(Eip7702Transaction {
                    chain_id: 0,
                    nonce,
                    max_priority_fee_per_gas: priority_price,
                    max_fee_per_gas: gas_price,
                    gas,
                    destination: match action {
                        Action::Call(address) => address,
                        Action::Create => Address::zero(),
                    },
                    value,
                    data,
                    access_list,
                    authorization_list: optional_list::<AuthorizationListItem>(
                        item, 11,
                    )?,
                }),
                _ => {
                    return Err(anyhow!(
                        "unsupported ethereum tx type {type_id}"
                    ))
                }
            };
            Ok(tx.fake_sign_rpc(sender.with_evm_space()))
        }
        _ => Err(anyhow!("unsupported tx space marker {space_marker}")),
    }
}

fn peek_tx_offset_units(record: &[u8]) -> Result<u64> {
    let mut offset = 45;
    for _ in 0..3 {
        read_uleb128(record, &mut offset)?;
    }
    for _ in 0..3 {
        read_qc5e(record, &mut offset)?;
    }
    for _ in 0..3 {
        read_uleb128(record, &mut offset)?;
    }
    read_uleb128(record, &mut offset)
}

fn decode_addresses(data: &[u8]) -> Result<Vec<Address>> {
    ensure!(data.len() % 20 == 0, "address table has trailing bytes");
    Ok(data.chunks_exact(20).map(Address::from_slice).collect())
}

fn decode_pos_entries(data: &[u8]) -> Result<Vec<PosLookupEntry>> {
    ensure!(data.len() % 34 == 0, "PoS table has trailing bytes");
    Ok(data
        .chunks_exact(34)
        .map(|chunk| PosLookupEntry {
            hash: H256::from_slice(&chunk[..32]),
            height_offset: u16::from_le_bytes([chunk[32], chunk[33]]),
        })
        .collect())
}

fn decode_u256_table(data: &[u8]) -> Result<Vec<U256>> {
    let data = trim_zero_padding(data, 32)?;
    ensure!(data.len() % 32 == 0, "U256 table has trailing bytes");
    Ok(data.chunks_exact(32).map(U256::from_big_endian).collect())
}

fn decode_sender_base_nonces(data: &[u8]) -> Result<Vec<SenderBaseNonce>> {
    let mut offset = 0;
    let mut out = Vec::new();
    while offset < data.len() {
        out.push(SenderBaseNonce {
            sender_index: read_uleb128(data, &mut offset)? as usize,
            base_nonce: read_uleb128(data, &mut offset)?,
        });
    }
    Ok(out)
}

fn decode_price(item: &Rlp, gas_prices: &[U256]) -> Result<U256> {
    let mode: u8 = item.val_at(0)?;
    match mode {
        0 => table_get(gas_prices, item.val_at::<u64>(1)? as usize),
        1 => decode_u256_bytes(item.val_at::<Vec<u8>>(1)?),
        _ => Err(anyhow!("invalid gas price mode {mode}")),
    }
}

fn decode_action(item: &Rlp, addresses: &[Address]) -> Result<Action> {
    let mode: u8 = item.val_at(0)?;
    match mode {
        0 => Ok(Action::Create),
        1 => Ok(Action::Call(table_get(
            addresses,
            item.val_at::<u64>(1)? as usize,
        )?)),
        _ => Err(anyhow!("invalid action mode {mode}")),
    }
}

fn optional_list<T: rlp::Decodable>(
    item: &Rlp, index: usize,
) -> Result<Vec<T>> {
    if item.item_count()? > index {
        item.list_at(index).map_err(Into::into)
    } else {
        Ok(Vec::new())
    }
}

fn decode_u256_bytes(bytes: Vec<u8>) -> Result<U256> {
    ensure!(bytes.len() <= 32, "U256 byte value exceeds 32 bytes");
    Ok(U256::from_big_endian(&bytes))
}

fn table_get<T: Copy>(table: &[T], index: usize) -> Result<T> {
    table
        .get(index)
        .copied()
        .ok_or_else(|| anyhow!("lookup table index {index} out of bounds"))
}

fn h256_prefix(prefix: &[u8]) -> H256 {
    let mut bytes = [0u8; 32];
    bytes[..prefix.len()].copy_from_slice(prefix);
    H256::from(bytes)
}

fn read_offsets(data: &[u8]) -> Result<[usize; HEADER_OFFSET_COUNT]> {
    let mut offsets = [0usize; HEADER_OFFSET_COUNT];
    for (i, item) in offsets.iter_mut().enumerate() {
        *item = read_u32_le(data, HEADER_FIXED_LEN + i * 4)? as usize;
    }
    Ok(offsets)
}

fn ensure_offsets(
    offsets: &[usize; HEADER_OFFSET_COUNT], len: usize,
) -> Result<()> {
    let mut previous = HEADER_LEN;
    for offset in offsets {
        ensure!(*offset >= previous, "offset table is not monotonic");
        ensure!(*offset <= len, "offset exceeds packet length");
        previous = *offset;
    }
    Ok(())
}

fn trim_zero_padding(data: &[u8], alignment: usize) -> Result<&[u8]> {
    let trailing = data.len() % alignment;
    if trailing == 0 {
        return Ok(data);
    }
    let split = data.len() - trailing;
    ensure!(
        data[split..].iter().all(|byte| *byte == 0),
        "non-zero table padding"
    );
    Ok(&data[..split])
}
