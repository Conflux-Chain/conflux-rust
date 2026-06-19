use crate::{
    codec::{read_u32_le, read_u64_le, read_uleb128},
    packet::{
        FLAG_HAS_TRANSACTIONS, FLAG_TX_COMPRESSED, HEADER_FIXED_LEN,
        HEADER_LEN, HEADER_OFFSET_COUNT,
    },
};
use anyhow::{ensure, Context, Result};
use snap::raw::Decoder as SnapDecoder;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub packet_bytes: usize,
    pub first_block_number: u64,
    pub min_timestamp: u64,
    pub min_height: u64,
    pub min_pos_height: u32,
    pub block_prefix_size: u8,
    pub block_count: u32,
    pub transaction_blocks: u32,
    pub transaction_items: u32,
}

pub fn verify_packet(data: &[u8]) -> Result<VerifyReport> {
    ensure!(data.len() >= HEADER_LEN, "packet shorter than header");
    let first_block_number = read_u64_le(data, 64)?;
    let min_timestamp = read_u64_le(data, 72)?;
    let min_height = read_u64_le(data, 80)?;
    let min_pos_height = read_u32_le(data, 88)?;
    let block_prefix_size = data[92];
    ensure!(
        matches!(block_prefix_size, 64 | 72 | 80 | 88 | 96),
        "invalid block_prefix_size {block_prefix_size}"
    );

    let offsets = read_offsets(data)?;
    ensure_offsets(&offsets, data.len())?;
    ensure!(
        offsets[5] % 32 == 0,
        "block header offset is not 32-byte aligned"
    );
    ensure!(
        offsets[7] % 64 == 0,
        "tx segment offset is not 64-byte aligned"
    );

    let block_header_offset = offsets[5];
    let block_body_offset = offsets[6];
    let tx_segment_offset = offsets[7];
    ensure!(block_header_offset + 4 <= data.len(), "missing block_count");
    let block_count = read_u32_le(data, block_header_offset)? as usize;
    let bitmap_len = block_count.div_ceil(8);
    ensure!(
        block_header_offset + 4 + bitmap_len <= block_body_offset,
        "block extension bitmap exceeds block body offset"
    );
    let bitmap =
        &data[block_header_offset + 4..block_header_offset + 4 + bitmap_len];

    let prefix_size = block_prefix_size as usize;
    let prefix_total = block_count
        .checked_mul(prefix_size)
        .context("block prefix size overflow")?;
    ensure!(
        block_body_offset + prefix_total <= tx_segment_offset,
        "block prefix area exceeds tx segment"
    );
    let mut overflow_offset = block_body_offset + prefix_total;
    let mut block_records = Vec::with_capacity(block_count);
    for index in 0..block_count {
        let mut record = data[block_body_offset + index * prefix_size
            ..block_body_offset + (index + 1) * prefix_size]
            .to_vec();
        if bitmap[index / 8] & (1 << (index % 8)) != 0 {
            let len = read_uleb128(data, &mut overflow_offset)? as usize;
            ensure!(
                overflow_offset + len <= tx_segment_offset,
                "block overflow exceeds tx segment"
            );
            record.extend_from_slice(
                &data[overflow_offset..overflow_offset + len],
            );
            overflow_offset += len;
        }
        block_records.push(record);
    }
    ensure!(
        overflow_offset <= tx_segment_offset,
        "block overflow parser passed tx segment"
    );

    let mut transaction_blocks = 0u32;
    let mut transaction_items = 0u32;
    for record in &block_records {
        ensure!(record.len() >= 45, "block record too short");
        let flags = record[44];
        if flags & FLAG_HAS_TRANSACTIONS == 0 {
            continue;
        }
        transaction_blocks += 1;
        let mut offset = 45;
        skip_uleb(record, &mut offset)?; // author
        skip_uleb(record, &mut offset)?; // timestamp
        skip_uleb(record, &mut offset)?; // difficulty
        skip_qc5e(record, &mut offset)?; // gas_limit
        skip_qc5e(record, &mut offset)?; // core base price
        skip_qc5e(record, &mut offset)?; // espace base price
        skip_uleb(record, &mut offset)?; // height
        skip_uleb(record, &mut offset)?; // blame
        skip_uleb(record, &mut offset)?; // finalized_epoch
        let tx_offset_units = read_uleb128(record, &mut offset)? as usize;
        let absolute = tx_segment_offset + tx_offset_units * 4;
        ensure!(absolute < data.len(), "tx payload offset out of bounds");
        let mut payload_offset = absolute;
        let payload_len = read_uleb128(data, &mut payload_offset)? as usize;
        ensure!(
            payload_offset + payload_len <= data.len(),
            "tx payload exceeds packet"
        );
        let payload = &data[payload_offset..payload_offset + payload_len];
        let decoded = if flags & FLAG_TX_COMPRESSED != 0 {
            SnapDecoder::new()
                .decompress_vec(payload)
                .context("snappy-decompress tx payload")?
        } else {
            payload.to_vec()
        };
        let rlp = rlp::Rlp::new(&decoded);
        transaction_items +=
            rlp.item_count().context("decode tx payload RLP")? as u32;
    }

    Ok(VerifyReport {
        packet_bytes: data.len(),
        first_block_number,
        min_timestamp,
        min_height,
        min_pos_height,
        block_prefix_size,
        block_count: block_count as u32,
        transaction_blocks,
        transaction_items,
    })
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

fn skip_uleb(data: &[u8], offset: &mut usize) -> Result<()> {
    read_uleb128(data, offset).map(|_| ())
}

fn skip_qc5e(data: &[u8], offset: &mut usize) -> Result<()> {
    ensure!(*offset < data.len(), "qc5e read out of bounds");
    let mode = data[*offset] >> 6;
    let len = match mode {
        0 => 1,
        1 => 5,
        2 => 6,
        _ => 7,
    };
    ensure!(*offset + len <= data.len(), "qc5e exceeds block record");
    *offset += len;
    Ok(())
}
