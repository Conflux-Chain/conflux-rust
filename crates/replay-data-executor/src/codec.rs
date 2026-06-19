use anyhow::{bail, ensure, Result};
use cfx_types::U256;

pub fn put_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn put_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    ensure!(offset + 4 <= data.len(), "u32 read out of bounds");
    Ok(u32::from_le_bytes(data[offset..offset + 4].try_into()?))
}

pub fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    ensure!(offset + 8 <= data.len(), "u64 read out of bounds");
    Ok(u64::from_le_bytes(data[offset..offset + 8].try_into()?))
}

pub fn put_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

pub fn read_uleb128(data: &[u8], offset: &mut usize) -> Result<u64> {
    let mut shift = 0;
    let mut value = 0u64;
    loop {
        ensure!(*offset < data.len(), "uleb128 read out of bounds");
        let byte = data[*offset];
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        ensure!(shift < 64, "uleb128 overflow");
    }
}

pub fn read_qc8(data: &[u8], offset: &mut usize) -> Result<U256> {
    ensure!(*offset < data.len(), "qc8 read out of bounds");
    let mode = data[*offset] >> 6;
    let len = match mode {
        0 => 8,
        1 => 9,
        2 => 10,
        _ => 11,
    };
    ensure!(*offset + len <= data.len(), "qc8 exceeds buffer");
    let mut bytes = vec![0u8; len];
    bytes.copy_from_slice(&data[*offset..*offset + len]);
    bytes[0] &= 0x3f;
    *offset += len;
    Ok(U256::from_big_endian(&bytes))
}

pub fn read_qc5e(data: &[u8], offset: &mut usize) -> Result<Qc5eValue> {
    ensure!(*offset < data.len(), "qc5e read out of bounds");
    let first = data[*offset];
    let mode = first >> 6;
    if mode == 0 {
        *offset += 1;
        return Ok(Qc5eValue::Enum(first & 0x3f));
    }
    let len = match mode {
        1 => 5,
        2 => 6,
        _ => 7,
    };
    ensure!(*offset + len <= data.len(), "qc5e exceeds buffer");
    let mut bytes = vec![0u8; len];
    bytes.copy_from_slice(&data[*offset..*offset + len]);
    bytes[0] &= 0x3f;
    *offset += len;
    Ok(Qc5eValue::Integer(U256::from_big_endian(&bytes)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qc5eValue {
    Enum(u8),
    Integer(U256),
}

impl Qc5eValue {
    pub fn gas_limit(self) -> U256 {
        match self {
            Qc5eValue::Enum(1) => U256::from(30_000_000),
            Qc5eValue::Enum(2) => U256::from(60_000_000),
            Qc5eValue::Enum(_) => U256::zero(),
            Qc5eValue::Integer(value) => value,
        }
    }

    pub fn base_price(self, espace: bool) -> U256 {
        match self {
            Qc5eValue::Enum(0) => U256::zero(),
            Qc5eValue::Enum(1) if espace => U256::from(20_000_000_000u64),
            Qc5eValue::Enum(1) => U256::from(1_000_000_000u64),
            Qc5eValue::Enum(_) => U256::zero(),
            Qc5eValue::Integer(value) => value,
        }
    }
}

pub fn uleb128_len(mut value: u64) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

pub fn put_qc8(out: &mut Vec<u8>, value: U256) -> Result<()> {
    let bytes = u256_to_be(value);
    let first_non_zero = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    let compact = &bytes[first_non_zero..];
    for (mode, total_len, max_bits) in
        [(0u8, 8usize, 62usize), (1, 9, 70), (2, 10, 78), (3, 11, 86)]
    {
        if bit_len(compact) <= max_bits {
            let mut payload = vec![0u8; total_len];
            let copy_start = total_len - compact.len();
            payload[copy_start..].copy_from_slice(compact);
            ensure!(payload[0] & 0xc0 == 0, "qc8 value exceeds payload bits");
            payload[0] |= mode << 6;
            out.extend_from_slice(&payload);
            return Ok(());
        }
    }
    bail!("qc8 value exceeds 86 bits: {}", value)
}

pub fn put_qc5e(
    out: &mut Vec<u8>, value: U256, enum_value: Option<u8>,
) -> Result<()> {
    if let Some(v) = enum_value {
        ensure!(v < 64, "qc5e enum value out of range");
        out.push(v);
        return Ok(());
    }
    let bytes = u256_to_be(value);
    let first_non_zero = bytes.iter().position(|b| *b != 0).unwrap_or(32);
    let compact = &bytes[first_non_zero..];
    for (mode, total_len, max_bits) in
        [(1u8, 5usize, 38usize), (2, 6, 46), (3, 7, 54)]
    {
        if bit_len(compact) <= max_bits {
            let mut payload = vec![0u8; total_len];
            let copy_start = total_len - compact.len();
            payload[copy_start..].copy_from_slice(compact);
            ensure!(payload[0] & 0xc0 == 0, "qc5e value exceeds payload bits");
            payload[0] |= mode << 6;
            out.extend_from_slice(&payload);
            return Ok(());
        }
    }
    bail!("qc5e value exceeds 54 bits: {}", value)
}

pub fn qc5e_gas_limit_enum(value: U256) -> Option<u8> {
    if value == U256::from(30_000_000u64) {
        Some(1)
    } else if value == U256::from(60_000_000u64) {
        Some(2)
    } else if value.is_zero() {
        Some(0)
    } else {
        None
    }
}

pub fn qc5e_base_price_enum(value: U256, espace: bool) -> Option<u8> {
    let default = if espace {
        20_000_000_000u64
    } else {
        1_000_000_000u64
    };
    if value.is_zero() {
        Some(0)
    } else if value == U256::from(default) {
        Some(1)
    } else {
        None
    }
}

pub fn u256_to_be(value: U256) -> [u8; 32] {
    value.to_big_endian()
}

fn bit_len(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        return 0;
    }
    let first = bytes[0];
    (bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize)
}

pub fn align_to(out: &mut Vec<u8>, align: usize) {
    let pad = (align - out.len() % align) % align;
    out.resize(out.len() + pad, 0);
}
