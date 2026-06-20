//! Throwaway inspector: dump per-block `blame` / pivot / deferred roots for a
//! height range, to confirm whether replay mismatches sit in a blame context.
//! Usage: dump_blame <container.cfxpack> <lo_height> <hi_height>
use cfx_replay_data_executor::decode::decode_packet;
use cfx_replay_data_executor::packet::{FLAG_PIVOT, FLAG_ZERO_TOTAL_REWARD};
use std::{env, fs};

const MAGIC: &[u8; 8] = b"CFXPACK1";
const HDR: usize = 24;
const ENTRY: usize = 32;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let file = &args[1];
    let lo: u64 = args[2].parse()?;
    let hi: u64 = args[3].parse()?;
    let data = fs::read(file)?;
    anyhow::ensure!(&data[0..8] == MAGIC, "not a cfxpack container");
    let groups = u32::from_le_bytes(data[12..16].try_into()?) as usize;
    let mut pos = HDR;
    let mut total_blocks = 0u64;
    let mut ztr_blocks = 0u64;
    let mut ztr_examples: Vec<(u64, u64, u8)> = Vec::new();
    for _ in 0..groups {
        let off = u64::from_le_bytes(data[pos + 16..pos + 24].try_into()?) as usize;
        let len = u64::from_le_bytes(data[pos + 24..pos + 32].try_into()?) as usize;
        pos += ENTRY;
        let input = decode_packet(&data[off..off + len])?;
        for b in &input.blocks {
            total_blocks += 1;
            if b.flags & FLAG_ZERO_TOTAL_REWARD != 0 {
                ztr_blocks += 1;
                if ztr_examples.len() < 10 {
                    let hp = b.hash.as_bytes();
                    ztr_examples.push((b.epoch, b.transactions.len() as u64, hp[0]));
                }
                if b.height >= lo && b.height <= hi {
                    let hp = b.hash.as_bytes();
                    println!(
                        "ZTR block=0x{:02x}{:02x}{:02x}{:02x} epoch={} height={} pivot={} txs={} base_reward={}",
                        hp[0], hp[1], hp[2], hp[3],
                        b.epoch, b.height,
                        (b.flags & FLAG_PIVOT != 0) as u8,
                        b.transactions.len(), b.base_reward,
                    );
                }
            }
            if b.index >= lo as usize && b.index <= hi as usize {
                println!(
                    "INDEX idx={} h={} epoch={} pivot={} blame={} txs={} base_reward={}",
                    b.index,
                    b.height,
                    b.epoch,
                    (b.flags & FLAG_PIVOT != 0) as u8,
                    b.blame,
                    b.transactions.len(),
                    b.base_reward,
                );
            }
            if b.height >= lo && b.height <= hi {
                let hp = b.hash.as_bytes();
                println!(
                    "block=0x{:02x}{:02x}{:02x}{:02x} epoch={} height={} pivot={} reward0={} blame={} txs={} base_reward={}",
                    hp[0], hp[1], hp[2], hp[3],
                    b.epoch,
                    b.height,
                    (b.flags & FLAG_PIVOT != 0) as u8,
                    (b.base_reward.is_zero()) as u8,
                    b.blame,
                    b.transactions.len(),
                    b.base_reward,
                );
            }
        }
    }
    println!(
        "SUMMARY total_blocks={total_blocks} zero_total_reward_blocks={ztr_blocks}"
    );
    for (epoch, txs, h0) in &ztr_examples {
        println!("  ztr example: epoch={epoch} txs={txs} hash0=0x{h0:02x}");
    }
    Ok(())
}
