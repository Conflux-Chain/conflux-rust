use anyhow::{Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if args.len() != 1 {
        eprintln!("usage: ckpt-roundtrip <checkpoint.bin>");
        std::process::exit(2);
    }
    let src = &args[0];

    let original = std::fs::read(src)
        .with_context(|| format!("read {}", src.display()))?;
    eprintln!("original: {} bytes", original.len());

    let ckpt = cfx_replay_data_executor::checkpoint::Checkpoint::load(src)?
        .context("no checkpoint")?;
    eprintln!("loaded: height={}", ckpt.height());

    // Full save round-trip
    let dir = tempfile::tempdir().context("tempdir")?;
    let full_path = dir.path().join("full.bin");
    ckpt.save(&full_path).context("save full")?;
    let resaved_full = std::fs::read(&full_path).context("read resaved full")?;
    eprintln!("resaved (full): {} bytes", resaved_full.len());

    if original == resaved_full {
        eprintln!("PASS: full save is byte-identical to original");
    } else {
        eprintln!("FAIL: full save differs from original");
        eprintln!("  original len={} resaved len={}", original.len(), resaved_full.len());
        let first_diff = original.iter().zip(resaved_full.iter())
            .position(|(a, b)| a != b);
        if let Some(pos) = first_diff {
            eprintln!("  first diff at byte {}: orig=0x{:02x} resaved=0x{:02x}", pos, original[pos], resaved_full[pos]);
        }
        std::process::exit(1);
    }

    // Streaming save round-trip
    let stream_path = dir.path().join("stream.bin");
    ckpt.save_streaming_self(&stream_path).context("save streaming")?;
    let resaved_stream = std::fs::read(&stream_path).context("read resaved stream")?;
    eprintln!("resaved (streaming): {} bytes", resaved_stream.len());

    if original == resaved_stream {
        eprintln!("PASS: streaming save is byte-identical to original");
    } else {
        eprintln!("FAIL: streaming save differs from original");
        let first_diff = original.iter().zip(resaved_stream.iter())
            .position(|(a, b)| a != b);
        if let Some(pos) = first_diff {
            eprintln!("  first diff at byte {}: orig=0x{:02x} resaved=0x{:02x}", pos, original[pos], resaved_stream[pos]);
        }
        std::process::exit(1);
    }

    Ok(())
}
