use cfx_rpc_eth_types::Bytes;
use primitives::transaction::eth_transaction::eip155_signature;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

pub(crate) fn skip_test(path: &Path) -> bool {
    if contains_meta_dir(path) {
        return true;
    }

    let name = path.file_name().unwrap().to_str().unwrap();

    matches!(
        name,
        // Tests not valid at Prague
        "intrinsicCancun.json"

        // Unreasonable test cases and also skipped by revm (fails in revm)
        | "RevertInCreateInInitCreate2Paris.json"
        | "create2collisionStorageParis.json"
        | "dynamicAccountOverwriteEmpty_Paris.json"
        | "InitCollisionParis.json"
        | "RevertInCreateInInit_Paris.json"

        // ## These tests are passing, but they take a lot of time to execute so we are going to skip them.
        // | "loopExp.json"
        // | "Call50000_sha256.json"
        // | "static_Call50000_sha256.json"
        | "loopMul.json"
        | "CALLBlake2f_MaxRounds.json"
    )
}

/// Check if the path matches `.meta/**`.
fn contains_meta_dir(path: &Path) -> bool {
    path.iter()
        .any(|c| c.to_str().map_or(false, |s| s == ".meta"))
}

#[allow(unused)]
pub(crate) fn allowed_test(path: &Path, matches: Option<&str>) -> bool {
    if matches.is_none() {
        return true;
    }

    let name = path.file_name().unwrap().to_str().unwrap();

    if name == matches.unwrap() {
        return true;
    }

    false
}

pub(crate) fn find_all_json_tests(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension() == Some("json".as_ref()))
            .map(DirEntry::into_path)
            .collect()
    }
}

// 1. Check if the input bytes is a rlp list
// 2. If it is, rlp decode the raw tx
// 3. Check the v value (the third from the last), if it is bigger than 28, then
//    it include the chainId info
pub(crate) fn extract_155_chain_id_from_raw_tx(
    raw_tx: &Option<Bytes>,
) -> Option<u64> {
    match raw_tx {
        Some(raw_tx) => match is_rlp_list(&raw_tx.0) {
            true => {
                let rlp_list = rlp::Rlp::new(&raw_tx.0);
                let item_count = rlp_list.item_count().ok()?;
                let v = rlp_list.val_at::<u64>(item_count - 3).ok()?;
                eip155_signature::extract_chain_id_from_legacy_v(v)
            }
            false => None, // not a 155 tx
        },
        None => None,
    }
}

fn is_rlp_list(raw: &[u8]) -> bool { !raw.is_empty() && raw[0] >= 0xc0 }
