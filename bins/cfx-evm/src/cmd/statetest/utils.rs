use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

pub(crate) fn skip_test(path: &Path) -> bool {
    let name = path.file_name().unwrap().to_str().unwrap();

    matches!(
        name,
        // Funky test with `bigint 0x00` value in json :) not possible to
        // happen on mainnet and require custom json parser. https://github.com/ethereum/tests/issues/971
        |"ValueOverflow.json"| "ValueOverflowParis.json"

        // Precompiles having storage is not possible
        | "RevertPrecompiledTouch_storage.json"
        | "RevertPrecompiledTouch.json"

        // `txbyte` is of type 02 and we don't parse tx bytes for this test to fail.
        | "typeTwoBerlin.json"

        // Need to handle Test errors
        | "transactionIntinsicBug.json"

        // Test check if gas price overflows, we handle this correctly but does not match tests specific exception.
        | "HighGasPrice.json"
        | "CREATE_HighNonce.json"
        | "CREATE_HighNonceMinus1.json"
        | "CreateTransactionHighNonce.json"

        // Skip test where basefee/accesslist/difficulty is present but it shouldn't be supported in
        // London/Berlin/TheMerge. https://github.com/ethereum/tests/blob/5b7e1ab3ffaf026d99d20b17bb30f533a2c80c8b/GeneralStateTests/stExample/eip1559.json#L130
        // It is expected to not execute these tests.
        | "basefeeExample.json"
        | "eip1559.json"
        | "mergeTest.json"

        // Test with some storage check.
        | "RevertInCreateInInit_Paris.json"
        | "RevertInCreateInInit.json"
        | "dynamicAccountOverwriteEmpty.json"
        | "dynamicAccountOverwriteEmpty_Paris.json"
        | "RevertInCreateInInitCreate2Paris.json"
        | "create2collisionStorage.json"
        | "RevertInCreateInInitCreate2.json"
        | "create2collisionStorageParis.json"
        | "InitCollision.json"
        | "InitCollisionParis.json"

        // These tests are passing, but they take a lot of time to execute so we are going to skip them.
        | "loopExp.json"
        | "Call50000_sha256.json"
        | "static_Call50000_sha256.json"
        | "loopMul.json"
        | "CALLBlake2f_MaxRounds.json"
    )
}

pub(crate) fn find_all_json_tests(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        vec![path.to_path_buf()]
    } else {
        WalkDir::new(path)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| e.path().extension() == Some("json".as_ref()))
            .map(DirEntry::into_path)
            .collect()
    }
}
