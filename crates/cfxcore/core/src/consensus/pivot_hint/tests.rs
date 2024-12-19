use rand::{thread_rng, RngCore};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    str::FromStr,
};

use crate::hash::H256;

use super::{PivotHint, PivotHintConfig};

pub struct TestHashFile {
    file: File,
}

impl TestHashFile {
    fn new() -> Self {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test_data")
            .join("sample_pivot_hash.bin");
        Self {
            file: File::open(path).unwrap(),
        }
    }

    fn hash_at_height(&mut self, height: u64) -> H256 {
        assert!(height < 1_000_000);
        assert!(height % 5 == 0);

        self.file.seek(SeekFrom::Start((height / 5) * 32)).unwrap();
        let mut answer = H256::default();
        self.file.read_exact(&mut answer.0).unwrap();

        answer
    }
}

fn make_test_pivot_hint() -> PivotHint {
    let file_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("sample_pivot_hint.bin");
    let checksum = H256::from_str(
        "28dcd783ff03d7f9718e95e52c9d56174d83faaa25aaeb9c6cc1dd7239d3069e",
    )
    .unwrap();
    let config = PivotHintConfig::new(file_path.to_str().unwrap(), checksum);
    PivotHint::new(&config).unwrap()
}

#[test]
fn test_pivot_hint() {
    let pivot_hint = make_test_pivot_hint();
    let mut test_file = TestHashFile::new();

    let mut rng = thread_rng();
    for _ in 0..100_000 {
        let fork_at = rng.next_u64() % 1_500_000;
        if fork_at == 0 {
            continue;
        }

        let diff = match rng.next_u64() % 3 {
            0 => rng.next_u64() % 10,
            1 => rng.next_u64() % 200,
            2 => rng.next_u64() % (1_500_000 - fork_at),
            _ => unreachable!(),
        };

        let me_height = fork_at + diff;

        let success = rng.next_u64() % 2 == 0;
        let mut manipulated = false;

        let allow_switch =
            pivot_hint.allow_switch(fork_at, me_height, |height| {
                let mut hash = test_file.hash_at_height(height);
                if !success {
                    hash.0[0] ^= 0x80;
                    manipulated = true;
                }
                hash
            });

        assert_eq!(allow_switch, !manipulated);
        assert!(pivot_hint.is_active());
    }
}
