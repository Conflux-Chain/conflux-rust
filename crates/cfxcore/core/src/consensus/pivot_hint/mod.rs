//! Pivot hint provides validation support during blockchain synchronization and
//! historical data execution by leveraging trusted pivot chain information from
//! authoritative sources.
//!
//! During the synchronization process of archive nodes, when processing
//! historical data, pivot hints help prevent execution on forked branches and
//! protect against problematic historical states that occurred on
//! mainnet/testnet chains.
//!
//! # File Structure
//! The pivot hint file consists of three main parts:
//! * Header Part (28 bytes): Contains configuration parameters
//! * Page Digests Part: A list of keccak hashes for each page
//! * Pages Part: Sequential storage of all pages
//!
//! # Page Organization
//! Blocks are organized into pages based on several configurable parameters:
//! * `range_max`: Upper bound (exclusive) of block heights for stored hashes
//! * `page_interval`: Number of consecutive blocks in each page
//! * Each page contains:
//!   - Major section: Full hashes for blocks every `major_interval` heights
//!   - Minor section: Hash prefixes (in length of `minor_hash_length`) for
//!     blocks every `minor_interval` heights
//!
//! # Parameter Constraints
//! The following parameters must maintain integer multiple relationships:
//! * `range_max` must be a multiple of `page_interval`
//! * `page_interval` must be a multiple of `major_interval`
//! * `major_interval` must be a multiple of `minor_interval`
//!
//! # Fork Validation
//! During fork validation, when the consensus layer attempts to switch the
//! pivot chain from branch A to branch B, it must provide:
//! * `fork_at`: The first block height where branch A and B diverge
//! * `me_height`: The last block height of branch B
//! * A query interface to retrieve block hashes on branch B within range
//!   [fork_at, me_height]
//!
//! The validation process follows these rules:
//! * If [fork_at, me_height] covers with major section records, validation uses
//!   the last recorded full hash
//! * If no major section records covered but minor section overlap exists,
//!   validation uses minor section records (note: this may allow switching to
//!   branches that aren't on the final main chain)
//! * If neither major nor minor section overlap exists, the switch is allowed
//!
//! When `fork_at` exceeds `range_max`, it indicates the fork point is beyond
//! the static file records, and the switch is automatically allowed.
//!
//! # Loading Process
//! 1. Load and validate Header Part parameters
//! 2. Load Page Digests Part and verify against predetermined Pivot Hint
//!    Checksum
//! 3. Keep Page Digests in memory
//! 4. Verify each page against Page Digests when loading to prevent corruption

mod config;
mod header;
mod page;
#[cfg(test)]
mod tests;

pub use config::PivotHintConfig;
use header::{PivotHintHeader, HEADER_LENGTH};
use page::PivotHintPage;

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::atomic::{AtomicBool, Ordering},
};

use crate::hash::{keccak, H256};
use lru_time_cache::LruCache;
use parking_lot::RwLock;

/// Manages pivot block hash records for chain fork validation during sync
/// process.
pub struct PivotHint {
    /// Path to the pivot hint file
    file_path: String,

    /// Module status flag. Set to false if error occurs, disabling the module
    /// without thread panic.
    active: AtomicBool,

    /// Pivot hint header with configuration parameters
    header: PivotHintHeader,

    /// LRU cache storing loaded pivot hint pages
    pages: RwLock<LruCache<u64, PivotHintPage>>,

    /// Keccak hashes of all pages, kept in memory for integrity verification
    page_digests: Vec<H256>,
}

impl PivotHint {
    /// Creates a new PivotHint instance by loading and validating the pivot
    /// hint file.
    ///
    /// # Steps
    /// 1. Loads and validates the header
    /// 2. Loads page digests and verifies against provided checksum
    /// 3. Initializes LRU cache for page data
    ///
    /// # Arguments
    /// * `conf` - Configuration containing file path and expected checksum
    ///
    /// # Errors
    /// * File open/read errors
    /// * Header parsing errors
    /// * Checksum mismatch
    pub fn new(conf: &PivotHintConfig) -> Result<Self, String> {
        let mut file = File::open(&conf.file_path)
            .map_err(|e| format!("Cannot open file: {:?}", e))?;
        let mut raw_header = [0u8; HEADER_LENGTH];
        file.read_exact(&mut raw_header)
            .map_err(|e| format!("Cannot load header: {:?}", e))?;
        let header = PivotHintHeader::from_raw(raw_header)
            .map_err(|e| format!("Cannot parse and check header: {}", e))?;

        let mut raw_page_digests = vec![0u8; header.page_number() * 32];
        file.read_exact(&mut raw_page_digests)
            .map_err(|e| format!("Cannot load page digests: {:?}", e))?;
        let file_checksum = keccak(&raw_page_digests);
        if file_checksum != conf.checksum {
            return Err("Incorrect checksum".into());
        }

        let page_digests = raw_page_digests
            .chunks_exact(32)
            .map(H256::from_slice)
            .collect();

        Ok(Self {
            file_path: conf.file_path.clone(),
            active: AtomicBool::new(true),
            header,
            pages: RwLock::new(LruCache::with_capacity(5)),
            page_digests,
        })
    }

    /// Validates if switching to a target branch is allowed based on pivot hint
    /// records.
    ///
    /// # Arguments
    /// * `fork_at` - First block height where the current chain and target
    ///   branch diverge
    /// * `me_height` - Last block height of the target branch
    /// * `ancestor_hash_at` - Callback to retrieve block hash at specified
    ///   height on target branch
    ///
    /// # Returns
    /// Returns whether switching to the fork branch is allowed.
    pub fn allow_switch(
        &self, fork_at: u64, me_height: u64,
        ancestor_hash_at: impl FnOnce(u64) -> H256,
    ) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return true;
        }

        if fork_at >= self.header.range_max {
            return true;
        }

        let check_height = if let Some(check_height) =
            self.header.compute_check_height(fork_at, me_height)
        {
            check_height
        } else {
            return true;
        };

        let actual_hash = ancestor_hash_at(check_height);
        let result = self.check_hash(check_height, actual_hash);
        debug!("Pivot hint check switch result {result}. fork_at: {fork_at}, me_height: {me_height}, check_height: {check_height}, fetch_hash: {actual_hash:?}");
        result
    }

    pub fn allow_extend(&self, height: u64, hash: H256) -> bool {
        if !self.active.load(Ordering::Acquire) {
            return true;
        }

        if height >= self.header.range_max {
            return true;
        }

        if height % self.header.minor_interval != 0 {
            return true;
        }

        let page_number = height / self.header.page_interval;
        let page_offset = height % self.header.page_interval;

        let result = self.check_with_page(page_number, |page| {
            page.check_hash_at_height(page_offset, hash)
        });
        debug!("Pivot hint check extend result {result}. me_height: {height}, fetch_hash: {hash:?}");
        result
    }

    pub fn is_active(&self) -> bool { self.active.load(Ordering::Acquire) }

    fn check_hash(&self, height: u64, hash: H256) -> bool {
        let page_number = height / self.header.page_interval;
        let page_offset = height % self.header.page_interval;

        self.check_with_page(page_number, |page| {
            page.check_hash_at_height(page_offset, hash)
        })
    }

    fn check_with_page(
        &self, page_number: u64, check: impl Fn(&PivotHintPage) -> bool,
    ) -> bool {
        let mut guard = self.pages.write();
        if let Some(page) = guard.get(&page_number) {
            check(page)
        } else {
            info!("Loading pivot hint page {}", page_number);
            let page = match self.load_page(page_number) {
                Ok(page) => page,
                Err(e) => {
                    warn!(
                        "Failed to load pivot hint page {}, pivot hint check disabled: {}",
                        page_number, e
                    );
                    self.active.store(false, Ordering::Release);
                    return true;
                }
            };
            let result = check(&page);
            guard.insert(page_number, page);
            result
        }
    }

    fn load_page(&self, page_number: u64) -> Result<PivotHintPage, String> {
        let page_bytes = self.header.page_bytes();
        let start_pos = HEADER_LENGTH as u64
            + self.page_digests.len() as u64 * 32
            + page_number * page_bytes as u64;

        let mut file = File::open(&self.file_path)
            .map_err(|e| format!("Cannot open pivot hint file: {:?}", e))?;

        file.seek(SeekFrom::Start(start_pos))
            .map_err(|e| format!("Cannot seek to start position: {:?}", e))?;

        let mut page_content = vec![0u8; page_bytes];
        file.read_exact(&mut page_content[..])
            .map_err(|e| format!("Cannot load the page: {:?}", e))?;

        let expected_page_checksum =
            if let Some(hash) = self.page_digests.get(page_number as usize) {
                hash
            } else {
                return Err("Empty page checksum".into());
            };

        let actual_page_checksum = keccak(&page_content);
        if expected_page_checksum != &actual_page_checksum {
            return Err("Incorrect checksum".into());
        }
        Ok(PivotHintPage::new(page_content, self.header))
    }
}
