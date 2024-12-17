use crate::hash::H256;

use super::PivotHintHeader;

/// A page of block hash data in the pivot hint file.
pub(super) struct PivotHintPage {
    /// Configuration parameters
    header: PivotHintHeader,

    /// Full block hashes at heights that are multiples of `major_interval` (32
    /// bytes per record)
    major_section: Vec<u8>,

    /// Hash prefixes at heights that are multiples of `minor_interval`
    /// (`minor_hash_length` bytes per record)
    minor_section: Vec<u8>,
}

impl PivotHintPage {
    pub fn new(mut page_content: Vec<u8>, header: PivotHintHeader) -> Self {
        let major_section_bytes = header.major_section_bytes();
        let minor_section = page_content.split_off(major_section_bytes);
        let major_section = page_content;
        Self {
            header,
            major_section,
            minor_section,
        }
    }

    pub fn check_hash_at_height(
        &self, page_offset: u64, actual_hash: H256,
    ) -> bool {
        if page_offset % self.header.major_interval == 0 {
            let major_index =
                (page_offset / self.header.major_interval) as usize;
            let len = 32;
            self.major_section[major_index * len..(major_index + 1) * len]
                == actual_hash[..len]
        } else {
            let minor_index =
                (page_offset / self.header.minor_interval) as usize;
            let len = self.header.minor_hash_length;
            self.minor_section[minor_index * len..(minor_index + 1) * len]
                == actual_hash[..len]
        }
    }
}
