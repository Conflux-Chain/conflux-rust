use rangetools::Rangetools;
use std::io::Read;

pub const HEADER_LENGTH: usize = 28;

#[derive(Clone, Copy, Debug)]
pub(super) struct PivotHintHeader {
    pub minor_interval: u64,
    pub major_interval: u64,
    pub page_interval: u64,
    pub range_max: u64,
    pub minor_hash_length: usize,
}

fn read_u32(mut reader: impl Read) -> Result<u32, String> {
    let mut raw = [0u8; 4];
    reader
        .read_exact(&mut raw)
        .map_err(|e| format!("Cannot load number {:?}", e))?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(mut reader: impl Read) -> Result<u64, String> {
    let mut raw = [0u8; 8];
    reader
        .read_exact(&mut raw)
        .map_err(|e| format!("Cannot load number {:?}", e))?;
    Ok(u64::from_le_bytes(raw))
}

impl PivotHintHeader {
    pub fn from_raw(raw_header: [u8; HEADER_LENGTH]) -> Result<Self, String> {
        let mut reader = &raw_header[..];

        let minor_interval = read_u32(&mut reader).unwrap() as u64;
        let major_interval = read_u32(&mut reader).unwrap() as u64;
        let page_interval = read_u32(&mut reader).unwrap() as u64;
        let range_max = read_u64(&mut reader).unwrap();
        let minor_hash_length = read_u32(&mut reader).unwrap() as usize;

        if major_interval % minor_interval != 0 {
            return Err("Inconsistent header params: major_interval".into());
        }

        if page_interval % major_interval != 0 {
            return Err("Inconsistent header params: page_interval".into());
        }

        if range_max % page_interval != 0 {
            return Err("Inconsistent header params: range_max".into());
        }

        let header = PivotHintHeader {
            major_interval,
            minor_interval,
            minor_hash_length,
            range_max,
            page_interval,
        };

        let page_bytes = read_u32(&mut reader).unwrap() as usize;
        if header.page_bytes() != page_bytes {
            return Err("Inconsistent page bytes".into());
        }
        assert!(reader.is_empty());

        Ok(header)
    }

    pub fn major_section_bytes(&self) -> usize {
        (32 * (self.page_interval / self.major_interval)) as usize
    }

    pub fn minor_section_bytes(&self) -> usize {
        self.minor_hash_length
            * (self.page_interval / self.minor_interval) as usize
    }

    pub fn page_bytes(&self) -> usize {
        self.major_section_bytes() + self.minor_section_bytes()
    }

    pub fn page_number(&self) -> usize {
        (self.range_max / self.page_interval) as usize
    }

    pub fn compute_check_height(
        &self, fork_at: u64, me_height: u64,
    ) -> Option<u64> {
        let major_ticks = ((fork_at - 1) / self.major_interval + 1)
            ..=(me_height / self.major_interval);
        let availd_major_ticks = 0..(self.range_max / self.major_interval);
        let last_valid_major_tick = major_ticks
            .intersection(availd_major_ticks)
            .into_iter()
            .next_back();
        let major_height =
            last_valid_major_tick.map(|x| x * self.major_interval);

        if cfg!(test) {
            assert!(major_height.map_or(true, |h| h >= fork_at
                && h <= me_height
                && h % self.major_interval == 0
                && h < self.range_max));
        }

        let minor_ticks = ((fork_at - 1) / self.minor_interval + 1)
            ..=(me_height / self.minor_interval);
        let availd_minor_ticks = 0..(self.range_max / self.minor_interval);
        let last_valid_minor_tick = minor_ticks
            .intersection(availd_minor_ticks)
            .into_iter()
            .next_back();
        let minor_height =
            last_valid_minor_tick.map(|x| x * self.minor_interval);
        if cfg!(test) {
            assert!(minor_height.map_or(true, |h| h >= fork_at
                && h <= me_height
                && h % self.minor_interval == 0
                && h < self.range_max));
        }

        major_height.or(minor_height)
    }
}
