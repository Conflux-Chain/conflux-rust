// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use parking_lot::Mutex;
use std::{
    cmp::min,
    collections::HashMap,
    fs::read_to_string,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct TokenBucket {
    max_tokens: u64,    // maximum tokens allowed in bucket
    cur_tokens: u64,    // current tokens in bucket
    recharge_rate: u64, // recharge N tokens per second
    default_cost: u64,  // default tokens to acquire once
    last_update: Instant,

    // once acquire failed, record the next time to acquire tokens
    throttled: Option<Instant>,
}

impl TokenBucket {
    pub fn new(
        max_tokens: u64, cur_tokens: u64, recharge_rate: u64, default_cost: u64,
    ) -> Self {
        assert!(cur_tokens <= max_tokens);

        TokenBucket {
            max_tokens,
            cur_tokens,
            recharge_rate,
            default_cost,
            last_update: Instant::now(),
            throttled: None,
        }
    }

    pub fn full(
        max_tokens: u64, recharge_rate: u64, default_cost: u64,
    ) -> Self {
        Self::new(max_tokens, max_tokens, recharge_rate, default_cost)
    }

    pub fn empty(
        max_tokens: u64, recharge_rate: u64, default_cost: u64,
    ) -> Self {
        Self::new(max_tokens, 0, recharge_rate, default_cost)
    }

    fn refresh(&mut self) {
        let elapsed_secs = self.last_update.elapsed().as_secs();
        if elapsed_secs == 0 {
            return;
        }

        let recharged = self.recharge_rate * elapsed_secs;
        self.cur_tokens = min(self.max_tokens, self.cur_tokens + recharged);
        self.last_update += Duration::from_secs(elapsed_secs);
    }

    pub fn try_acquire(&mut self) -> Result<(), Duration> {
        self.try_acquire_cost(self.default_cost)
    }

    pub fn try_acquire_cost(&mut self, cost: u64) -> Result<(), Duration> {
        self.refresh();

        if cost <= self.cur_tokens {
            self.cur_tokens -= cost;
            self.throttled = None;
            return Ok(());
        }

        let recharge_secs = ((cost - self.cur_tokens) as f64
            / self.recharge_rate as f64)
            .ceil() as u64;

        let next_time = self.last_update + Duration::from_secs(recharge_secs);
        self.throttled = Some(next_time);

        let now = Instant::now();
        if next_time > now {
            Err(next_time - now)
        } else {
            self.try_acquire_cost(cost)
        }
    }

    pub fn update_recharge_rate(&mut self, rate: u64) {
        self.refresh();

        self.recharge_rate = rate;
    }

    pub fn throttled(&self) -> Option<Instant> { self.throttled }
}

impl FromStr for TokenBucket {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let fields: Vec<&str> = s.split(",").collect();

        if fields.len() != 4 {
            return Err(format!(
                "invalid number of fields, expected = 4, actual = {}",
                fields.len()
            ));
        }

        let mut nums = Vec::new();

        for f in fields {
            let num = u64::from_str(f)
                .map_err(|e| format!("failed to parse number: {:?}", e))?;
            nums.push(num);
        }

        Ok(TokenBucket::new(nums[0], nums[1], nums[2], nums[3]))
    }
}

#[derive(Default)]
pub struct TokenBucketManager {
    // manage buckets by name
    buckets: HashMap<String, Arc<Mutex<TokenBucket>>>,
}

impl TokenBucketManager {
    pub fn register(&mut self, name: String, bucket: TokenBucket) {
        if self.buckets.contains_key(&name) {
            panic!("token bucket {:?} already registered", name);
        }

        self.buckets.insert(name, Arc::new(Mutex::new(bucket)));
    }

    pub fn get(&self, name: &String) -> Option<Arc<Mutex<TokenBucket>>> {
        self.buckets.get(name).cloned()
    }

    pub fn load(
        toml_file: &String, section: Option<&str>,
    ) -> Result<Self, String> {
        let content = read_to_string(toml_file)
            .map_err(|e| format!("failed to read toml file: {:?}", e))?;
        let toml_val = content
            .parse::<toml::Value>()
            .map_err(|e| format!("failed to parse toml file: {:?}", e))?;

        let val = match section {
            Some(section) => match toml_val.get(section) {
                Some(val) => val,
                None => return Err(format!("section [{}] not found", section)),
            },
            None => &toml_val,
        };
        let table = val.as_table().expect("not table value");

        let mut manager = TokenBucketManager::default();

        for (k, v) in table.iter() {
            let v = match v.as_str() {
                Some(v) => v,
                None => {
                    return Err(format!(
                        "invalid value type {:?}, string type required",
                        v.type_str()
                    ))
                }
            };

            manager.register(k.into(), TokenBucket::from_str(v)?);
        }

        Ok(manager)
    }
}

#[cfg(test)]
mod tests {
    use crate::token_bucket::TokenBucket;
    use std::{thread::sleep, time::Duration};

    #[test]
    fn test_init_tokens() {
        // empty bucket
        let mut bucket = TokenBucket::empty(3, 1, 1);
        assert!(bucket.try_acquire().unwrap_err() < Duration::from_secs(1));

        // 1 token
        let mut bucket = TokenBucket::new(3, 1, 1, 1);
        assert!(
            bucket.try_acquire_cost(2).unwrap_err() < Duration::from_secs(1)
        );
        assert_eq!(bucket.try_acquire(), Ok(()));
    }

    #[test]
    fn test_acquire() {
        let mut bucket = TokenBucket::full(3, 1, 1);

        // Token enough
        assert_eq!(bucket.try_acquire(), Ok(()));
        assert_eq!(bucket.try_acquire_cost(2), Ok(()));

        // Token not enough
        assert!(bucket.try_acquire().unwrap_err() < Duration::from_secs(1));
        assert!(
            bucket.try_acquire_cost(2).unwrap_err() < Duration::from_secs(2)
        );

        // Sleep 0.5s, but not recharged
        sleep(Duration::from_millis(500));
        assert!(bucket.try_acquire().unwrap_err() < Duration::from_millis(500));

        // Sleep 0.5s, and recharged 1 token
        sleep(Duration::from_millis(500));

        // cannot acquire 2 tokens since only 1 recharged
        assert!(
            bucket.try_acquire_cost(2).unwrap_err() < Duration::from_secs(1)
        );

        // acquire the recharged 1 token
        assert_eq!(bucket.try_acquire(), Ok(()));
    }
}
