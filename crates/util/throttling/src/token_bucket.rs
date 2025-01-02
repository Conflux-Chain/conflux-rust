// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use malloc_size_of::MallocSizeOf;
use malloc_size_of_derive::MallocSizeOf as DeriveMallocSizeOf;
use parking_lot::Mutex;
use std::{
    cmp::{max, min},
    collections::HashMap,
    fs::read_to_string,
    hash::Hash,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Debug, Eq, PartialEq)]
pub enum ThrottleResult {
    Success,
    Throttled(Duration),
    AlreadyThrottled,
}

#[derive(DeriveMallocSizeOf)]
pub struct ThrottleTokens {
    max_tokens: u64,    // maximum tokens allowed in bucket
    cur_tokens: u64,    // current tokens in bucket
    recharge_rate: u64, // recharge N tokens per second
    default_cost: u64,  // default tokens to acquire once
}

impl ThrottleTokens {
    pub fn new(
        max_tokens: u64, cur_tokens: u64, recharge_rate: u64, default_cost: u64,
    ) -> Self {
        ThrottleTokens {
            max_tokens,
            cur_tokens,
            recharge_rate,
            default_cost,
        }
    }
}

#[derive(DeriveMallocSizeOf)]
pub struct TokenBucket {
    cpu_tokens: ThrottleTokens,
    message_size_tokens: ThrottleTokens,
    last_update: Instant,
    // once acquire failed, record the next time to acquire tokens
    throttled_until: Option<Instant>,
    // client may send multiple requests in a short time, and the
    // `throttled_counter` is used to tolerate throttling instead
    // of disconnect the client directly.
    throttled_counter: u64,
    max_throttled_counter: u64,
}

impl TokenBucket {
    pub fn new(
        max_cpu_tokens: u64, cur_cpu_tokens: u64, cpu_token_recharge_rate: u64,
        default_cpu_cost: u64, max_message_tokens: u64,
        cur_message_tokens: u64, message_token_recharge_rate: u64,
        default_message_cost: u64,
    ) -> Self {
        assert!(cur_cpu_tokens <= max_cpu_tokens);
        assert!(cur_message_tokens <= max_message_tokens);

        TokenBucket {
            cpu_tokens: ThrottleTokens::new(
                max_cpu_tokens,
                cur_cpu_tokens,
                cpu_token_recharge_rate,
                default_cpu_cost,
            ),
            message_size_tokens: ThrottleTokens::new(
                max_message_tokens,
                cur_message_tokens,
                message_token_recharge_rate,
                default_message_cost,
            ),
            last_update: Instant::now(),
            throttled_until: None,
            throttled_counter: 0,
            max_throttled_counter: 0,
        }
    }

    pub fn full(
        max_cpu_tokens: u64, cpu_token_recharge_rate: u64,
        default_cpu_cost: u64, max_message_tokens: u64,
        message_token_recharge_rate: u64, default_message_cost: u64,
    ) -> Self {
        Self::new(
            max_cpu_tokens,
            max_cpu_tokens,
            cpu_token_recharge_rate,
            default_cpu_cost,
            max_message_tokens,
            max_message_tokens,
            message_token_recharge_rate,
            default_message_cost,
        )
    }

    pub fn empty(
        max_cpu_tokens: u64, cpu_token_recharge_rate: u64,
        default_cpu_cost: u64, max_message_tokens: u64,
        message_token_recharge_rate: u64, default_message_cost: u64,
    ) -> Self {
        Self::new(
            max_cpu_tokens,
            0, /* cur_cpu_tokens */
            cpu_token_recharge_rate,
            default_cpu_cost,
            max_message_tokens,
            0, /* cur_message_tokens */
            message_token_recharge_rate,
            default_message_cost,
        )
    }

    pub fn set_max_throttled_counter(&mut self, max_throttled_counter: u64) {
        self.max_throttled_counter = max_throttled_counter;
    }

    fn refresh(&mut self, now: Instant) {
        let elapsed_secs = (now - self.last_update).as_secs();
        if elapsed_secs == 0 {
            return;
        }

        let cpu_recharged = self.cpu_tokens.recharge_rate * elapsed_secs;
        self.cpu_tokens.cur_tokens = min(
            self.cpu_tokens.max_tokens,
            self.cpu_tokens.cur_tokens + cpu_recharged,
        );
        let message_recharged =
            self.message_size_tokens.recharge_rate * elapsed_secs;
        self.message_size_tokens.cur_tokens = min(
            self.message_size_tokens.max_tokens,
            self.message_size_tokens.cur_tokens + message_recharged,
        );
        self.last_update += Duration::from_secs(elapsed_secs);
    }

    fn try_acquire_cost(
        &mut self, cpu_cost: u64, message_size_cost: u64,
    ) -> Result<(), Duration> {
        let now = Instant::now();

        self.refresh(now);

        if cpu_cost <= self.cpu_tokens.cur_tokens
            && message_size_cost <= self.message_size_tokens.cur_tokens
        {
            // tokens enough
            self.cpu_tokens.cur_tokens -= cpu_cost;
            self.message_size_tokens.cur_tokens -= message_size_cost;
            return Ok(());
        }

        // tokens not enough and throttled
        let cpu_recharge_secs = if cpu_cost > self.cpu_tokens.cur_tokens {
            ((cpu_cost - self.cpu_tokens.cur_tokens) as f64
                / self.cpu_tokens.recharge_rate as f64)
                .ceil() as u64
        } else {
            0
        };
        let message_recharge_secs = if message_size_cost
            > self.message_size_tokens.cur_tokens
        {
            ((message_size_cost - self.message_size_tokens.cur_tokens) as f64
                / self.message_size_tokens.recharge_rate as f64)
                .ceil() as u64
        } else {
            0
        };
        let recharge_secs = max(cpu_recharge_secs, message_recharge_secs);
        // `refresh` ensures the difference in `self.last_update` and `now` is
        // less than 1 second, and `recharge_secs` is at least 1 second,
        // so this will not underflow.
        Err(self.last_update + Duration::from_secs(recharge_secs) - now)
    }

    pub fn throttle_default(&mut self) -> ThrottleResult {
        self.throttle(
            self.cpu_tokens.default_cost,
            self.message_size_tokens.default_cost,
        )
    }

    pub fn throttle(
        &mut self, cpu_cost: u64, message_size_cost: u64,
    ) -> ThrottleResult {
        let now = Instant::now();

        // already throttled
        if let Some(until) = self.throttled_until {
            if now < until {
                if self.throttled_counter < self.max_throttled_counter {
                    self.throttled_counter += 1;
                    return ThrottleResult::Throttled(until - now);
                } else {
                    return ThrottleResult::AlreadyThrottled;
                }
            } else {
                self.throttled_until = None;
                self.throttled_counter = 0;
            }
        }

        match self.try_acquire_cost(cpu_cost, message_size_cost) {
            Ok(_) => ThrottleResult::Success,
            Err(wait_time) => {
                self.throttled_until = Some(now + wait_time);
                ThrottleResult::Throttled(wait_time)
            }
        }
    }
}

impl FromStr for TokenBucket {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let fields: Vec<&str> = s.split(',').collect();

        if fields.len() != 5 {
            return Err(format!(
                "invalid number of fields, expected = 9, actual = {}",
                fields.len()
            ));
        }

        let mut nums = Vec::new();

        for f in fields {
            let num = u64::from_str(f)
                .map_err(|e| format!("failed to parse number: {:?}", e))?;
            nums.push(num);
        }

        // TODO: Correctly set the message token information.
        let mut bucket =
            TokenBucket::new(nums[0], nums[1], nums[2], nums[3], 1, 1, 1, 0);
        bucket.set_max_throttled_counter(nums[4]);

        Ok(bucket)
    }
}

#[derive(Default, DeriveMallocSizeOf, Clone)]
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

    pub fn get(&self, name: &str) -> Option<Arc<Mutex<TokenBucket>>> {
        self.buckets.get(name).cloned()
    }

    pub fn load(
        toml_file: &str, section: Option<&str>,
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

#[derive(Default, DeriveMallocSizeOf)]
pub struct ThrottledManager<K: Eq + Hash + MallocSizeOf> {
    items: HashMap<K, Instant>,
}

impl<K: Eq + Hash + MallocSizeOf> ThrottledManager<K> {
    pub fn set_throttled(&mut self, k: K, until: Instant) {
        let current = self.items.entry(k).or_insert(until);
        if *current < until {
            *current = until;
        }
    }

    pub fn check_throttled(&mut self, k: &K) -> bool {
        let until = match self.items.get(k) {
            Some(until) => until,
            None => return false,
        };

        if Instant::now() < *until {
            return true;
        }

        self.items.remove(k);

        false
    }
}

#[cfg(test)]
mod tests {
    use crate::token_bucket::{ThrottleResult, TokenBucket};
    use std::{thread::sleep, time::Duration};

    #[test]
    fn test_init_tokens() {
        // empty bucket
        let mut bucket = TokenBucket::empty(3, 1, 1, 3, 1, 1);
        assert!(
            bucket.try_acquire_cost(1, 1).unwrap_err()
                <= Duration::from_secs(1)
        );

        // 1 token
        let mut bucket = TokenBucket::new(3, 1, 1, 1, 3, 1, 1, 1);
        assert!(
            bucket.try_acquire_cost(2, 2).unwrap_err()
                <= Duration::from_secs(1)
        );
        assert_eq!(bucket.try_acquire_cost(1, 1), Ok(()));
    }

    #[test]
    fn test_acquire() {
        let mut bucket = TokenBucket::full(3, 1, 1, 3, 1, 1);

        // Token enough
        assert_eq!(bucket.try_acquire_cost(1, 1), Ok(()));
        assert_eq!(bucket.try_acquire_cost(2, 2), Ok(()));

        // Token not enough
        assert!(
            bucket.try_acquire_cost(1, 1).unwrap_err()
                <= Duration::from_secs(1)
        );
        assert!(
            bucket.try_acquire_cost(2, 2).unwrap_err()
                <= Duration::from_secs(2)
        );

        // Sleep 0.5s, but not recharged
        sleep(Duration::from_millis(500));
        assert!(
            bucket.try_acquire_cost(1, 1).unwrap_err()
                <= Duration::from_millis(500)
        );

        // Sleep 0.5s, and recharged 1 token
        sleep(Duration::from_millis(500));

        // cannot acquire 2 tokens since only 1 recharged
        assert!(
            bucket.try_acquire_cost(2, 2).unwrap_err()
                <= Duration::from_secs(1)
        );

        // acquire the recharged 1 token
        assert_eq!(bucket.try_acquire_cost(1, 1), Ok(()));
    }

    fn assert_throttled(result: ThrottleResult, wait_time: Duration) {
        match result {
            ThrottleResult::Throttled(d) => assert!(d <= wait_time),
            _ => panic!("invalid throttle result"),
        }
    }

    #[test]
    fn test_throttled() {
        // empty bucket
        let mut bucket = TokenBucket::empty(3, 1, 1, 3, 1, 1);

        // throttled
        assert_throttled(bucket.throttle(1, 1), Duration::from_secs(1));

        // already throttled
        assert_eq!(bucket.throttle(1, 1), ThrottleResult::AlreadyThrottled);

        sleep(Duration::from_secs(1));

        assert_eq!(bucket.throttle(1, 1), ThrottleResult::Success);
        assert_eq!(bucket.throttled_until, None);
        assert_eq!(bucket.throttled_counter, 0);
    }

    #[test]
    fn test_tolerate_throttling() {
        // empty bucket
        let mut bucket = TokenBucket::empty(3, 1, 1, 3, 1, 1);
        bucket.set_max_throttled_counter(2);

        // throttled
        assert_throttled(bucket.throttle(1, 1), Duration::from_secs(1));

        // tolerate another 2 times
        assert_throttled(bucket.throttle(1, 1), Duration::from_secs(1));
        assert_throttled(bucket.throttle(1, 1), Duration::from_secs(1));

        // already throttled
        assert_eq!(bucket.throttle(1, 1), ThrottleResult::AlreadyThrottled);
    }
}
