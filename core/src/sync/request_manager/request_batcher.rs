use crate::sync::{
    message::{GetBlockHashesByEpoch, GetBlockHeaders, GetBlocks},
    request_manager::Request,
};
use cfx_types::H256;
use std::{cmp::min, time::Duration};

const DEFAULT_REQUEST_BATCHER_BUCKET_NUMBER: usize = 30;
const DEFAULT_REQUEST_HEADER_BATCH_SIZE: usize = 100;
const DEFAULT_REQUEST_BLOCK_BATCH_SIZE: usize = 50;
const DEFAULT_REQUEST_EPOCH_BATCH_SIZE: usize = 10;

/// Batch requests that are going to be resent.
/// Resent requests include: `GetBlockHeaders`, `GetBlockTxn`,
/// `GetBlockHashesByEpoch`, and `GetBlocks`. `GetBlockTxn` only includes one
/// block so cannot be batched.
pub struct RequestBatcher {
    /// Hashes in header requests
    headers: DelayBucket<H256>,

    /// Hashes in block requests
    /// TODO Handle with_public.
    blocks: DelayBucket<H256>,

    /// Epoch numbers in epoch requests
    epochs: DelayBucket<u64>,

    original_requests: Vec<(Duration, Box<dyn Request>)>,
}

impl RequestBatcher {
    pub fn new(bucket_size: Duration) -> Self {
        Self {
            headers: DelayBucket::new(
                DEFAULT_REQUEST_BATCHER_BUCKET_NUMBER,
                bucket_size,
            ),
            blocks: DelayBucket::new(
                DEFAULT_REQUEST_BATCHER_BUCKET_NUMBER,
                bucket_size,
            ),
            epochs: DelayBucket::new(
                DEFAULT_REQUEST_BATCHER_BUCKET_NUMBER,
                bucket_size,
            ),
            original_requests: Vec::new(),
        }
    }

    /// Insert request and its delay into this batcher
    /// TODO Remove these downcast.
    pub fn insert(&mut self, delay: Duration, mut request: Box<dyn Request>) {
        if let Some(header_req) =
            request.as_any_mut().downcast_mut::<GetBlockHeaders>()
        {
            self.headers.insert(&mut header_req.hashes, delay);
        } else if let Some(block_req) =
            request.as_any_mut().downcast_mut::<GetBlocks>()
        {
            self.blocks.insert(&mut block_req.hashes, delay);
        } else if let Some(epoch_req) =
            request.as_any_mut().downcast_mut::<GetBlockHashesByEpoch>()
        {
            self.epochs.insert(&mut epoch_req.epochs, delay);
        } else {
            self.original_requests.push((delay, request));
        }
    }

    /// Batch inserted requests according to their request types.
    /// Requests with close delays are batched together.
    pub fn get_batched_requests(
        mut self,
    ) -> impl Iterator<Item = (Duration, Box<dyn Request>)> {
        let mut requests = Vec::new();
        for (delay, hashes) in
            self.headers.batch_iter(DEFAULT_REQUEST_HEADER_BATCH_SIZE)
        {
            requests.push((
                delay,
                Box::new(GetBlockHeaders {
                    request_id: 0,
                    hashes,
                }) as Box<dyn Request>,
            ));
        }
        for (delay, hashes) in
            self.blocks.batch_iter(DEFAULT_REQUEST_BLOCK_BATCH_SIZE)
        {
            requests.push((
                delay,
                Box::new(GetBlocks {
                    request_id: 0,
                    hashes,
                    with_public: false,
                }) as Box<dyn Request>,
            ));
        }
        for (delay, epochs) in
            self.epochs.batch_iter(DEFAULT_REQUEST_EPOCH_BATCH_SIZE)
        {
            requests.push((
                delay,
                Box::new(GetBlockHashesByEpoch {
                    request_id: 0,
                    epochs,
                }) as Box<dyn Request>,
            ));
        }
        requests.append(&mut self.original_requests);
        requests.into_iter()
    }
}

/// Store requests with close delay to the same buckets.
struct DelayBucket<T> {
    /// Each bucket keeps the sum of request delays and the flattened request
    /// set in the bucket.
    buckets: Vec<(Duration, Vec<T>)>,

    /// requests with delay in [i*bucket_size, (i+1)*bucket_size) is stored in
    /// buckets i
    bucket_size: Duration,
}

impl<T> DelayBucket<T> {
    fn new(bucket_number: usize, bucket_size: Duration) -> Self {
        let mut buckets = Vec::with_capacity(bucket_number);
        for _ in 0..bucket_number {
            buckets.push((Duration::default(), Vec::new()));
        }
        Self {
            buckets,
            bucket_size,
        }
    }

    fn insert(&mut self, new_requests: &mut Vec<T>, delay: Duration) {
        let bucket_index = min(
            (delay.as_millis() / self.bucket_size.as_millis()) as usize,
            self.buckets.len() - 1,
        );
        let (delay_sum, requests) = &mut self.buckets[bucket_index];
        *delay_sum += delay * new_requests.len() as u32;
        requests.append(new_requests);
    }
}

impl<T: Clone> DelayBucket<T> {
    /// Return the batched requests with the given batch_size.
    /// The delay is the average of all requests in this bucket.
    fn batch_iter(
        &self, batch_size: usize,
    ) -> impl Iterator<Item = (Duration, Vec<T>)> {
        let mut batches = Vec::new();
        for (delay_sum, bucket) in &self.buckets {
            if bucket.is_empty() {
                continue;
            }
            let delay = *delay_sum / bucket.len() as u32;
            for batch in bucket.chunks(batch_size) {
                batches.push((delay, batch.to_vec()));
            }
        }
        batches.into_iter()
    }
}

#[test]
fn test_bucket_batch() {
    let mut bucket = DelayBucket::<usize>::new(5, Duration::from_secs(1));
    bucket.insert(&mut vec![1, 2, 3, 4, 5], Duration::from_millis(500));
    let mut iter = bucket.batch_iter(2);
    let item1 = iter.next();
    assert!(item1.is_some());
    let item1 = item1.unwrap();
    assert_eq!(item1.0, Duration::from_millis(500));
    assert_eq!(item1.1, vec![1, 2]);
    iter.next();
    let item3 = iter.next();
    assert!(item3.is_some());
    assert_eq!(item3.unwrap().1, vec![5]);
    let item4 = iter.next();
    assert!(item4.is_none());
}
