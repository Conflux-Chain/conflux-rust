use cfx_types::SignedBigNum;

pub struct FenwickTree {
    n: usize,
    a: Vec<SignedBigNum>,
}

impl FenwickTree {
    pub fn new() -> Self {
        let n = 32;
        let mut a = Vec::new();
        a.resize_with(n + 1, || SignedBigNum::zero());
        FenwickTree { n, a }
    }

    pub fn get_sum(&self, me: usize) -> Option<SignedBigNum> {
        // We increment the id by one to handle the 0 case
        let mut i = (me + 1) as i64;
        if me + 1 > self.n {
            return None;
        }
        let mut val = SignedBigNum::zero();
        while i > 0 {
            let lsb = i & (-i);
            val += self.a[i as usize];
            i -= lsb;
        }
        Some(val)
    }

    pub fn get(&self, me: usize) -> Option<SignedBigNum> {
        if me == 0 {
            return self.get_sum(0);
        }
        if let Some(a) = self.get_sum(me) {
            if let Some(b) = self.get_sum(me - 1) {
                Some(a - b)
            } else {
                None
            }
        } else {
            None
        }
    }

    fn grow_if_required(&mut self, me: usize) {
        if self.n < me {
            let old_last = self.a[self.n];
            self.n = self.n << 1;
            self.a.resize_with(self.n + 1, || SignedBigNum::zero());
            self.a[self.n] = old_last;
        }
    }

    pub fn add(&mut self, me: usize, val: &SignedBigNum) {
        // We increment the id by one to handle the 0 case
        let mut i = (me + 1) as i64;
        self.grow_if_required(i as usize);
        while i as usize <= self.n {
            let lsb = i & (-i);
            self.a[i as usize] += *val;
            i += lsb;
        }
    }
}
