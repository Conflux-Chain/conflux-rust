use cfx_types::SignedBigNum;

pub struct TreeArray {
    n: usize,
    a: Vec<SignedBigNum>,
}

impl TreeArray {
    pub fn new() -> Self {
        let n = 5;
        let mut a = Vec::new();
        a.resize_with(1 << n, || SignedBigNum::zero());
        TreeArray { n, a }
    }

    pub fn get_sum(&self, me: usize) -> Option<SignedBigNum> {
        if me >= (1 << self.n) {
            return None;
        }
        let mut val = self.a[me];
        let mut x = me;
        for i in 0..self.n {
            let y = 1 << i;
            if ((x & y) == 0) && (x > y) {
                x = x - y;
                val += self.a[x];
            }
        }
        Some(val)
    }

    pub fn get(&self, me: usize) -> Option<SignedBigNum> {
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
        if (1 << self.n) <= me {
            let old_last = self.a[(1 << self.n) - 1];
            self.n += 1;
            self.a.resize_with(1 << self.n, || SignedBigNum::zero());
            self.a[1 << self.n - 1] = old_last;
        }
    }

    pub fn update(&mut self, me: usize, val: SignedBigNum) {
        self.grow_if_required(me);
        self.a[me] += val;
        let mut x = me;
        for i in 0..self.n {
            let y = 1 << i;
            if (y & x) == 0 {
                x = x | y;
                self.a[x] += val;
            }
        }
    }
}
