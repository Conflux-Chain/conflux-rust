// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate ethereum_types;

pub use ethereum_types::{
    Address, Bloom, BloomInput, Public, Secret, Signature, H128, H160, H256,
    H512, H520, H64, U128, U256, U512, U64,
};
use std::{cmp::Ordering, convert, ops};

pub fn into_i128(num: &U256) -> i128 {
    (num.0[0] as i128) | ((num.0[1] as i128) << 64)
}

pub fn into_u256(num: i128) -> U256 {
    assert!(num >= 0);
    U256([(num & ((1i128 << 64) - 1)) as u64, (num >> 64) as u64, 0, 0])
}

#[derive(Copy, Clone, Eq, Debug)]
pub struct SignedBigNum {
    sign: bool,
    num: U256,
}

impl SignedBigNum {
    pub fn zero() -> Self {
        Self {
            sign: false,
            num: U256::zero(),
        }
    }

    pub fn neg(num: U256) -> Self { Self { sign: true, num } }

    pub fn pos(num: U256) -> Self { Self { sign: false, num } }

    pub fn negate(signed_num: &SignedBigNum) -> SignedBigNum {
        if signed_num.num == U256::zero() {
            signed_num.clone()
        } else {
            SignedBigNum {
                sign: !signed_num.sign,
                num: signed_num.num.clone(),
            }
        }
    }
}

impl convert::From<U256> for SignedBigNum {
    fn from(num: U256) -> Self { Self { sign: false, num } }
}

impl convert::From<SignedBigNum> for U256 {
    fn from(signed_num: SignedBigNum) -> Self {
        assert!(!signed_num.sign);
        signed_num.num
    }
}

impl ops::Add<SignedBigNum> for SignedBigNum {
    type Output = SignedBigNum;

    fn add(self, other: SignedBigNum) -> SignedBigNum {
        if self.sign == other.sign {
            SignedBigNum {
                sign: self.sign,
                num: self.num + other.num,
            }
        } else if self.num == other.num {
            SignedBigNum::zero()
        } else if self.num < other.num {
            SignedBigNum {
                sign: other.sign,
                num: other.num - self.num,
            }
        } else {
            SignedBigNum {
                sign: self.sign,
                num: self.num - other.num,
            }
        }
    }
}

impl ops::AddAssign<SignedBigNum> for SignedBigNum {
    fn add_assign(&mut self, other: SignedBigNum) {
        if self.sign == other.sign {
            self.num += other.num;
        } else if self.num == other.num {
            self.sign = false;
            self.num = U256::zero();
        } else if self.num < other.num {
            self.sign = other.sign;
            self.num = other.num - self.num;
        } else {
            self.num -= other.num;
        }
    }
}

impl ops::Sub<SignedBigNum> for SignedBigNum {
    type Output = SignedBigNum;

    fn sub(self, other: SignedBigNum) -> SignedBigNum {
        self + SignedBigNum::negate(&other)
    }
}

impl ops::SubAssign<SignedBigNum> for SignedBigNum {
    fn sub_assign(&mut self, other: SignedBigNum) {
        *self += SignedBigNum::negate(&other);
    }
}

impl Ord for SignedBigNum {
    fn cmp(&self, other: &SignedBigNum) -> Ordering {
        if self.sign != other.sign {
            return if self.sign {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        if self.num == other.num {
            return Ordering::Equal;
        }

        if self.sign {
            if self.num < other.num {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        } else {
            if self.num < other.num {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        }
    }
}

impl PartialOrd for SignedBigNum {
    fn partial_cmp(&self, other: &SignedBigNum) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SignedBigNum {
    fn eq(&self, other: &SignedBigNum) -> bool {
        self.sign == other.sign && self.num == other.num
    }
}
