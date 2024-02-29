use std::{cmp::Ordering, marker::PhantomData};

use cfx_types::U256;
use treap_map::{Direction, TreapMapConfig};

use crate::packing_batch::PackingBatch;

use super::{
    key_mng::PackingPoolExtMap, transaction::PackingPoolTransaction,
    weight::PackingPoolWeight,
};

pub(crate) struct PackingPoolMap<TX: PackingPoolTransaction>(PhantomData<TX>);

impl<TX: PackingPoolTransaction> TreapMapConfig for PackingPoolMap<TX> {
    type ExtMap = PackingPoolExtMap<TX::Sender>;
    type SearchKey = TX::Sender;
    type SortKey = U256;
    type Value = PackingBatch<TX>;
    type Weight = PackingPoolWeight;

    #[inline]
    fn next_node_dir(
        me: (&Self::SortKey, &Self::SearchKey),
        other: (&Self::SortKey, &Self::SearchKey),
    ) -> Option<Direction> {
        match me.0.cmp(other.0) {
            Ordering::Greater => {
                return Some(Direction::Left);
            }
            Ordering::Equal => {}
            Ordering::Less => {
                return Some(Direction::Right);
            }
        }
        match me.1.cmp(other.1) {
            Ordering::Less => Some(Direction::Left),
            Ordering::Equal => None,
            Ordering::Greater => Some(Direction::Right),
        }
    }
}
