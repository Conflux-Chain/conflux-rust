// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use super::super::{
    consensus_inner::{NULL, NULLU64},
    ConsensusGraphInner, DEFERRED_STATE_EPOCH_COUNT,
};

use cfx_types::H256;
use parking_lot::RwLock;
use std::{cmp::min, collections::VecDeque, convert::TryFrom};

pub const MIN_MAINTAINED_RISK: f64 = 0.000001;
pub const MAX_NUM_MAINTAINED_RISK: usize = 10;

pub struct TotalWeightInPastMovingDelta {
    pub old: i128,
    pub cur: i128,
    pub delta: i128,
}

pub struct FinalityManager {
    pub lowest_epoch_num: u64,
    pub risks_less_than: VecDeque<f64>,
}

struct ConfirmationMeterInner {
    total_weight_in_past_2d: TotalWeightInPastMovingDelta,
    finality_manager: FinalityManager,
}

impl ConfirmationMeterInner {
    pub fn new() -> Self {
        Self {
            total_weight_in_past_2d: TotalWeightInPastMovingDelta {
                old: 0,
                cur: 0,
                delta: 0,
            },
            finality_manager: FinalityManager {
                lowest_epoch_num: 0,
                risks_less_than: VecDeque::new(),
            },
        }
    }
}

pub struct ConfirmationMeter {
    inner: RwLock<ConfirmationMeterInner>,
}

impl ConfirmationMeter {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(ConfirmationMeterInner::new()),
        }
    }

    pub fn reset(&self) {
        let mut inner = self.inner.write();
        inner.total_weight_in_past_2d = TotalWeightInPastMovingDelta {
            old: 0,
            cur: 0,
            delta: 0,
        };
        inner.finality_manager = FinalityManager {
            lowest_epoch_num: 0,
            risks_less_than: VecDeque::new(),
        };
    }

    pub fn update_total_weight_in_past(&self) {
        let mut inner = self.inner.write();
        let total_weight = &mut inner.total_weight_in_past_2d;
        total_weight.delta = total_weight.cur - total_weight.old;
        total_weight.old = total_weight.cur;
    }

    pub fn aggregate_total_weight_in_past(&self, weight: i128) {
        let mut inner = self.inner.write();
        let total_weight = &mut inner.total_weight_in_past_2d;
        total_weight.cur += weight;
    }

    pub fn reset_for_checkpoint(&self, total_weight: i128, stable_height: u64) {
        let mut inner = self.inner.write();
        let change = inner.total_weight_in_past_2d.cur - total_weight;
        inner.total_weight_in_past_2d.cur = total_weight;
        inner.total_weight_in_past_2d.old -= change;

        if stable_height > inner.finality_manager.lowest_epoch_num {
            let gap = stable_height - inner.finality_manager.lowest_epoch_num;
            for _i in 0..gap {
                inner.finality_manager.risks_less_than.pop_front();
            }
            inner.finality_manager.lowest_epoch_num = stable_height;
        }
    }

    fn get_total_weight_in_past(&self) -> i128 {
        let inner = self.inner.read();
        inner.total_weight_in_past_2d.delta
    }

    // FIXME: For now we sync at checkpoint rather than the latest snapshot,
    // FIXME: therefore we fake the confirmed epoch_num by passing it.
    pub fn get_confirmed_epoch_num(
        &self, keep_snapshot_till_cur_era_genesis_height: u64,
    ) -> u64 {
        let x = self.inner.read().finality_manager.lowest_epoch_num;
        if x > 0 {
            min(x - 1, keep_snapshot_till_cur_era_genesis_height)
        } else {
            0
        }
    }

    pub fn confirmation_risk_by_hash(
        &self, g_inner: &ConsensusGraphInner, hash: H256,
    ) -> Option<f64> {
        let index = *g_inner.hash_to_arena_indices.get(&hash)?;
        let epoch_num = g_inner.arena[index].data.epoch_number;
        if epoch_num == NULLU64 {
            return None;
        }

        if epoch_num == 0 {
            return Some(0.0);
        }

        let finality = &self.inner.read().finality_manager;

        if epoch_num < finality.lowest_epoch_num {
            return Some(MIN_MAINTAINED_RISK);
        }

        let idx = (epoch_num - finality.lowest_epoch_num) as usize;
        if idx < finality.risks_less_than.len() {
            let mut max_risk = 0.0;
            for i in 0..idx + 1 {
                let risk = *finality.risks_less_than.get(i).unwrap();
                if max_risk < risk {
                    max_risk = risk;
                }
            }
            Some(max_risk)
        } else {
            None
        }
    }

    fn confirmation_risk(
        &self, g_inner: &ConsensusGraphInner, w_0: i128, w_4: i128,
        epoch_num: u64,
    ) -> f64
    {
        // Compute w_1
        let idx = g_inner.get_pivot_block_arena_index(epoch_num);
        let w_1 = g_inner.block_weight(idx, false /* inclusive */);

        // Compute w_2
        let parent = g_inner.arena[idx].parent;
        assert!(parent != NULL);
        let mut max_weight = 0;
        for child in g_inner.arena[parent].children.iter() {
            if *child == idx || g_inner.arena[*child].data.partial_invalid {
                continue;
            }

            let child_weight =
                g_inner.block_weight(*child, false /* inclusive */);
            if child_weight > max_weight {
                max_weight = child_weight;
            }
        }
        let w_2 = max_weight;

        // Compute w_3
        let w_3 = g_inner.arena[idx].past_weight;

        // Compute d
        let d = i128::try_from(g_inner.current_difficulty.low_u128()).unwrap();

        // Compute n
        let w_2_4 = w_2 + w_4;
        let n = if w_1 >= w_2_4 { w_1 - w_2_4 } else { 0 };

        let n = (n / d) + 1;

        // Compute m
        let m = if w_0 >= w_3 { w_0 - w_3 } else { 0 };

        let m = m / d;

        // Compute risk
        let m_2 = 2i128 * m;
        let e_1 = m_2 / 5i128;
        let e_2 = m_2 / 7i128;
        let n_min_1 = e_1 + 13i128;
        let n_min_2 = e_2 + 36i128;
        let n_min = if n_min_1 < n_min_2 { n_min_1 } else { n_min_2 };

        let mut risk = 0.9;
        if n <= n_min {
            return risk;
        }

        risk = 0.0001;

        let n_min_1 = e_1 + 19i128;
        let n_min_2 = e_2 + 57i128;
        let n_min = if n_min_1 < n_min_2 { n_min_1 } else { n_min_2 };

        if n <= n_min {
            return risk;
        }

        risk = 0.000001;
        risk
    }

    pub fn update_confirmation_risks(&self, g_inner: &ConsensusGraphInner) {
        if g_inner.pivot_chain.len() > DEFERRED_STATE_EPOCH_COUNT as usize {
            let w_0 = g_inner
                .weight_tree
                .get(g_inner.cur_era_genesis_block_arena_index);
            let mut risks = VecDeque::new();
            let mut epoch_num = g_inner
                .pivot_index_to_height(g_inner.pivot_chain.len())
                - DEFERRED_STATE_EPOCH_COUNT;
            let mut count = 0;
            while epoch_num > 0 && count < MAX_NUM_MAINTAINED_RISK {
                let w_4 = self.get_total_weight_in_past();
                let risk = self.confirmation_risk(g_inner, w_0, w_4, epoch_num);
                if risk <= MIN_MAINTAINED_RISK {
                    break;
                }
                risks.push_front(risk);
                epoch_num -= 1;
                count += 1;
            }

            if risks.is_empty() {
                epoch_num = 0;
            } else {
                epoch_num += 1;
            }

            let mut finality = &mut self.inner.write().finality_manager;
            finality.lowest_epoch_num = epoch_num;
            finality.risks_less_than = risks;
        }
    }
}
