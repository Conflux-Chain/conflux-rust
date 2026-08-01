use std::{
    collections::{vec_deque::Iter, VecDeque},
    fmt::Debug,
};

use serde::{Deserialize, Serialize};

#[cfg(any(test, feature = "fuzzing"))]
use proptest_derive::Arbitrary;

use diem_logger::prelude::*;

use crate::{
    block_info::View,
    term_state::pos_state_config::{PosStateConfigTrait, POS_STATE_CONFIG},
};

#[derive(Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct StatusItem {
    pub view: View,
    pub votes: u64,
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct StatusList {
    inner: VecDeque<StatusItem>,
    sorted: bool,
}

impl Default for StatusList {
    fn default() -> Self {
        Self {
            inner: VecDeque::new(),
            sorted: true,
        }
    }
}

impl StatusList {
    /// Push a given `StatusItem` into list and record it into `update_views`.
    fn push(
        &mut self, exit_view: View, votes: u64, update_views: &mut Vec<View>,
    ) {
        // If the pushed item breaks the ascending order of list, set
        // `self.sorted` to false.
        if self
            .inner
            .back()
            .map_or(false, |item| item.view > exit_view)
        {
            self.sorted = false;
        }
        self.inner.push_back(StatusItem {
            view: exit_view,
            votes,
        });
        update_views.push(exit_view);
    }

    /// Pull the first item from list. If `votes` of the first item exceed
    /// `required_votes`, the rest votes will be put back.
    fn pull(&mut self, required_votes: u64) -> Option<StatusItem> {
        self.sort();
        if let Some(item) = self.inner.pop_front() {
            if item.votes <= required_votes {
                Some(item)
            } else {
                let rest_votes = item.votes - required_votes;
                self.inner.push_front(StatusItem {
                    view: item.view,
                    votes: rest_votes,
                });
                Some(StatusItem {
                    view: item.view,
                    votes: required_votes,
                })
            }
        } else {
            None
        }
    }

    /// Pop the first item if its view is no larger than given `view`.
    fn pop_by_view(&mut self, view: View) -> Option<StatusItem> {
        self.sort();
        if let Some(item) = self.inner.pop_front() {
            if item.view > view {
                self.inner.push_front(item);
                None
            } else {
                Some(item)
            }
        } else {
            None
        }
    }

    fn sort(&mut self) {
        if !self.sorted {
            self.inner
                .make_contiguous()
                .sort_unstable_by_key(|item| item.view);
            self.sorted = true;
        }
    }

    fn clear(&mut self) {
        self.inner.clear();
        self.sorted = true;
    }

    pub fn len(&self) -> usize { self.inner.len() }

    pub fn is_empty(&self) -> bool { self.inner.is_empty() }

    pub fn iter(&self) -> Iter<'_, StatusItem> { self.inner.iter() }

    fn total(&self) -> u64 { self.inner.iter().map(|item| item.votes).sum() }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Default)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct NodeLockStatus {
    pub in_queue: StatusList,
    pub locked: u64,
    pub out_queue: StatusList,
    unlocked: u64,

    // Cache of `active_votes()`, kept equal to it by every write below.
    available_votes: u64,

    // Record the view being forced retire.
    force_retired: Option<View>,
    // Set by a pre-CIP-156 dispute, which froze the withdrawable amount
    // instead of relocking. Everything above the frozen value is forfeited.
    legacy_withdrawable_cap: Option<u64>,
}

/// Three different quantities that were all once called "votes":
/// `active_votes` is the stake that has not started leaving, `available_votes`
/// is the same masked by a legacy forfeit, and `unlocked_votes` is what the
/// operator can actually withdraw.
impl NodeLockStatus {
    fn active_votes(&self) -> u64 { self.in_queue.total() + self.locked }

    pub fn available_votes(&self) -> u64 {
        if self.legacy_withdrawable_cap.is_some() {
            0
        } else {
            self.available_votes
        }
    }

    pub fn unlocked_votes(&self) -> u64 {
        self.legacy_withdrawable_cap.unwrap_or(self.unlocked)
    }

    pub fn forfeited(&self) -> u64 { self.unlocked - self.unlocked_votes() }

    pub fn force_retired(&self) -> Option<u64> { self.force_retired }

    pub fn legacy_withdrawable_cap(&self) -> Option<u64> {
        self.legacy_withdrawable_cap
    }
}

impl NodeLockStatus {
    pub(super) fn update(&mut self, view: View) -> bool {
        let mut new_votes_unlocked = false;

        while let Some(item) = self.in_queue.pop_by_view(view) {
            self.locked += item.votes;
        }

        while let Some(item) = self.out_queue.pop_by_view(view) {
            self.unlocked += item.votes;
            new_votes_unlocked = true;
        }

        if self.force_retired.map_or(false, |retire_view| {
            view >= retire_view
                + POS_STATE_CONFIG.force_retired_locked_views(view)
        }) {
            self.force_retired = None;
        }

        if self.legacy_withdrawable_cap.is_some() {
            new_votes_unlocked = false
        }

        new_votes_unlocked
    }

    pub(super) fn new_lock(
        &mut self, view: View, votes: u64, initialize_mode: bool,
        update_views: &mut Vec<View>,
    ) {
        if votes == 0 {
            return;
        }

        if initialize_mode {
            self.available_votes += votes;
            self.locked += votes;
            return;
        }

        // If force retired is not none, new locked tokens will be forced
        // retire.
        if self.force_retired.is_some() {
            let exit_view = view
                + POS_STATE_CONFIG.in_queue_locked_views(view)
                + POS_STATE_CONFIG.out_queue_locked_views(view);
            self.out_queue.push(exit_view, votes, update_views);
        } else {
            self.available_votes += votes;
            let exit_view = view + POS_STATE_CONFIG.in_queue_locked_views(view);
            self.in_queue.push(exit_view, votes, update_views);
        }
    }

    pub(super) fn new_unlock(
        &mut self, view: View, to_unlock_votes: u64,
        update_views: &mut Vec<View>,
    ) {
        if to_unlock_votes == 0 {
            return;
        }

        let before_available_votes = self.available_votes;
        let mut rest_votes = to_unlock_votes;

        // First, we try to unlock votes from self.locked
        let votes = rest_votes.min(self.locked);
        if votes > 0 {
            rest_votes -= votes;
            self.locked -= votes;
            self.available_votes -= votes;

            let exit_view =
                view + POS_STATE_CONFIG.out_queue_locked_views(view);
            self.out_queue.push(exit_view, votes, update_views);
        }

        // Then, we try to unlock votes from `in_queue`, ordered by timestamp.
        while rest_votes > 0 {
            let maybe_item = self.in_queue.pull(rest_votes);

            if maybe_item.is_none() {
                diem_warn!(
                    "Not enough votes to unlock: before available votes {}, to unlock votes {}, rest votes {}.",
                    before_available_votes,
                    to_unlock_votes,
                    rest_votes
                );
                break;
            }

            let item = maybe_item.unwrap();

            rest_votes -= item.votes;
            self.available_votes -= item.votes;

            let exit_view =
                item.view + POS_STATE_CONFIG.out_queue_locked_views(view);
            self.out_queue.push(exit_view, item.votes, update_views);
        }
    }

    pub(super) fn force_retire(
        &mut self, view: View, callback_views: &mut Vec<View>,
    ) {
        if self.force_retired.is_some() {
            return;
        }
        // Drain first: `new_unlock` must see the pre-retirement status, and
        // draining before the flag is set keeps `available_votes` consistent
        // at every point rather than only on return. The unmasked
        // `active_votes()` — a legacy-forfeited node still has stake to
        // retire, and the masked accessor would report none.
        self.new_unlock(view, self.active_votes(), callback_views);
        self.force_retired = Some(view);
        callback_views
            .push(view + POS_STATE_CONFIG.force_retired_locked_views(view));
    }

    pub(super) fn forfeit(
        &mut self, view: View, updated_views: &mut Vec<View>,
    ) {
        if self.legacy_withdrawable_cap.is_some() {
            return;
        }
        match POS_STATE_CONFIG.dispute_locked_views(view) {
            None => self.legacy_withdrawable_cap = Some(self.unlocked),
            Some(dispute_locked_views) => {
                // Active stake excludes out_queue, so a fully-retired node
                // (stake only in out_queue) escaped the lock before the fix.
                let relock = self.active_votes() > 0
                    || (POS_STATE_CONFIG.dispute_lock_includes_out_queue(view)
                        && !self.out_queue.is_empty());
                if relock {
                    // We will lock all votes in `in_queue`, `locked`, and
                    // `out_queue`.
                    let mut to_lock_votes = self.active_votes();
                    self.in_queue.clear();
                    self.locked = 0;
                    self.available_votes = 0;

                    while let Some(item) = self.out_queue.pop_by_view(u64::MAX)
                    {
                        to_lock_votes += item.votes;
                    }
                    // `force_retired` is deliberately preserved: a dispute is
                    // a stronger accusation than the inactivity that triggers
                    // force retirement and must not lift the no-new-active-
                    // deposit restriction. Expiry now rests entirely on the
                    // callback `force_retire` scheduled.
                    self.out_queue.push(
                        view.saturating_add(dispute_locked_views),
                        to_lock_votes,
                        updated_views,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::term_state::pos_state_config::test_config;
    use std::collections::HashSet;

    enum Operation {
        NewLock(u64),
        NewUnlock(u64),
        ForceRetire,
        Forfeit,
        AssertAvailable(u64),
        AssertLocked(u64),
        AssertUnlocked(u64),
        /// `(exit view, votes)` in stored order, which is what gets
        /// serialized — a test that only compared the multiset would not
        /// notice a rule that reshuffles the queue.
        AssertOutQueue(Vec<(View, u64)>),
        AssertForceRetired(bool),
    }

    use Operation::*;

    /// Runs `tasks` against a fresh status, one view per iteration.
    ///
    /// The `update_view > view` filter below has no counterpart in
    /// `PosState::record_update_views`, which inserts every supplied view. So
    /// this harness cannot show whether an operation strands a past-dated
    /// hint; assert that at the `PosState` level instead.
    fn run_tasks(tasks: Vec<(Operation, View)>) {
        test_config::install();
        let mut tasks: VecDeque<(Operation, View)> = tasks.into();

        let mut lock_status = NodeLockStatus::default();
        let mut hint_views = HashSet::<View>::new();
        let mut view = 0;

        while !(tasks.is_empty() && hint_views.is_empty()) {
            if hint_views.contains(&view) {
                lock_status.update(view);
                hint_views.remove(&view);
            }

            let mut update_views = Vec::new();

            while tasks.front().map(|x| x.1) == Some(view) {
                match tasks.pop_front().unwrap().0 {
                    Operation::NewLock(votes) => {
                        lock_status.new_lock(
                            view,
                            votes,
                            false,
                            &mut update_views,
                        );
                    }
                    Operation::NewUnlock(votes) => {
                        lock_status.new_unlock(view, votes, &mut update_views);
                    }
                    Operation::ForceRetire => {
                        lock_status.force_retire(view, &mut update_views);
                    }
                    Operation::Forfeit => {
                        lock_status.forfeit(view, &mut update_views)
                    }
                    Operation::AssertAvailable(votes) => {
                        if lock_status.available_votes != votes {
                            panic!("View {}\n {:?}", view, lock_status);
                        }
                    }
                    Operation::AssertLocked(votes) => {
                        if lock_status.locked != votes {
                            panic!("View {}\n {:?}", view, lock_status);
                        }
                    }
                    Operation::AssertUnlocked(votes) => {
                        if lock_status.unlocked_votes() != votes {
                            panic!("View {}\n {:?}", view, lock_status);
                        }
                    }
                    Operation::AssertOutQueue(expected) => {
                        let actual: Vec<(View, u64)> = lock_status
                            .out_queue
                            .iter()
                            .map(|item| (item.view, item.votes))
                            .collect();
                        assert_eq!(
                            actual, expected,
                            "out_queue at view {}\n {:?}",
                            view, lock_status
                        );
                    }
                    Operation::AssertForceRetired(expected) => {
                        assert_eq!(
                            lock_status.force_retired.is_some(),
                            expected,
                            "force_retired at view {}\n {:?}",
                            view,
                            lock_status
                        );
                    }
                }
            }

            for update_view in update_views {
                if update_view > view {
                    hint_views.insert(update_view);
                }
            }
            view += 1;
        }
    }

    #[test]
    fn basic() {
        let one_vote = vec![
            (NewLock(1), 2),
            (AssertAvailable(1), 3),
            (AssertLocked(1), 10082),
            (NewUnlock(1), 20000),
            (AssertAvailable(0), 20001),
            (AssertUnlocked(0), 20002),
            (AssertUnlocked(1), 30080),
        ];

        let multi_vote = vec![
            (NewLock(10), 2u64),
            (AssertAvailable(10), 3),
            (AssertLocked(10), 10082),
            (NewUnlock(7), 20000),
            (AssertAvailable(3), 20001),
            (AssertUnlocked(0), 20002),
            (AssertUnlocked(7), 30080),
            (AssertAvailable(3), 30081),
        ];

        run_tasks(one_vote);
        run_tasks(multi_vote);
    }

    #[test]
    fn increase_during_exit() {
        let tasks = vec![
            (NewLock(10), 2),
            (AssertAvailable(10), 3),
            (NewLock(5), 4),
            (AssertAvailable(15), 5),
            (NewUnlock(7), 20000),
            (AssertAvailable(8), 20001),
            (NewLock(5), 20002),
            (AssertAvailable(13), 20003),
            (NewUnlock(7), 20004),
            (AssertAvailable(6), 20005),
            (AssertUnlocked(0), 20005),
            (NewUnlock(3), 20006),
            (AssertUnlocked(7), 30080),
            (AssertUnlocked(14), 30084),
            (AssertUnlocked(15), 30086),
            (AssertUnlocked(15), 40161),
            (AssertUnlocked(17), 40162),
        ];

        run_tasks(tasks);
    }

    #[test]
    fn force_retire() {
        let tasks = vec![
            (NewLock(6), 2),
            (AssertAvailable(6), 3),
            (NewLock(7), 12),
            (AssertAvailable(13), 13),
            (AssertLocked(6), 10090),
            (ForceRetire, 10090),
            (NewLock(8), 10092),
            (AssertAvailable(0), 10093),
            (AssertLocked(0), 10093),
            (AssertUnlocked(0), 20169),
            (AssertUnlocked(6), 20170),
            (NewLock(9), 20170),
            (AssertAvailable(9), 20171),
            (AssertUnlocked(13), 20172),
            (AssertLocked(0), 30249),
            (AssertLocked(9), 30250),
            (AssertUnlocked(13), 30251),
            (AssertUnlocked(21), 30252),
        ];

        run_tasks(tasks);
    }

    /// Characterization of #3524, which this branch builds on: a node whose
    /// stake sits entirely in `out_queue` has `available_votes == 0`, and
    /// before CIP-173 that alone let it escape the dispute lock.
    #[test]
    fn forfeit_relocks_fully_retired_after_cip173() {
        let retire = test_config::CIP173_TRANSITION + 1000;
        let exit = retire + test_config::OUT_QUEUE_VIEWS;
        let dispute = retire + 1;
        let tasks = vec![
            (NewLock(10), 2),
            (NewUnlock(10), retire),
            (AssertOutQueue(vec![(exit, 10)]), retire + 1),
            (Forfeit, dispute),
            (
                AssertOutQueue(vec![(
                    dispute + test_config::DISPUTE_LOCKED_VIEWS,
                    10,
                )]),
                dispute + 1,
            ),
        ];

        run_tasks(tasks);
    }

    /// A dispute is a stronger accusation than the inactivity that triggers
    /// force retirement, so it must not lift the restriction. `force_retired`
    /// is the only reachable abnormal state to combine with a dispute:
    /// deposits made while it is set are routed straight to `out_queue`, so
    /// the node has no active stake to hold.
    #[test]
    fn forfeit_preserves_force_retired() {
        let retire = test_config::CIP173_TRANSITION + 500;
        let dispute = retire + 100;
        let deadline = dispute + test_config::DISPUTE_LOCKED_VIEWS;
        let tasks = vec![
            (NewLock(10), 2),
            (ForceRetire, retire),
            (AssertForceRetired(true), retire + 1),
            (Forfeit, dispute),
            (AssertForceRetired(true), dispute + 1),
            (AssertOutQueue(vec![(deadline, 10)]), dispute + 1),
            (AssertUnlocked(10), deadline + 1),
        ];

        run_tasks(tasks);
    }

    /// The same state one gate earlier: CIP-156 is active, so the dispute is
    /// not a legacy forfeit, but the relock still skips `out_queue`.
    #[test]
    fn forfeit_noop_on_fully_retired_before_cip173() {
        let retire = test_config::CIP156_TRANSITION + 5000;
        let exit = retire + test_config::OUT_QUEUE_VIEWS;
        let dispute = retire + 1000;
        let tasks = vec![
            (NewLock(10), 2),
            (NewUnlock(10), retire),
            (Forfeit, dispute),
            (AssertOutQueue(vec![(exit, 10)]), dispute + 1),
            (AssertAvailable(0), dispute + 1),
        ];

        run_tasks(tasks);
    }

    #[test]
    fn resolve_retired() {
        let tasks = vec![
            (NewLock(6), 2),
            (AssertAvailable(6), 3),
            (ForceRetire, 10),
            (NewLock(8), 10090),
            (AssertAvailable(8), 10091),
        ];

        run_tasks(tasks);
    }
}
