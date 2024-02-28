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

    pub fn len(&self) -> usize { self.inner.len() }

    pub fn iter(&self) -> Iter<StatusItem> { self.inner.iter() }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Default)]
#[cfg_attr(any(test, feature = "fuzzing"), derive(Arbitrary))]
pub struct NodeLockStatus {
    pub in_queue: StatusList,
    pub locked: u64,
    pub out_queue: StatusList,
    unlocked: u64,

    // Equals to the summation of in_queue + locked
    available_votes: u64,

    // Record the view being forced retire.
    force_retired: Option<View>,
    // If the staking is forfeited, the unlocked votes before forfeiting is
    // exempted.
    exempt_from_forfeit: Option<u64>,
}

impl NodeLockStatus {
    pub fn available_votes(&self) -> u64 {
        if self.exempt_from_forfeit.is_some() {
            0
        } else {
            self.available_votes
        }
    }

    pub fn unlocked_votes(&self) -> u64 {
        self.exempt_from_forfeit.unwrap_or(self.unlocked)
    }

    pub fn forfeited(&self) -> u64 { self.unlocked - self.unlocked_votes() }

    pub fn force_retired(&self) -> Option<u64> { self.force_retired }

    pub fn exempt_from_forfeit(&self) -> Option<u64> {
        self.exempt_from_forfeit
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

        if self.exempt_from_forfeit.is_some() {
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
        if self.force_retired.is_none() {
            self.force_retired = Some(view);
            callback_views
                .push(view + POS_STATE_CONFIG.force_retired_locked_views(view));
            self.new_unlock(view, self.available_votes, callback_views);
        }
    }

    pub(super) fn forfeit(&mut self) {
        if self.exempt_from_forfeit.is_some() {
            return;
        }
        self.exempt_from_forfeit = Some(self.unlocked)
    }
}

#[allow(dead_code)]
pub mod tests {
    use super::*;
    use std::collections::HashSet;

    enum Operation {
        NewLock(u64),
        NewUnlock(u64),
        ForceRetire,
        Forfeit,
        AssertAvailable(u64),
        AssertLocked(u64),
        AssertUnlocked(u64),
    }

    use Operation::*;

    fn run_tasks(tasks: Vec<(Operation, View)>) {
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
                    Operation::Forfeit => lock_status.forfeit(),
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

    // #[test]
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

    // #[test]
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

    // #[test]
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

    pub fn run_all() {
        basic();
        increase_during_exit();
        force_retire();
        resolve_retired();
    }
}
