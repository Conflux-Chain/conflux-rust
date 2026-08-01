use std::{
    collections::{vec_deque::Iter, VecDeque},
    fmt::Debug,
};

use anyhow::{anyhow, Result};
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
            // `force_retire` schedules one callback and nothing reschedules
            // it, so the delay has to be read at the view that scheduled it.
            // Reading it here instead means a delay that changed in between
            // makes the callback fire at a view its own condition rejects,
            // leaving the flag set with nothing left to clear it.
            let delay_view = if POS_STATE_CONFIG
                .force_retire_expiry_uses_retire_view(view)
            {
                retire_view
            } else {
                view
            };
            // Saturating, not checked: this bounds a restriction rather than
            // an exit view, so an absurd configured delay should mean "never
            // expires" and not a panic.
            view >= retire_view.saturating_add(
                POS_STATE_CONFIG.force_retired_locked_views(delay_view),
            )
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
        &mut self, view: View, rule: ForfeitRule, updated_views: &mut Vec<View>,
    ) -> Result<()> {
        if self.legacy_withdrawable_cap.is_some() {
            return Ok(());
        }
        match rule {
            ForfeitRule::FreezeWithdrawable => {
                self.legacy_withdrawable_cap = Some(self.unlocked);
            }
            ForfeitRule::RelockActive { deadline } => {
                // Active stake excludes out_queue, so a node whose stake is
                // entirely on its way out escapes this rule.
                if self.active_votes() > 0 {
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
                    // deposit restriction. Expiry rests entirely on the
                    // callback `force_retire` scheduled.
                    self.out_queue.push(deadline, to_lock_votes, updated_views);
                }
            }
            ForfeitRule::RelockAll { deadline } => {
                self.relock_all(view, deadline, updated_views)?;
            }
        }
        Ok(())
    }

    /// Hold every piece of stake until `deadline`, or until its own ordinary
    /// exit if that falls later.
    ///
    /// Per item rather than one collapsed entry, because collapsing gets it
    /// wrong in opposite directions: collapsing onto `deadline` alone lets
    /// nearly-stale evidence *shorten* the wait on stake that had not started
    /// leaving, making the penalty a way around the withdrawal delay, while
    /// collapsing onto the latest floor drags the older stake out to a later
    /// deposit's exit.
    ///
    /// It is also what makes resubmitting the same evidence a no-op: every
    /// item already sits at or after `deadline`, so the `max` reproduces the
    /// list unchanged.
    fn relock_all(
        &mut self, view: View, deadline: View, updated_views: &mut Vec<View>,
    ) -> Result<()> {
        let out_delay = POS_STATE_CONFIG.out_queue_locked_views(view);
        // Every fallible exit is computed before anything is drained, so a
        // rejected relock leaves the status untouched rather than half-empty.
        let mut relocked =
            Vec::with_capacity(self.in_queue.len() + self.out_queue.len() + 1);
        for item in self.in_queue.iter() {
            let ordinary_exit =
                item.view.checked_add(out_delay).ok_or_else(|| {
                    anyhow!("in_queue ordinary exit view overflows")
                })?;
            relocked.push((ordinary_exit.max(deadline), item.votes));
        }
        if self.locked > 0 {
            let ordinary_exit =
                view.checked_add(out_delay).ok_or_else(|| {
                    anyhow!("locked ordinary exit view overflows")
                })?;
            relocked.push((ordinary_exit.max(deadline), self.locked));
        }
        for item in self.out_queue.iter() {
            relocked.push((item.view.max(deadline), item.votes));
        }
        if relocked.is_empty() {
            return Ok(());
        }

        self.in_queue.clear();
        self.locked = 0;
        self.available_votes = 0;
        self.out_queue.clear();
        for (exit_view, votes) in relocked {
            self.out_queue.push(exit_view, votes, updated_views);
        }
        Ok(())
    }
}

/// The three penalties a dispute has carried, kept apart because they share
/// the same fields and a predicate written for one silently rewrites the
/// others. `PosState` picks exactly one, so the rule and the deadline it was
/// derived from cannot disagree.
pub(super) enum ForfeitRule {
    /// Pre-CIP-156: freeze what is withdrawable and forfeit the rest.
    FreezeWithdrawable,
    /// CIP-156: collapse the active stake into a single entry at `deadline`,
    /// measured from the submission.
    RelockActive { deadline: View },
    /// CIP-173: hold every piece, `out_queue` included, until at least
    /// `deadline`, which is measured from the offence.
    RelockAll { deadline: View },
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
        Forfeit(ForfeitRule),
        AssertAvailable(u64),
        AssertLocked(u64),
        AssertUnlocked(u64),
        /// `(exit view, votes)` in stored order, which is what gets
        /// serialized — a test that only compared the multiset would not
        /// notice a rule that reshuffles the queue.
        AssertOutQueue(Vec<(View, u64)>),
        AssertForceRetired(bool),
        Snapshot,
        /// Whole-status equality, not a projection: idempotence has to hold
        /// for the bytes that get serialized, `StatusList::sorted` included.
        AssertUnchangedSinceSnapshot,
    }

    use ForfeitRule::*;
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
        let mut snapshot: Option<NodeLockStatus> = None;
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
                    Operation::Forfeit(rule) => lock_status
                        .forfeit(view, rule, &mut update_views)
                        .expect("forfeit"),
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
                    Operation::Snapshot => {
                        snapshot = Some(lock_status.clone());
                    }
                    Operation::AssertUnchangedSinceSnapshot => {
                        assert_eq!(
                            Some(&lock_status),
                            snapshot.as_ref(),
                            "changed since the snapshot, at view {}",
                            view
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

    /// Nothing detects a repeated dispute, so the same evidence stays valid
    /// forever and can be resubmitted by anyone. What keeps that from being a
    /// way to extend the lock indefinitely is that a second application at
    /// the same deadline leaves the status byte-identical.
    #[test]
    fn replay_at_the_same_deadline_changes_nothing() {
        let dispute = test_config::CIP173_TRANSITION + 1000;
        let deadline = dispute + test_config::DISPUTE_LOCKED_VIEWS;
        let tasks = vec![
            (NewLock(10), 2),
            (Forfeit(RelockAll { deadline }), dispute),
            (Snapshot, dispute + 1),
            (Forfeit(RelockAll { deadline }), dispute + 2),
            (AssertUnchangedSinceSnapshot, dispute + 3),
            (Forfeit(RelockAll { deadline }), dispute + 4),
            (AssertUnchangedSinceSnapshot, dispute + 5),
        ];

        run_tasks(tasks);
    }

    /// Stake deposited after the dispute is swept in by the next replay — the
    /// penalty is not escapable by re-staking — but it keeps its own later
    /// exit and does not drag the older stake along with it. Collapsing the
    /// two into one entry would extend a penalty the deadline had already
    /// fixed.
    #[test]
    fn a_later_deposit_gets_its_own_exit() {
        let dispute = test_config::CIP173_TRANSITION + 1000;
        // Short enough that the deposit's ordinary exit is the later of the
        // two; with a dominating deadline both would land on it and the
        // distinction this test exists for would be invisible.
        let deadline = dispute + test_config::OUT_QUEUE_VIEWS;
        let deposit = dispute + 100;
        let old_pile_exit = dispute + test_config::OUT_QUEUE_VIEWS;
        let deposit_exit = deposit
            + test_config::IN_QUEUE_VIEWS
            + test_config::OUT_QUEUE_VIEWS;
        let tasks = vec![
            (NewLock(10), 2),
            (Forfeit(RelockAll { deadline }), dispute),
            (NewLock(5), deposit),
            (AssertAvailable(5), deposit + 1),
            (Forfeit(RelockAll { deadline }), deposit + 1),
            (
                AssertOutQueue(vec![(deposit_exit, 5), (old_pile_exit, 10)]),
                deposit + 2,
            ),
            (Snapshot, deposit + 3),
            (Forfeit(RelockAll { deadline }), deposit + 4),
            (AssertUnchangedSinceSnapshot, deposit + 5),
        ];

        run_tasks(tasks);
    }

    /// A floor, never a ceiling. Evidence submitted just before it goes stale
    /// leaves almost no penalty, and stake that had not started leaving must
    /// still serve its ordinary withdrawal delay — otherwise a validator
    /// could arrange to be disputed on nearly-stale evidence and use the
    /// penalty to skip the queue.
    #[test]
    fn a_nearly_stale_deadline_does_not_release_locked_stake_early() {
        let dispute = test_config::CIP173_TRANSITION + 1000;
        let deadline = dispute + 1;
        let ordinary_exit = dispute + test_config::OUT_QUEUE_VIEWS;
        let tasks = vec![
            (NewLock(10), 2),
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertOutQueue(vec![(ordinary_exit, 10)]), dispute + 1),
            (AssertUnlocked(0), ordinary_exit - 1),
            (AssertUnlocked(10), ordinary_exit + 1),
        ];

        run_tasks(tasks);
    }

    /// The same floor rule for stake still maturing: its ordinary exit is
    /// measured from where it sits in `in_queue`, so a dispute cannot turn a
    /// fresh deposit into an early withdrawal either.
    #[test]
    fn a_nearly_stale_deadline_does_not_release_in_queue_stake_early() {
        let deposit = test_config::CIP173_TRANSITION + 500;
        let dispute = deposit + 1;
        let deadline = dispute + 1;
        let ordinary_exit = deposit
            + test_config::IN_QUEUE_VIEWS
            + test_config::OUT_QUEUE_VIEWS;
        let tasks = vec![
            (NewLock(10), deposit),
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertOutQueue(vec![(ordinary_exit, 10)]), dispute + 1),
            (AssertUnlocked(0), ordinary_exit - 1),
            (AssertUnlocked(10), ordinary_exit + 1),
        ];

        run_tasks(tasks);
    }

    /// Characterization of #3524, which this branch builds on: a node whose
    /// stake sits entirely in `out_queue` has no active stake, and under
    /// `RelockActive` that alone let it escape the dispute lock.
    #[test]
    fn relock_all_catches_a_fully_retired_node() {
        let retire = test_config::CIP173_TRANSITION + 1000;
        let exit = retire + test_config::OUT_QUEUE_VIEWS;
        let dispute = retire + 1;
        let deadline = dispute + test_config::DISPUTE_LOCKED_VIEWS;
        let tasks = vec![
            (NewLock(10), 2),
            (NewUnlock(10), retire),
            (AssertOutQueue(vec![(exit, 10)]), retire + 1),
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertOutQueue(vec![(deadline, 10)]), dispute + 1),
        ];

        run_tasks(tasks);
    }

    /// `force_retire` schedules exactly one callback and nothing reschedules
    /// it, so the expiry test has to agree with what was scheduled. Here the
    /// queue delay grows at `CIP136_TRANSITION`, between the retirement and
    /// its callback: reading today's delay makes the callback fire too early
    /// to satisfy its own condition, and the flag is then set forever.
    ///
    /// The retirement starts before `CIP173_TRANSITION` and the callback
    /// lands after it, which is the case the gate has to decide: gating on
    /// the callback view repairs the straddling nodes instead of leaving them
    /// on the defective rule permanently.
    #[test]
    fn force_retire_expiry_uses_the_scheduled_delay() {
        let retire =
            test_config::CIP136_TRANSITION - test_config::OUT_QUEUE_VIEWS;
        assert!(retire < test_config::CIP173_TRANSITION);
        let expiry = retire + test_config::OUT_QUEUE_VIEWS;
        assert!(expiry > test_config::CIP173_TRANSITION);
        let tasks = vec![
            (NewLock(10), 2),
            (ForceRetire, retire),
            (AssertForceRetired(true), expiry - 1),
            (AssertForceRetired(false), expiry + 1),
            // The restriction is what routes deposits away from active
            // stake, so a flag that never expires silently strands them.
            (NewLock(5), expiry + 1),
            (AssertAvailable(5), expiry + 2),
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
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertForceRetired(true), dispute + 1),
            (AssertOutQueue(vec![(deadline, 10)]), dispute + 1),
            (AssertUnlocked(10), deadline + 1),
        ];

        run_tasks(tasks);
    }

    /// The same state under the rule one gate earlier, which is still live
    /// for replay of the CIP-156 era.
    #[test]
    fn relock_active_leaves_a_fully_retired_node_alone() {
        let retire = test_config::CIP156_TRANSITION + 5000;
        let exit = retire + test_config::OUT_QUEUE_VIEWS;
        let dispute = retire + 1000;
        let deadline = dispute + test_config::DISPUTE_LOCKED_VIEWS;
        let tasks = vec![
            (NewLock(10), 2),
            (NewUnlock(10), retire),
            (Forfeit(RelockActive { deadline }), dispute),
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
