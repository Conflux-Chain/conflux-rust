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

/// Three quantities that were all once called "votes": stake that has not
/// started leaving, the same masked by a legacy forfeit, and what the operator
/// can withdraw.
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
    /// The delay is read at the view that scheduled the callback, because
    /// nothing reschedules it: a delay that changed in between would make the
    /// callback fire at a view its own condition rejects, leaving the flag set
    /// with nothing left to clear it.
    fn force_retirement_expired(&self, view: View) -> bool {
        self.force_retired.map_or(false, |retire_view| {
            let delay_view = if POS_STATE_CONFIG
                .force_retire_expiry_uses_retire_view(view)
            {
                retire_view
            } else {
                view
            };
            // Saturating because this bounds a restriction, not an exit view:
            // an absurd delay should mean "never expires", not a stranded
            // stake.
            view >= retire_view.saturating_add(
                POS_STATE_CONFIG.force_retired_locked_views(delay_view),
            )
        })
    }

    pub(super) fn update(&mut self, view: View) -> bool {
        let mut new_votes_unlocked = false;

        while let Some(item) = self.in_queue.pop_by_view(view) {
            self.locked += item.votes;
        }

        while let Some(item) = self.out_queue.pop_by_view(view) {
            self.unlocked += item.votes;
            new_votes_unlocked = true;
        }

        if self.force_retirement_expired(view) {
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

        // `next_view` consumes the hint whether or not the old predicate
        // cleared the flag, so a retirement whose only callback already fired
        // has nothing left to clear it. This is the one place the flag is
        // read. Gated, because pre-activation it would clear flags at views
        // production does not.
        if POS_STATE_CONFIG.force_retire_expiry_uses_retire_view(view)
            && self.force_retirement_expired(view)
        {
            self.force_retired = None;
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
        // Unmasked `active_votes()`: a legacy-forfeited node still has stake
        // to retire, and the masked accessor would report none. Draining
        // before the flag is set keeps the two consistent throughout rather
        // than only on return.
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
                    // `force_retired` is deliberately not cleared: a dispute
                    // must not lift the restriction that inactivity imposed.
                    // Expiry rests on the callback `force_retire` scheduled.
                    self.out_queue.push(deadline, to_lock_votes, updated_views);
                }
            }
            ForfeitRule::RelockAll { deadline } => {
                self.relock_all(view, deadline, updated_views)?;
            }
        }
        Ok(())
    }

    /// Hold every piece of stake until `deadline`, or its own ordinary exit
    /// if that falls later.
    ///
    /// Per item, because collapsing fails in both directions: onto `deadline`
    /// alone, nearly-stale evidence *shortens* the wait on stake that had not
    /// started leaving, turning the penalty into a way around the withdrawal
    /// delay; onto the latest floor, a later deposit drags the older stake out
    /// with it. It is also what makes a resubmission a no-op, since every item
    /// already sits at or after `deadline`.
    fn relock_all(
        &mut self, view: View, deadline: View, updated_views: &mut Vec<View>,
    ) -> Result<()> {
        let out_delay = POS_STATE_CONFIG.out_queue_locked_views(view);
        // Every fallible exit is computed before anything is drained, so a
        // rejected relock leaves the status untouched, not half-empty.
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
        // Canonical, so the result depends on the stake and the deadline
        // alone. In insertion order it would also depend on whether an
        // `update` had sorted the queue since the last dispute — both the
        // order and `sorted` are serialized. Merging equal views also stops
        // deposit-then-replay cycles growing the queue.
        relocked.sort_unstable();
        relocked.dedup_by(|(view, votes), (kept_view, kept_votes)| {
            let same = view == kept_view;
            if same {
                *kept_votes += *votes;
            }
            same
        });

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
/// others. `PosState` picks exactly one, so the rule and the deadline cannot
/// disagree.
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
    use proptest::prelude::*;
    use std::collections::HashSet;

    enum Operation {
        NewLock(u64),
        NewUnlock(u64),
        ForceRetire,
        Forfeit(ForfeitRule),
        AssertAvailable(u64),
        AssertLocked(u64),
        AssertUnlocked(u64),
        /// Stored order, which is what gets serialized — comparing the
        /// multiset would miss a rule that reshuffles the queue.
        AssertOutQueue(Vec<(View, u64)>),
        /// The exact view: a rule that re-stamped it with today's would
        /// restart the restriction, and a boolean could not tell.
        AssertForceRetired(Option<View>),
        Snapshot,
        /// Whole-status equality: idempotence has to hold for the serialized
        /// bytes, `StatusList::sorted` included.
        AssertUnchangedSinceSnapshot,
    }

    use ForfeitRule::*;
    use Operation::*;

    /// The queue delays are tiered, so a test that hard-coded one tier would
    /// silently describe a different scenario once a transition moved.
    fn in_delay(view: View) -> u64 {
        test_config::install();
        POS_STATE_CONFIG.in_queue_locked_views(view)
    }

    fn out_delay(view: View) -> u64 {
        test_config::install();
        POS_STATE_CONFIG.out_queue_locked_views(view)
    }

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
                            lock_status.force_retired, expected,
                            "force_retired at view {}\n {:?}",
                            view, lock_status
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

    /// Nothing detects a repeat, so the same evidence stays valid forever and
    /// anyone can resubmit it. What stops that extending the lock is that a
    /// second application leaves the status byte-identical.
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

    /// The common shape, since the deadline usually dominates: two pieces
    /// clamp onto it and merge. Worth its own case because `Vec::dedup_by`
    /// hands the closure the later element first and drops it, so summing into
    /// the wrong side loses votes while still leaving one plausible entry.
    #[test]
    fn pieces_landing_on_the_deadline_merge_without_losing_votes() {
        let retire = test_config::CIP173_TRANSITION + 500;
        let dispute = retire + 500;
        let deadline = dispute + test_config::DISPUTE_LOCKED_VIEWS;
        // Both the retiring piece and the still-locked one exit well before
        // the deadline, so both clamp onto it.
        assert!(retire + out_delay(retire) < deadline);
        assert!(dispute + out_delay(dispute) < deadline);
        let tasks = vec![
            (NewLock(10), 2),
            (NewUnlock(4), retire),
            (
                AssertOutQueue(vec![(retire + out_delay(retire), 4)]),
                dispute - 1,
            ),
            (AssertLocked(6), dispute - 1),
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertOutQueue(vec![(deadline, 10)]), dispute + 1),
            (AssertUnlocked(10), deadline + 1),
        ];

        run_tasks(tasks);
    }

    /// `update` sorts the queue through `pop_by_view`, and both the order and
    /// `sorted` are serialized — so a replay after one has run starts from a
    /// differently encoded queue and still has to land on the same state.
    #[test]
    fn replay_is_stable_across_an_intervening_update() {
        let deposit = test_config::CIP173_TRANSITION + 500;
        let dispute = deposit + 1;
        // Below the deposit's ordinary exit, so the two pieces land on
        // different views and ordering is observable at all.
        let deadline = dispute + out_delay(dispute);
        let tasks = vec![
            (NewLock(10), 2),
            (NewLock(5), deposit),
            (Forfeit(RelockAll { deadline }), dispute),
            // Past the first exit, so `update` has drained and re-sorted.
            (Snapshot, deadline + 1),
            (Forfeit(RelockAll { deadline }), deadline + 2),
            (AssertUnchangedSinceSnapshot, deadline + 3),
        ];

        run_tasks(tasks);
    }

    /// `next_view` consumed the hint even though the old predicate refused to
    /// clear the flag, and no second callback follows. With no other scheduled
    /// view, only re-checking where the flag is read can repair it.
    #[test]
    fn a_consumed_callback_does_not_strand_force_retirement() {
        let retire = test_config::CIP99_TRANSITION - 5000;
        let consumed_callback = retire + out_delay(retire);
        // Both sides of the callback precede the gate, so the flag is still
        // set when CIP-173 activates and no hint remains to revisit it.
        assert!(consumed_callback < test_config::CIP173_TRANSITION);
        assert!(out_delay(consumed_callback) > out_delay(retire));
        let deposit = test_config::CIP173_TRANSITION + 1;
        let tasks = vec![
            // No stake, so the expiry callback is the only view ever
            // scheduled and nothing revisits the node after it is consumed.
            (ForceRetire, retire),
            (AssertForceRetired(Some(retire)), consumed_callback + 1),
            (NewLock(5), deposit),
            (AssertForceRetired(None), deposit + 1),
            (AssertAvailable(5), deposit + 1),
        ];

        run_tasks(tasks);
    }

    /// A replay sweeps stake deposited since, so the penalty is not escapable
    /// by re-staking — but the new stake keeps its own later exit instead of
    /// dragging the older pile out to it.
    #[test]
    fn a_later_deposit_gets_its_own_exit() {
        let dispute = test_config::CIP173_TRANSITION + 1000;
        // Short enough that the deposit's ordinary exit is the later of the
        // two; with a dominating deadline both would land on it and the
        // distinction this test exists for would be invisible.
        let deadline = dispute + out_delay(dispute);
        let deposit = dispute + 100;
        let old_pile_exit = dispute + out_delay(dispute);
        let deposit_exit = deposit + in_delay(deposit) + out_delay(deposit);
        let tasks = vec![
            (NewLock(10), 2),
            (Forfeit(RelockAll { deadline }), dispute),
            (NewLock(5), deposit),
            (AssertAvailable(5), deposit + 1),
            (Forfeit(RelockAll { deadline }), deposit + 1),
            // Ascending, though the deposit is enqueued first: the result is
            // canonical rather than a record of the insertion order.
            (
                AssertOutQueue(vec![(old_pile_exit, 10), (deposit_exit, 5)]),
                deposit + 2,
            ),
            (Snapshot, deposit + 3),
            (Forfeit(RelockAll { deadline }), deposit + 4),
            (AssertUnchangedSinceSnapshot, deposit + 5),
        ];

        run_tasks(tasks);
    }

    /// A floor, never a ceiling: evidence filed just before it goes stale
    /// leaves almost no penalty, and stake that had not started leaving must
    /// still serve its ordinary delay — otherwise a validator could arrange to
    /// be disputed on stale evidence and skip the withdrawal queue.
    #[test]
    fn a_nearly_stale_deadline_does_not_release_locked_stake_early() {
        let dispute = test_config::CIP173_TRANSITION + 1000;
        let deadline = dispute + 1;
        let ordinary_exit = dispute + out_delay(dispute);
        let tasks = vec![
            (NewLock(10), 2),
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertOutQueue(vec![(ordinary_exit, 10)]), dispute + 1),
            (AssertUnlocked(0), ordinary_exit - 1),
            (AssertUnlocked(10), ordinary_exit + 1),
        ];

        run_tasks(tasks);
    }

    /// The same floor for maturing stake, measured from its place in
    /// `in_queue`, so a dispute cannot turn a fresh deposit into an early
    /// withdrawal either.
    #[test]
    fn a_nearly_stale_deadline_does_not_release_in_queue_stake_early() {
        let deposit = test_config::CIP173_TRANSITION + 500;
        let dispute = deposit + 1;
        let deadline = dispute + 1;
        let ordinary_exit = deposit + in_delay(deposit) + out_delay(deposit);
        let tasks = vec![
            (NewLock(10), deposit),
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertOutQueue(vec![(ordinary_exit, 10)]), dispute + 1),
            (AssertUnlocked(0), ordinary_exit - 1),
            (AssertUnlocked(10), ordinary_exit + 1),
        ];

        run_tasks(tasks);
    }

    /// Characterization of #3524: a node whose stake sits entirely in
    /// `out_queue` has no active stake, which alone let it escape the lock.
    #[test]
    fn relock_all_catches_a_fully_retired_node() {
        let retire = test_config::CIP173_TRANSITION + 1000;
        let exit = retire + out_delay(retire);
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

    /// The delay grows between the retirement and its one callback, so
    /// reading today's delay makes the callback fire too early to satisfy its
    /// own condition and the flag stays set forever.
    ///
    /// Retirement before `CIP173_TRANSITION`, callback after: the straddle the
    /// gate has to decide, repaired rather than left on the old rule.
    #[test]
    fn force_retire_expiry_uses_the_scheduled_delay() {
        let retire = test_config::CIP173_TRANSITION - 6000;
        let expiry = retire + out_delay(retire);
        // Retired before the gate, expiring after it, and after the delay
        // grew — otherwise the two rules agree and prove nothing.
        assert!(retire < test_config::CIP173_TRANSITION);
        assert!(expiry > test_config::CIP173_TRANSITION);
        assert!(out_delay(expiry) > out_delay(retire));
        let tasks = vec![
            (NewLock(10), 2),
            (ForceRetire, retire),
            (AssertForceRetired(Some(retire)), expiry - 1),
            (AssertForceRetired(None), expiry + 1),
            // The restriction is what routes deposits away from active
            // stake, so a flag that never expires silently strands them.
            (NewLock(5), expiry + 1),
            (AssertAvailable(5), expiry + 2),
        ];

        run_tasks(tasks);
    }

    /// A dispute must not lift the restriction inactivity imposed.
    /// `force_retired` is the only abnormal state reachable alongside a
    /// dispute: deposits made while it is set go straight to `out_queue`.
    #[test]
    fn forfeit_preserves_force_retired() {
        let retire = test_config::CIP173_TRANSITION + 500;
        let dispute = retire + 100;
        let deadline = dispute + test_config::DISPUTE_LOCKED_VIEWS;
        let tasks = vec![
            (NewLock(10), 2),
            (ForceRetire, retire),
            (AssertForceRetired(Some(retire)), retire + 1),
            (Forfeit(RelockAll { deadline }), dispute),
            (AssertForceRetired(Some(retire)), dispute + 1),
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
        let exit = retire + out_delay(retire);
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

    #[derive(Clone, Debug)]
    enum Step {
        /// Move to the next view an earlier operation scheduled, and run the
        /// update there.
        Advance,
        NewLock(u64),
        NewUnlock(u64),
        ForceRetire,
        Forfeit(ForfeitKind, View),
    }

    #[derive(Clone, Copy, Debug)]
    enum ForfeitKind {
        Freeze,
        Active,
        All,
    }

    fn any_step() -> impl Strategy<Value = Step> {
        prop_oneof![
            6 => Just(Step::Advance),
            3 => (1u64..1000).prop_map(Step::NewLock),
            3 => (1u64..1000).prop_map(Step::NewUnlock),
            1 => Just(Step::ForceRetire),
            2 => (
                prop_oneof![
                    Just(ForfeitKind::Freeze),
                    Just(ForfeitKind::Active),
                    Just(ForfeitKind::All),
                ],
                1u64..60_000,
            )
                .prop_map(|(kind, offset)| Step::Forfeit(kind, offset)),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// The properties this type relies on but states nowhere — they were
        /// emergent, which is how a predicate written for one abnormal state
        /// could quietly rewrite the others.
        ///
        /// Sequences start from the default state, never from arbitrary ones:
        /// the derived `Arbitrary` impls break the cache and routing
        /// invariants by construction.
        ///
        /// The driver visits exactly the views an operation scheduled, as
        /// `node_map_hint` does; skipping them would let `in_queue` hold
        /// matured items, which production never reaches.
        #[test]
        fn invariants_survive_any_operation_sequence(
            steps in prop::collection::vec(any_step(), 1..32),
        ) {
            test_config::install();
            let mut status = NodeLockStatus::default();
            let mut pending: std::collections::BTreeSet<View> =
                Default::default();
            let mut view: View = 1;
            let mut prev_unlocked = 0u64;
            let mut deposited = 0u64;

            for step in steps {
                let mut pushed = Vec::new();
                match step {
                    Step::Advance => {
                        match pending.range(view..).next().copied() {
                            Some(next) => {
                                pending.remove(&next);
                                view = next;
                                status.update(view);
                            }
                            None => view += 1,
                        }
                    }
                    Step::NewLock(votes) => {
                        deposited += votes;
                        status.new_lock(view, votes, false, &mut pushed);
                    }
                    Step::NewUnlock(votes) => {
                        status.new_unlock(view, votes, &mut pushed);
                    }
                    Step::ForceRetire => {
                        status.force_retire(view, &mut pushed);
                    }
                    Step::Forfeit(kind, offset) => {
                        let deadline = view + offset;
                        let rule = match kind {
                            ForfeitKind::Freeze => {
                                ForfeitRule::FreezeWithdrawable
                            }
                            ForfeitKind::Active => {
                                ForfeitRule::RelockActive { deadline }
                            }
                            ForfeitKind::All => {
                                ForfeitRule::RelockAll { deadline }
                            }
                        };
                        status
                            .forfeit(view, rule, &mut pushed)
                            .map_err(|e| TestCaseError::fail(e.to_string()))?;
                    }
                }

                // A key scheduled in the past would sit in `node_map_hint`
                // unvisited forever, and the stake behind it with it.
                for scheduled in &pushed {
                    prop_assert!(
                        *scheduled > view,
                        "scheduled {} at view {}",
                        scheduled,
                        view
                    );
                    pending.insert(*scheduled);
                }

                // Everything reading `available_votes` rather than
                // recomputing depends on this.
                prop_assert_eq!(status.available_votes, status.active_votes());
                // The restriction itself, enforced by deposit routing.
                if status.force_retired.is_some() {
                    prop_assert_eq!(status.active_votes(), 0);
                }
                // A dispute freezes what may be taken out, never claws back
                // what already was.
                prop_assert!(status.unlocked >= prev_unlocked);
                prev_unlocked = status.unlocked;
                // `forfeit` moves stake between buckets, and used to take one
                // total from the cache and the other from real items.
                prop_assert_eq!(
                    status.active_votes()
                        + status.out_queue.total()
                        + status.unlocked,
                    deposited
                );
            }
        }
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
