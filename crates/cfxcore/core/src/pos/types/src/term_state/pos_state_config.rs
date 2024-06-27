use crate::{
    block_info::Round,
    term_state::{
        IN_QUEUE_LOCKED_VIEWS, OUT_QUEUE_LOCKED_VIEWS, ROUND_PER_TERM,
        TERM_ELECTED_SIZE, TERM_LIST_LEN, TERM_MAX_SIZE,
    },
};
use diem_crypto::_once_cell::sync::OnceCell;

const CIP99_FORCE_RETIRE_EPOCH_COUNT: u64 = 3;

#[derive(Clone, Debug)]
pub struct PosStateConfig {
    round_per_term: Round,
    term_max_size: usize,
    term_elected_size: usize,
    in_queue_locked_views: u64,
    out_queue_locked_views: u64,

    cip99_transition_view: u64,
    cip99_out_queue_locked_views: u64,
    cip99_in_queue_locked_views: u64,

    cip136_transition_view: u64,
    cip136_out_queue_locked_views: u64,
    cip136_in_queue_locked_views: u64,
    cip136_round_per_term: u64,

    fix_cip136_transition_view: u64,
    fix_cip136_in_queue_locked_views: u64,
    fix_cip136_out_queue_locked_views: u64,

    nonce_limit_transition_view: u64,
    max_nonce_per_account: u64,
}

pub trait PosStateConfigTrait {
    fn round_per_term(&self, view: u64) -> Round;
    fn election_term_start_round(&self, view: u64) -> Round;
    fn election_term_end_round(&self, view: u64) -> Round;
    fn first_start_election_view(&self) -> u64;
    fn first_end_election_view(&self) -> u64;
    fn term_max_size(&self) -> usize;
    fn term_elected_size(&self) -> usize;
    fn in_queue_locked_views(&self, view: u64) -> u64;
    fn out_queue_locked_views(&self, view: u64) -> u64;
    fn force_retired_locked_views(&self, view: u64) -> u64;

    fn force_retire_check_epoch_count(&self, view: u64) -> u64;
    fn max_nonce_per_account(&self, view: u64) -> u64;
    fn get_term_view(&self, view: u64) -> (u64, u64);
    fn get_starting_view_for_term(&self, term: u64) -> Option<u64>;
}

impl PosStateConfig {
    pub fn new(
        round_per_term: Round, term_max_size: usize, term_elected_size: usize,
        in_queue_locked_views: u64, out_queue_locked_views: u64,
        cip99_transition_view: u64, cip99_in_queue_locked_views: u64,
        cip99_out_queue_locked_views: u64, nonce_limit_transition_view: u64,
        max_nonce_per_account: u64, cip136_transition_view: u64,
        cip136_in_queue_locked_views: u64, cip136_out_queue_locked_views: u64,
        cip136_round_per_term: u64, fix_cip136_transition_view: u64,
        fix_cip136_in_queue_locked_views: u64,
        fix_cip136_out_queue_locked_views: u64,
    ) -> Self {
        Self {
            round_per_term,
            term_max_size,
            term_elected_size,
            in_queue_locked_views,
            out_queue_locked_views,
            cip99_transition_view,
            cip99_out_queue_locked_views,
            cip99_in_queue_locked_views,
            cip136_transition_view,
            cip136_out_queue_locked_views,
            cip136_in_queue_locked_views,
            cip136_round_per_term,
            fix_cip136_transition_view,
            fix_cip136_in_queue_locked_views,
            fix_cip136_out_queue_locked_views,
            nonce_limit_transition_view,
            max_nonce_per_account,
        }
    }
}

impl PosStateConfigTrait for OnceCell<PosStateConfig> {
    fn round_per_term(&self, view: u64) -> Round {
        let conf = self.get().unwrap();
        if view < conf.cip136_transition_view {
            conf.round_per_term
        } else {
            conf.cip136_round_per_term
        }
    }

    /// A term `n` is open for election in the view range
    /// `(n * ROUND_PER_TERM - ELECTION_TERM_START_ROUND, n * ROUND_PER_TERM -
    /// ELECTION_TERM_END_ROUND]`
    fn election_term_start_round(&self, view: u64) -> Round {
        self.round_per_term(view) / 2 * 3
    }

    fn election_term_end_round(&self, view: u64) -> Round {
        self.round_per_term(view) / 2
    }

    fn first_start_election_view(&self) -> u64 {
        TERM_LIST_LEN as u64 * self.round_per_term(0)
            - self.election_term_start_round(0)
    }

    fn first_end_election_view(&self) -> u64 {
        TERM_LIST_LEN as u64 * self.round_per_term(0)
            - self.election_term_end_round(0)
    }

    fn term_max_size(&self) -> usize { self.get().unwrap().term_max_size }

    fn term_elected_size(&self) -> usize {
        self.get().unwrap().term_elected_size
    }

    fn in_queue_locked_views(&self, view: u64) -> u64 {
        let conf = self.get().unwrap();
        if view >= conf.cip99_transition_view
            && view < conf.cip136_transition_view
        {
            conf.cip99_in_queue_locked_views
        } else if view >= conf.cip136_transition_view
            && view < conf.fix_cip136_transition_view
        {
            conf.cip136_in_queue_locked_views
        } else if view >= conf.fix_cip136_transition_view {
            conf.fix_cip136_in_queue_locked_views
        } else {
            conf.in_queue_locked_views
        }
    }

    fn out_queue_locked_views(&self, view: u64) -> u64 {
        let conf = self.get().unwrap();
        if view >= conf.cip99_transition_view
            && view < conf.cip136_transition_view
        {
            conf.cip99_out_queue_locked_views
        } else if view >= conf.cip136_transition_view
            && view < conf.fix_cip136_transition_view
        {
            conf.cip136_out_queue_locked_views
        } else if view >= conf.fix_cip136_transition_view {
            conf.fix_cip136_out_queue_locked_views
        } else {
            conf.out_queue_locked_views
        }
    }

    fn force_retired_locked_views(&self, view: u64) -> u64 {
        self.out_queue_locked_views(view)
    }

    fn force_retire_check_epoch_count(&self, view: u64) -> u64 {
        let conf = self.get().unwrap();
        if view >= conf.cip99_transition_view {
            // This is set according to the value of `TERM_LIST_LEN`.
            // Since `TERM_LIST_LEN` is hardcoded, we do not parameterize this.
            CIP99_FORCE_RETIRE_EPOCH_COUNT
        } else {
            1
        }
    }

    fn max_nonce_per_account(&self, view: u64) -> u64 {
        let conf = self.get().unwrap();
        if view >= conf.nonce_limit_transition_view {
            conf.max_nonce_per_account
        } else {
            u64::MAX
        }
    }

    fn get_term_view(&self, view: u64) -> (u64, u64) {
        let conf = self.get().unwrap();
        if view < conf.cip136_transition_view {
            (view / conf.round_per_term, view % conf.round_per_term)
        } else {
            let transition_term =
                conf.cip136_transition_view / conf.round_per_term;
            let view_after = view - conf.cip136_transition_view;
            (
                transition_term + view_after / conf.cip136_round_per_term,
                view_after % conf.cip136_round_per_term,
            )
        }
    }

    fn get_starting_view_for_term(&self, term: u64) -> Option<u64> {
        let conf = self.get().unwrap();
        let transition_term = conf.cip136_transition_view / conf.round_per_term;
        if term < transition_term {
            Some(term * conf.round_per_term)
        } else {
            (term - transition_term)
                .checked_mul(conf.cip136_round_per_term)
                .map(|v| v + conf.cip136_transition_view)
        }
    }
}

pub static POS_STATE_CONFIG: OnceCell<PosStateConfig> = OnceCell::new();

impl Default for PosStateConfig {
    fn default() -> Self {
        Self {
            round_per_term: ROUND_PER_TERM,
            term_max_size: TERM_MAX_SIZE,
            term_elected_size: TERM_ELECTED_SIZE,
            in_queue_locked_views: IN_QUEUE_LOCKED_VIEWS,
            out_queue_locked_views: OUT_QUEUE_LOCKED_VIEWS,
            cip99_transition_view: u64::MAX,
            cip99_out_queue_locked_views: IN_QUEUE_LOCKED_VIEWS,
            cip99_in_queue_locked_views: OUT_QUEUE_LOCKED_VIEWS,
            cip136_transition_view: u64::MAX,
            cip136_out_queue_locked_views: IN_QUEUE_LOCKED_VIEWS,
            cip136_in_queue_locked_views: OUT_QUEUE_LOCKED_VIEWS,
            cip136_round_per_term: ROUND_PER_TERM,
            fix_cip136_transition_view: u64::MAX,
            fix_cip136_in_queue_locked_views: IN_QUEUE_LOCKED_VIEWS,
            fix_cip136_out_queue_locked_views: OUT_QUEUE_LOCKED_VIEWS,
            nonce_limit_transition_view: u64::MAX,
            max_nonce_per_account: u64::MAX,
        }
    }
}
