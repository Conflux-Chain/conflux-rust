use cfx_types::U256;
use primitives::{DepositInfo, DepositList};

use super::OverlayAccount;

impl OverlayAccount {
    pub fn staking_balance(&self) -> &U256 {
        self.address.assert_native();
        &self.staking_balance
    }

    pub fn withdrawable_staking_balance(&self, block_number: u64) -> U256 {
        self.address.assert_native();
        assert!(self.vote_stake_list.is_some());
        let vote_stake_list = self.vote_stake_list.as_ref().unwrap();
        return vote_stake_list
            .withdrawable_staking_balance(self.staking_balance, block_number);
    }

    /// Withdraw some amount of tokens, return the value of interest.
    pub fn withdraw(
        &mut self, amount: U256, accumulated_interest_rate: U256, cip_97: bool,
    ) -> U256 {
        self.address.assert_native();
        assert!(self.deposit_list.is_some());
        let deposit_list = self.deposit_list.as_mut().unwrap();
        let before_staking_balance = self.staking_balance.clone();
        self.staking_balance -= amount;

        if deposit_list.0.is_empty() {
            self.add_balance(&amount);
            return U256::zero();
        }

        let mut rest = if cip_97 {
            before_staking_balance
        } else {
            amount
        };

        let mut interest = U256::zero();
        let mut index = 0;
        while !rest.is_zero() {
            let capital = std::cmp::min(deposit_list[index].amount, rest);
            interest += capital * accumulated_interest_rate
                / deposit_list[index].accumulated_interest_rate
                - capital;

            deposit_list[index].amount -= capital;
            rest -= capital;
            if deposit_list[index].amount.is_zero() {
                index += 1;
            }
        }
        if index > 0 {
            *deposit_list = DepositList(deposit_list.split_off(index));
        }
        self.accumulated_interest_return += interest;
        self.add_balance(&(amount + interest));
        interest
    }

    pub fn deposit(
        &mut self, amount: U256, accumulated_interest_rate: U256,
        deposit_time: u64, cip_97: bool,
    ) {
        self.address.assert_native();
        assert!(self.deposit_list.is_some());
        self.sub_balance(&amount);
        self.staking_balance += amount;

        if self.not_maintain_deposit_list(cip_97) {
            // Since cip_97, the deposit_list is cleared because the staking has
            // not generated interest in cip_43.
            return;
        }
        self.deposit_list.as_mut().unwrap().push(DepositInfo {
            amount,
            deposit_time: deposit_time.into(),
            accumulated_interest_rate,
        });
    }

    fn not_maintain_deposit_list(&self, cip_97: bool) -> bool {
        // Even if CIP-97 is activated, if the deposit list is not empty, we
        // still need to maintain it. Because the clearance of deposit list can
        // only happen on withdrawal, so that the unclaimed interest can be
        // settled correctly.
        cip_97 && self.deposit_list.as_ref().unwrap().0.is_empty()
    }

    pub fn record_interest_receive(&mut self, interest: &U256) {
        self.address.assert_native();
        self.accumulated_interest_return += *interest;
    }

    #[cfg(test)]
    pub fn accumulated_interest_return(&self) -> &U256 {
        &self.accumulated_interest_return
    }

    pub fn vote_lock(&mut self, amount: U256, unlock_block_number: u64) {
        self.address.assert_native();
        assert!(self.vote_stake_list.is_some());
        assert!(amount <= self.staking_balance);
        let vote_stake_list = self.vote_stake_list.as_mut().unwrap();
        vote_stake_list.vote_lock(amount, unlock_block_number)
    }

    pub fn remove_expired_vote_stake_info(&mut self, block_number: u64) {
        self.address.assert_native();
        assert!(self.vote_stake_list.is_some());
        let vote_stake_list = self.vote_stake_list.as_mut().unwrap();
        vote_stake_list.remove_expired_vote_stake_info(block_number)
    }
}
