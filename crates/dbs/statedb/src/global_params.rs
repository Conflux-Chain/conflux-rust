use cfx_parameters::{
    internal_contract_addresses::*,
    staking::{
        ACCUMULATED_INTEREST_RATE_SCALE, BLOCKS_PER_YEAR,
        INITIAL_INTEREST_RATE_PER_BLOCK,
    },
};
use cfx_types::{Address, Space, U256};
use primitives::{StorageKey, StorageKeyWithSpace};

pub trait GlobalParamKey {
    const SPACE: Space = Space::Native;
    const ADDRESS: Address = STORAGE_INTEREST_STAKING_CONTRACT_ADDRESS;
    const ID: usize;
    const KEY: &'static [u8];
    const STORAGE_KEY: StorageKeyWithSpace<'static> =
        StorageKey::new_storage_key(&Self::ADDRESS, Self::KEY)
            .with_space(Self::SPACE);

    /// How to initialize such a variable in the executor
    fn init_vm_value() -> U256 { U256::zero() }
    /// How to convert such a variable from the executor representing to the db
    /// representing
    fn from_vm_value(val: U256) -> U256 { val }
    /// How to convert such a variable from the db representing to the executor
    /// representing
    fn into_vm_value(val: U256) -> U256 { val }
}

#[macro_export]
macro_rules! for_all_global_param_keys {
    ($f:ident::<Key>($($args:expr),*);) => {
        $f::<InterestRate>($($args),*);
        $f::<AccumulateInterestRate>($($args),*);
        $f::<TotalIssued>($($args),*);
        $f::<TotalStaking>($($args),*);
        $f::<TotalStorage>($($args),*);
        $f::<TotalEvmToken>($($args),*);
        $f::<UsedStoragePoints>($($args),*);
        $f::<ConvertedStoragePoints>($($args),*);
        $f::<TotalPosStaking>($($args),*);
        $f::<DistributablePoSInterest>($($args),*);
        $f::<LastDistributeBlock>($($args),*);
        $f::<PowBaseReward>($($args),*);
        $f::<TotalBurnt1559>($($args),*);
        $f::<BaseFeeProp>($($args),*);
    };
    ($f:ident::<Key>($($args:expr),*)?;) => {
        $f::<InterestRate>($($args),*)?;
        $f::<AccumulateInterestRate>($($args),*)?;
        $f::<TotalIssued>($($args),*)?;
        $f::<TotalStaking>($($args),*)?;
        $f::<TotalStorage>($($args),*)?;
        $f::<TotalEvmToken>($($args),*)?;
        $f::<UsedStoragePoints>($($args),*)?;
        $f::<ConvertedStoragePoints>($($args),*)?;
        $f::<TotalPosStaking>($($args),*)?;
        $f::<DistributablePoSInterest>($($args),*)?;
        $f::<LastDistributeBlock>($($args),*)?;
        $f::<PowBaseReward>($($args),*)?;
        $f::<TotalBurnt1559>($($args),*)?;
        $f::<BaseFeeProp>($($args),*)?;
    };
}

pub struct InterestRate;
impl GlobalParamKey for InterestRate {
    const ID: usize = 0;
    const KEY: &'static [u8] = b"interest_rate";

    fn init_vm_value() -> U256 { *INITIAL_INTEREST_RATE_PER_BLOCK }

    fn from_vm_value(val: U256) -> U256 { val * U256::from(BLOCKS_PER_YEAR) }

    fn into_vm_value(val: U256) -> U256 { val / U256::from(BLOCKS_PER_YEAR) }
}

pub struct AccumulateInterestRate;
impl GlobalParamKey for AccumulateInterestRate {
    const ID: usize = InterestRate::ID + 1;
    const KEY: &'static [u8] = b"accumulate_interest_rate";

    fn init_vm_value() -> U256 { *ACCUMULATED_INTEREST_RATE_SCALE }
}

pub struct TotalIssued;
impl GlobalParamKey for TotalIssued {
    const ID: usize = AccumulateInterestRate::ID + 1;
    const KEY: &'static [u8] = b"total_issued_tokens";
}

pub struct TotalStaking;
impl GlobalParamKey for TotalStaking {
    const ID: usize = TotalIssued::ID + 1;
    const KEY: &'static [u8] = b"total_staking_tokens";
}

pub struct TotalStorage;
impl GlobalParamKey for TotalStorage {
    const ID: usize = TotalStaking::ID + 1;
    const KEY: &'static [u8] = b"total_storage_tokens";
}

pub struct TotalEvmToken;
impl GlobalParamKey for TotalEvmToken {
    const ID: usize = TotalStorage::ID + 1;
    const KEY: &'static [u8] = b"total_evm_tokens";
}

pub struct UsedStoragePoints;
impl GlobalParamKey for UsedStoragePoints {
    const ID: usize = TotalEvmToken::ID + 1;
    const KEY: &'static [u8] = b"used_storage_points";
}

pub struct ConvertedStoragePoints;
impl GlobalParamKey for ConvertedStoragePoints {
    const ID: usize = UsedStoragePoints::ID + 1;
    const KEY: &'static [u8] = b"converted_storage_points_key";
}

pub struct TotalPosStaking;
impl GlobalParamKey for TotalPosStaking {
    const ID: usize = ConvertedStoragePoints::ID + 1;
    const KEY: &'static [u8] = b"total_pos_staking_tokens";
}

pub struct DistributablePoSInterest;
impl GlobalParamKey for DistributablePoSInterest {
    const ID: usize = TotalPosStaking::ID + 1;
    const KEY: &'static [u8] = b"distributable_pos_interest";
}
pub struct LastDistributeBlock;
impl GlobalParamKey for LastDistributeBlock {
    const ID: usize = DistributablePoSInterest::ID + 1;
    const KEY: &'static [u8] = b"last_distribute_block";
}

pub struct PowBaseReward;
impl GlobalParamKey for PowBaseReward {
    const ADDRESS: Address = PARAMS_CONTROL_CONTRACT_ADDRESS;
    const ID: usize = LastDistributeBlock::ID + 1;
    const KEY: &'static [u8] = b"pow_base_reward";
}

pub struct TotalBurnt1559;
impl GlobalParamKey for TotalBurnt1559 {
    const ID: usize = PowBaseReward::ID + 1;
    const KEY: &'static [u8] = b"total_burnt_tokens_by_cip1559";
}

pub struct BaseFeeProp;
impl GlobalParamKey for BaseFeeProp {
    const ID: usize = TotalBurnt1559::ID + 1;
    const KEY: &'static [u8] = b"base_fee_prop";
}

pub const TOTAL_GLOBAL_PARAMS: usize = BaseFeeProp::ID + 1;
