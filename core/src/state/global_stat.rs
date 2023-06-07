use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_parameters::staking::{
    ACCUMULATED_INTEREST_RATE_SCALE, INITIAL_INTEREST_RATE_PER_BLOCK,
};
use cfx_statedb::{
    for_all_global_param_keys,
    global_params::{
        self, AccumulateInterestRate, GlobalParamKey, InterestRate,
        TOTAL_GLOBAL_PARAMS,
    },
    Result as DbResult, StateDbExt, StateDbGeneric as StateDb,
};
use cfx_types::U256;

#[derive(Copy, Clone, Debug)]
pub(super) struct GlobalStat([U256; TOTAL_GLOBAL_PARAMS]);

impl GlobalStat {
    pub fn new() -> Self {
        let mut ans = <[U256; TOTAL_GLOBAL_PARAMS]>::default();
        ans[InterestRate::ID] = *INITIAL_INTEREST_RATE_PER_BLOCK;
        ans[AccumulateInterestRate::ID] = *ACCUMULATED_INTEREST_RATE_SCALE;
        GlobalStat(ans)
    }

    pub fn loaded(db: &StateDb) -> DbResult<Self> {
        let mut ans = Default::default();
        fn load_value<T: GlobalParamKey>(
            ans: &mut [U256; TOTAL_GLOBAL_PARAMS], db: &StateDb,
        ) -> DbResult<()> {
            let loaded = db.get_global_param::<T>()?;
            ans[T::ID] = T::into_vm_value(loaded);
            Ok(())
        }
        use global_params::*;
        for_all_global_param_keys! {
            load_value::<Key>(&mut ans, db)?;
        }
        Ok(GlobalStat(ans))
    }

    pub fn assert_non_inited(db: &StateDb) -> DbResult<()> {
        // If db is not initialized, all the loaded value should be zero.
        fn assert_zero_global_params<T: GlobalParamKey>(
            db: &StateDb,
        ) -> DbResult<()> {
            assert!(
                db.get_global_param::<T>()?.is_zero(),
                "{:x?} is non-zero when db is un-init",
                T::STORAGE_KEY
            );
            Ok(())
        }
        use global_params::*;
        for_all_global_param_keys! {
            assert_zero_global_params::<Key>(&db)?;
        }
        Ok(())
    }

    pub fn commit(
        &self, db: &mut StateDb,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()>
    {
        fn commit_param<T: GlobalParamKey>(
            ans: &[U256; TOTAL_GLOBAL_PARAMS], db: &mut StateDb,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> DbResult<()>
        {
            let value = T::from_vm_value(ans[T::ID]);
            db.set_global_param::<T>(&value, debug_record)?;
            Ok(())
        }
        use global_params::*;
        for_all_global_param_keys! {
            commit_param::<Key>(&self.0, db, debug_record.as_deref_mut())?;
        }
        Ok(())
    }

    pub fn get<T: GlobalParamKey>(&self) -> U256 { self.0[T::ID] }

    pub fn refr<T: GlobalParamKey>(&self) -> &U256 { &self.0[T::ID] }

    pub fn val<T: GlobalParamKey>(&mut self) -> &mut U256 { &mut self.0[T::ID] }
}
