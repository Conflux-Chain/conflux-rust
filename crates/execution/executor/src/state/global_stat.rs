use cfx_internal_common::debug::ComputeEpochDebugRecord;
use cfx_statedb::{
    for_all_global_param_keys,
    global_params::{self, GlobalParamKey, TOTAL_GLOBAL_PARAMS},
    Result as DbResult, StateDbExt, StateDbGeneric as StateDb,
};
use cfx_types::U256;

/// Manages specially-treated global variables during execution.
///
/// Underlying this structure is a fixed-length array, where each global
/// variable corresponds to an instance of the `GlobalParamKey` trait. This
/// trait defines the variable's index in the array, its initialization process,
/// and the type conversion between database layer format and application layer
/// format.
//
// This approach, compared to implementing each global variable as a separate
// field, significantly reduces repetitive code, leverages a few generic
// functions instead of individual logic for each field. As variable indices are
// compile-time constants, the resulting code is free from array boundary
// checks, achieving performance comparable to a field-based implementation.
//
// TODO: Incorporating these variables into existing cache/checkpoint logic
// would make the code clean, but it would be difficult to achieve back forward
// compatibility.
#[derive(Copy, Clone, Debug)]
pub(super) struct GlobalStat([U256; TOTAL_GLOBAL_PARAMS]);

impl GlobalStat {
    /// Make new global statistical variables with their initialization value.
    pub fn new() -> Self {
        let mut ans = <[U256; TOTAL_GLOBAL_PARAMS]>::default();
        fn init_value<T: GlobalParamKey>(
            ans: &mut [U256; TOTAL_GLOBAL_PARAMS],
        ) {
            ans[T::ID] = T::init_vm_value();
        }
        use global_params::*;
        for_all_global_param_keys! {
            init_value::<Key>(&mut ans);
        }
        GlobalStat(ans)
    }

    /// Get loaded global statistic variables from the database.
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

    /// Assert the global statistic variables have never been inited in the
    /// database.
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

    /// Commit the in-memory global statistic variables to the database.
    pub fn commit(
        &self, db: &mut StateDb,
        mut debug_record: Option<&mut ComputeEpochDebugRecord>,
    ) -> DbResult<()> {
        fn commit_param<T: GlobalParamKey>(
            ans: &[U256; TOTAL_GLOBAL_PARAMS], db: &mut StateDb,
            debug_record: Option<&mut ComputeEpochDebugRecord>,
        ) -> DbResult<()> {
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

    /// Get the owned value of a variable
    pub fn get<T: GlobalParamKey>(&self) -> U256 { self.0[T::ID] }

    /// Get the immutable reference of a variable
    pub fn refr<T: GlobalParamKey>(&self) -> &U256 { &self.0[T::ID] }

    /// Get the mutable reference of a variable
    pub fn val<T: GlobalParamKey>(&mut self) -> &mut U256 { &mut self.0[T::ID] }
}
