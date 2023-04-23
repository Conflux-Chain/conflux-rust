use lazy_static::lazy_static;
use metrics::{
    register_meter_with_group, register_timer_with_group, Meter, Timer,
};
use std::sync::Arc;

lazy_static! {
    pub(crate) static ref STORAGE_GET_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "backend::get");
    pub(crate) static ref STORAGE_GET_TIMER2: Arc<dyn Timer> =
        register_timer_with_group("storage", "backend::get_timer");
    pub(crate) static ref STORAGE_SET_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "backend::set");
    pub(crate) static ref STORAGE_SET_TIMER2: Arc<dyn Timer> =
        register_timer_with_group("storage", "backend::set_timer");
    pub(crate) static ref STORAGE_COMMIT_TIMER: Arc<dyn Meter> =
        register_meter_with_group("timer", "backend::commit");
    pub(crate) static ref STORAGE_COMMIT_TIMER2: Arc<dyn Timer> =
        register_timer_with_group("storage", "backend::commit_timer");
}
