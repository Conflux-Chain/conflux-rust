#[macro_export]
macro_rules! check_func_signature {
    ($interface:ident, $signature:expr) => {
        assert_eq!(
            $interface::FUNC_SIG.to_vec(),
            $signature.from_hex::<Vec<u8>>().unwrap(),
            "Test solidity signature for {}",
            $interface::NAME_AND_PARAMS
        );
    };
}

#[macro_export]
macro_rules! check_event_signature {
    ($interface:ident, $signature:expr) => {
        assert_eq!(
            $interface::EVENT_SIG.0.to_vec(),
            $signature.from_hex::<Vec<u8>>().unwrap(),
            "Test solidity event signature"
        );
    };
}

#[macro_export]
macro_rules! internal_bail {
    ($e:expr) => {
        return Err(crate::vm::Error::InternalContract($e.into()));
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err(crate::vm::Error::InternalContract(format!($fmt, $($arg)+)));
    };
}
