#[macro_export]
macro_rules! unwrap_option_or_return_result_none {
    ($e:ident) => {
        let $e = match $e {
            Some(x) => x,
            None => return Ok(None),
        };
    };
}

#[macro_export]
macro_rules! bail {
    ($e:expr) => {
        return Err($e.into());
    };
    ($fmt:expr, $($arg:tt)+) => {
        return Err(format!($fmt, $($arg)+).into());
    };
}
