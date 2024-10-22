#[macro_export]
macro_rules! unwrap_option_or_return_result_none {
    ($e:ident) => {
        let $e = match $e {
            Some(x) => x,
            None => return Ok(None),
        };
    };
}
