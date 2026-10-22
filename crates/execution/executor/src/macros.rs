#[macro_export]
macro_rules! try_loaded {
    ($expr:expr_2021) => {
        match $expr {
            Err(e) => {
                return Err(e);
            }
            Ok(None) => {
                return Ok(Default::default());
            }
            Ok(Some(v)) => v,
        }
    };
}

#[macro_export]
macro_rules! return_if {
    ($expr:expr_2021) => {
        if $expr {
            return Ok(Default::default());
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($option:expr_2021) => {
        match $option {
            Some(val) => val,
            None => return Default::default(),
        }
    };
    ($option:expr_2021, $ret:expr_2021) => {
        match $option {
            Some(val) => val,
            None => return $ret,
        }
    };
}
