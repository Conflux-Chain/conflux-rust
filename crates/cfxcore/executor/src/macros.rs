#[macro_export]
macro_rules! try_loaded {
    ($expr:expr) => {
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
    ($expr:expr) => {
        if $expr {
            return Ok(Default::default());
        }
    };
}

#[macro_export]
macro_rules! unwrap_or_return {
    ($option:expr) => {
        match $option {
            Some(val) => val,
            None => return Default::default(),
        }
    };
    ($option:expr, $ret:expr) => {
        match $option {
            Some(val) => val,
            None => return $ret,
        }
    };
}
