// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

macro_rules! if_option {
	(Option<$type:ty>, THEN {$($then:tt)*} ELSE {$($otherwise:tt)*}) => (
		$($then)*
	);
	($type:ty, THEN {$($then:tt)*} ELSE {$($otherwise:tt)*}) => (
		$($otherwise)*
	);
}

macro_rules! underscore_to_hyphen {
    ($e:expr) => {
        str::replace($e, "_", "-")
    };
}

#[macro_export]
macro_rules! build_config{
    (
        {
            $(($name:ident, ($($type:tt)+), $default:expr))*
        }
        {
            $(($c_name:ident, ($($c_type:tt)+), $c_default:expr, $converter:expr))*
        }
    ) => {
        use cfxcore::pow::ProofOfWorkConfig;
        use cfxcore::verification::VerificationConfig;
        use cfxcore::cache_config::CacheConfig;
        use clap;
        use cfxcore::db::NUM_COLUMNS;
        use db;
        use kvdb_rocksdb::DatabaseConfig;
        use log::LevelFilter;
        use network::{node_table::validate_node_url, ErrorKind, NetworkConfiguration};
        use std::{
            fs::{self, File},
            io::prelude::*,
            net::ToSocketAddrs,
            path::Path,
            str::FromStr,
            time::Duration,
        };
        use toml;

        #[derive(Debug, PartialEq, Clone)]
        pub struct RawConfiguration {
            $(pub $name: $($type)+,)*
            $(pub $c_name: $($c_type)+,)*
        }

        impl Default for RawConfiguration {
            fn default() -> Self {
                RawConfiguration {
                    $($name: $default,)*
                    $($c_name: $c_default,)*
                }
            }
        }
        impl RawConfiguration {
            // First parse arguments from config file,
            // and then parse them from commandline.
            // Replace the ones from config file with the ones
            // from commandline if duplicates.
            pub fn parse(matches: &clap::ArgMatches) -> Result<RawConfiguration, String> {
                let mut config = RawConfiguration::default();

                let config_filename = matches.value_of("config");
                if config_filename.is_some() {
                    let mut config_file = File::open(config_filename.unwrap())
                        .map_err(|e| format!("failed to open configuration file: {:?}", e))?;

                    let mut config_str = String::new();
                    config_file
                        .read_to_string(&mut config_str)
                        .map_err(|e| format!("failed to read configuration file: {:?}", e))?;

                    let config_value = config_str.parse::<toml::Value>()
                        .map_err(|e| format!("failed to parse configuration file: {:?}", e))?;
                    $(
                        if let Some(value) = config_value.get(stringify!($name)) {
                            config.$name = if_option!(
                                $($type)+,
                                THEN{ Some(value.clone().try_into().map_err(|_| concat!("Invalid ", stringify!($name)).to_owned())?) }
                                ELSE{ value.clone().try_into().map_err(|_| concat!("Invalid ", stringify!($name)).to_owned())? }
                            );
                        }
                    )*
                    $(
                        if let Some(value) = config_value.get(stringify!($c_name)) {
                            config.$c_name = if_option!(
                                $($c_type)+,
                                THEN{ Some($converter(value.as_str().unwrap())?) }
                                ELSE{ $converter(value.as_str().unwrap())? }
                            )
                        }
                    )*
                }

                $(
                    if let Some(value) = matches.value_of(underscore_to_hyphen!(stringify!($name))) {
                        config.$name = if_option!(
                                $($type)+,
                                THEN{ Some(value.parse().map_err(|_| concat!("Invalid ", stringify!($name)).to_owned())?) }
                                ELSE{ value.parse().map_err(|_| concat!("Invalid ", stringify!($name)).to_owned())? }
                            );
                    }
                )*
                $(
                    if let Some(value) = matches.value_of(underscore_to_hyphen!(stringify!($c_name))) {
                    config.$c_name = if_option!(
                                $($c_type)+,
                                THEN{ Some($converter(value)?) }
                                ELSE{ $converter(value)? }
                            )
                    }
                )*
                Ok(config)
            }
        }
    }
}
