// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate clap;
extern crate client;
extern crate log;
extern crate log4rs;
extern crate parking_lot;

use clap::{App, Arg};
use client::{Client, Configuration};
use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Config as LogConfig, Logger, Root},
    encode::pattern::PatternEncoder,
};
use network::throttling::THROTTLING_SERVICE;
use parking_lot::{Condvar, Mutex};
use std::{io as stdio, io::Write, process, str::FromStr, sync::Arc};

fn main() {
    let matches = App::new("conflux")
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("Listen for p2p connections on PORT.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("udp-port")
                .long("udp-port")
                .value_name("PORT")
                .help("UDP port for peer discovery.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("jsonrpc-tcp-port")
                .long("jsonrpc-tcp-port")
                .value_name("PORT")
                .help("Specify the PORT for the TCP JSON-RPC API server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("jsonrpc-http-port")
                .long("jsonrpc-http-port")
                .value_name("PORT")
                .help("Specify the PORT for the HTTP JSON-RPC API server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("jsonrpc-cors")
                .long("jsonrpc-cors")
                .value_name("URL")
                .help("Specify CORS header for HTTP JSON-RPC API responses. Special options: \"all\", \"none\".")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("jsonrpc-http-keep-alive")
                .long("jsonrpc-http-keep-alive")
                .value_name("BOOL")
                .help("Enable HTTP/1.1 keep alive header. Enabling keep alive will re-use the same TCP connection to fire multiple requests.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .value_name("FILE")
                .help("Specify the filename for the log. Stdout will be used by default if omitted.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .help("Can be error/warn/info/debug/trace. Default is the info level.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("bootnodes")
                .long("bootnodes")
                .value_name("NODES")
                .help("Sets a custom list of bootnodes")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("netconf-dir")
                .long("netconf-dir")
                .value_name("NETCONF_DIR")
                .help("Sets a custom directory for network configurations")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("public-address")
                .long("public-address")
                .value_name("ADDRESS")
                .help("Sets a custom public address to be connected by others")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ledger-cache-size")
                .short("lcs")
                .long("ledger-cache-size")
                .value_name("SIZE")
                .help("Sets the ledger cache size")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("db-cache-size")
                .short("dcs")
                .long("db-cache-size")
                .value_name("SIZE")
                .help("Sets the db cache size")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("enable-discovery")
                .long("enable-discovery")
                .value_name("BOOL")
                .help("Enable discovery protocol")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("node-table-timeout")
                .long("node-table-timeout")
                .value_name("SEC")
                .help("How often Conflux updates its peer table (default 300).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("node-table-promotion-timeout")
                .long("node-table-promotion-timeout")
                .value_name("SEC")
                .help("How long Conflux waits for promoting a peer to trustworthy (default 3 * 24 * 3600).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("test-mode")
                .long("test-mode")
                .value_name("BOOL")
                .help("Sets test mode for adding latency")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("db-compact-profile")
                .long("db-compact-profile")
                .value_name("ENUM")
                .help("Sets the compaction profile of RocksDB.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("db-dir")
                .long("db-dir")
                .value_name("PATH")
                .help("Sets the root path of db.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("load-test-chain")
                .long("load-test-chain")
                .value_name("FILE")
                .help("Sets the test chain json file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("egress-queue-capacity")
                .long("egress-queue-capacity")
                .value_name("MB")
                .help("Sets egress queue capacity of P2P network.")
                .takes_value(true)
                .default_value("256")
                .validator(from_str_validator::<usize>),
        )
        .arg(
            Arg::with_name("egress-min-throttle")
                .long("egress-min-throttle")
                .value_name("MB")
                .help("Sets minimum throttling queue size of egress.")
                .takes_value(true)
                .default_value("10")
                .validator(from_str_validator::<usize>),
        )
        .arg(
            Arg::with_name("egress-max-throttle")
                .long("egress-max-throttle")
                .value_name("MB")
                .help("Sets maximum throttling queue size of egress.")
                .takes_value(true)
                .default_value("64")
                .validator(from_str_validator::<usize>),
        )
        .get_matches_from(std::env::args().collect::<Vec<_>>());

    THROTTLING_SERVICE.write().initialize(
        value_from_str(&matches, "egress-queue-capacity"),
        value_from_str(&matches, "egress-min-throttle"),
        value_from_str(&matches, "egress-max-throttle"),
    );

    let conf = Configuration::parse(&matches).unwrap();

    // If log_conf is provided, use it for log configuration and ignore
    // log_file and log_level. Otherwise, set stdout to INFO and set
    // all our crate log to log_level.
    let log_config = match conf.raw_conf.log_conf {
        Some(ref log_conf) => {
            log4rs::load_config_file(log_conf, Default::default()).unwrap()
        }
        None => {
            let mut conf_builder =
                LogConfig::builder().appender(Appender::builder().build(
                    "stdout",
                    Box::new(ConsoleAppender::builder().build()),
                ));
            let mut root_builder = Root::builder().appender("stdout");
            if let Some(ref log_file) = conf.raw_conf.log_file {
                conf_builder =
                    conf_builder.appender(Appender::builder().build(
                        "logfile",
                        Box::new(
                            FileAppender::builder().encoder(Box::new(PatternEncoder::new("{d} {h({l}):5.5} {T:<20.20} {t:12.12} - {m}{n}"))).build(log_file).unwrap(),
                        ),
                    ));
                root_builder = root_builder.appender("logfile");
            };
            // Should add new crate names here
            for crate_name in [
                "blockgen",
                "cfxcore",
                "conflux",
                "db",
                "keymgr",
                "network",
                "rpc",
                "txgen",
                "client",
                "primitives",
            ]
            .iter()
            {
                conf_builder = conf_builder.logger(
                    Logger::builder()
                        .build(*crate_name, conf.raw_conf.log_level),
                );
            }
            conf_builder
                .build(root_builder.build(LevelFilter::Info))
                .unwrap()
        }
    };
    log4rs::init_config(log_config).unwrap();

    let exit = Arc::new((Mutex::new(false), Condvar::new()));

    process::exit(match Client::start(conf, exit.clone()) {
        Ok(client_handle) => Client::run_until_closed(exit, client_handle),
        Err(err) => {
            writeln!(&mut stdio::stderr(), "{}", err).unwrap();
            1
        }
    });
}

fn from_str_validator<T: FromStr>(arg: String) -> Result<(), String> {
    match arg.parse::<T>() {
        Ok(_) => Ok(()),
        Err(_) => Err(arg),
    }
}

fn value_from_str<T, S>(matches: &clap::ArgMatches, name: S) -> T
where
    T: FromStr,
    S: AsRef<str>,
{
    matches.value_of(name).unwrap().parse::<T>().ok().unwrap()
}
