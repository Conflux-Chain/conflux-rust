// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod command;

use crate::command::rpc::RpcCommand;
use clap::{load_yaml, App, ArgMatches};
use client::{
    archive::ArchiveClient, configuration::Configuration, full::FullClient,
    light::LightClient,
};
use command::account::{AccountCmd, ImportAccounts, ListAccounts, NewAccount};
use log::{info, LevelFilter};
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Config as LogConfig, Logger, Root},
    encode::pattern::PatternEncoder,
};
use network::throttling::THROTTLING_SERVICE;
use parking_lot::{Condvar, Mutex};
use std::sync::Arc;

fn main() -> Result<(), String> {
    #[cfg(feature = "deadlock_detection")]
    {
        // only for #[cfg]
        use parking_lot::deadlock;
        use std::{thread, time::Duration};

        // Create a background thread which checks for deadlocks every 10s
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(10));
            let deadlocks = deadlock::check_deadlock();
            if deadlocks.is_empty() {
                continue;
            }

            println!("{} deadlocks detected", deadlocks.len());
            for (i, threads) in deadlocks.iter().enumerate() {
                println!("Deadlock #{}", i);
                for t in threads {
                    println!("Thread Id {:#?}", t.thread_id());
                    println!("{:#?}", t.backtrace());
                }
            }
        });
    } // only for #[cfg]

    let yaml = load_yaml!("cli.yaml");
    let matches = App::from_yaml(yaml).get_matches();

    if let Some(output) = handle_sub_command(&matches)? {
        println!("{}", output);
        return Ok(());
    }

    let conf = Configuration::parse(&matches)?;

    // If log_conf is provided, use it for log configuration and ignore
    // log_file and log_level. Otherwise, set stdout to INFO and set
    // all our crate log to log_level.
    let log_config = match conf.raw_conf.log_conf {
        Some(ref log_conf) => {
            log4rs::load_config_file(log_conf, Default::default()).map_err(
                |e| format!("failed to load log configuration file: {:?}", e),
            )?
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
                            FileAppender::builder().encoder(Box::new(PatternEncoder::new("{d} {h({l}):5.5} {T:<20.20} {t:12.12} - {m}{n}"))).build(log_file).map_err(|e|format!("failed to build log pattern: {:?}", e))?,
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
                "txgen",
                "client",
                "primitives",
                "io",
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
                .map_err(|e| format!("failed to build log config: {:?}", e))?
        }
    };

    log4rs::init_config(log_config).map_err(|e| {
        format!("failed to initialize log with config: {:?}", e)
    })?;

    THROTTLING_SERVICE.write().initialize(
        conf.raw_conf.egress_queue_capacity,
        conf.raw_conf.egress_min_throttle,
        conf.raw_conf.egress_max_throttle,
    );

    let exit = Arc::new((Mutex::new(false), Condvar::new()));

    if matches.is_present("light") {
        //FIXME: implement light client later
        info!("Starting light client...");
        let client_handle = LightClient::start(conf, exit.clone())
            .map_err(|e| format!("failed to start light client: {:?}", e))?;
        LightClient::run_until_closed(exit, client_handle);
    } else if matches.is_present("archive") {
        info!("Starting archive client...");
        let client_handle = ArchiveClient::start(conf, exit.clone())
            .map_err(|e| format!("failed to start archive client: {:?}", e))?;
        ArchiveClient::run_until_closed(exit, client_handle);
    } else if matches.is_present("full") {
        // todo this is to test full node in python code
        // remove this branch when starts full node by default.
        info!("Starting full client...");
        let client_handle = FullClient::start(conf, exit.clone())
            .map_err(|e| format!("failed to start full client: {:?}", e))?;
        FullClient::run_until_closed(exit, client_handle);
    } else {
        info!("Starting archive client...");
        let client_handle = ArchiveClient::start(conf, exit.clone())
            .map_err(|e| format!("failed to start archive client: {:?}", e))?;
        ArchiveClient::run_until_closed(exit, client_handle);
    }

    Ok(())
}

fn handle_sub_command(matches: &ArgMatches) -> Result<Option<String>, String> {
    if matches.subcommand_name().is_none() {
        return Ok(None);
    }

    // account sub-commands
    if let ("account", Some(account_matches)) = matches.subcommand() {
        let account_cmd = match account_matches.subcommand() {
            ("new", Some(new_acc_matches)) => {
                AccountCmd::New(NewAccount::new(new_acc_matches))
            }
            ("list", Some(list_acc_matches)) => {
                AccountCmd::List(ListAccounts::new(list_acc_matches))
            }
            ("import", Some(import_acc_matches)) => {
                AccountCmd::Import(ImportAccounts::new(import_acc_matches))
            }
            _ => unreachable!(),
        };
        let execute_output = command::account::execute(account_cmd)?;
        return Ok(Some(execute_output));
    }

    // general RPC commands
    let mut subcmd_matches = matches;
    while let Some(m) = subcmd_matches.subcommand().1 {
        subcmd_matches = m;
    }

    if let Some(cmd) = RpcCommand::parse(subcmd_matches)? {
        return Ok(Some(cmd.execute()?));
    }

    Ok(None)
}
