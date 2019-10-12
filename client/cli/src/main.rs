// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use clap::{load_yaml, App, ArgMatches};
use futures::future::Future;
use jsonrpc_core::{Params, Value};
use jsonrpc_core_client::{transports::http::connect, RawClient};
use jsonrpc_http_server::hyper::rt;
use serde_json::Map;
use std::{str::FromStr, sync::mpsc::channel};

fn main() -> Result<(), String> {
    let yaml = load_yaml!("cli.yaml");
    let matches = App::from_yaml(yaml).get_matches();

    let mut opts = &matches;
    while let Some(m) = opts.subcommand().1 {
        opts = m;
    }

    let rpc_method = match opts.value_of("rpc-method") {
        Some(method) => method,
        None => {
            println!("{}", opts.usage());
            return Ok(());
        }
    };

    let rpc_server = opts
        .value_of("url")
        .ok_or(String::from("RPC URL not specified"))?;
    let rpc_args = match opts.values_of("rpc-args") {
        Some(args) => args,
        None => {
            call_rpc(rpc_server.into(), rpc_method.into(), Params::None);
            return Ok(());
        }
    };

    let mut params = Vec::new();
    for arg in rpc_args {
        match ArgSchema::parse(arg).value(opts)? {
            Some(val) => params.push(val),
            None => break,
        }
    }

    call_rpc(rpc_server.into(), rpc_method.into(), Params::Array(params));

    Ok(())
}

fn call_rpc(url: String, method: String, params: Params) {
    let (sender, receiver) = channel();

    rt::run(
        connect::<RawClient>(url.as_str())
            .and_then(move |client| {
                client.call_method(method.as_str(), params).then(
                    move |result| {
                        sender.send(result).expect("channel should work fine");
                        Ok(())
                    },
                )
            })
            .map_err(|e| eprintln!("future error: {:?}", e)),
    );

    match receiver.recv().expect("channel should work fine") {
        Ok(result) => println!("{:#}", result),
        Err(e) => println!("{:?}", e),
    }
}

struct ArgSchema<'a> {
    arg_name: &'a str,
    arg_type: &'a str,
}

impl<'a> ArgSchema<'a> {
    fn parse(arg: &'a str) -> Self {
        let schema: Vec<&str> = arg.splitn(2, ":").collect();
        ArgSchema {
            arg_name: schema[0],
            arg_type: schema.get(1).cloned().unwrap_or("string"),
        }
    }

    fn value(&self, opts: &ArgMatches) -> Result<Option<Value>, String> {
        match self.arg_type {
            "string" => match opts.value_of(self.arg_name) {
                Some(val) => Ok(Some(Value::String(val.into()))),
                None => Ok(None),
            },
            "bool" => Ok(Some(Value::Bool(opts.is_present(self.arg_name)))),
            "u64" => self.u64(opts),
            _ => {
                if self.arg_type.starts_with("map(")
                    && self.arg_type.ends_with(")")
                {
                    return Ok(Some(self.object(opts)?));
                }

                panic!("unsupported RPC argument type: {}", self.arg_type);
            }
        }
    }

    fn u64(&self, opts: &ArgMatches) -> Result<Option<Value>, String> {
        let val = match opts.value_of(self.arg_name) {
            Some(val) => val,
            None => return Ok(None),
        };

        let val = u64::from_str(val).map_err(|e| {
            format!("failed to parse argument [--{}]: {:?}", self.arg_name, e)
        })?;

        Ok(Some(Value::String(format!("{:#x}", val))))
    }

    fn object(&self, opts: &ArgMatches) -> Result<Value, String> {
        let fields: Vec<&str> = self
            .arg_type
            .trim_start_matches("map(")
            .trim_end_matches(")")
            .split(";")
            .collect();

        let mut object = Map::new();

        for field in fields {
            let schema = ArgSchema::parse(field);
            if let Some(val) = schema.value(opts)? {
                object.insert(schema.arg_name.into(), val);
            }
        }

        Ok(Value::Object(object))
    }
}
