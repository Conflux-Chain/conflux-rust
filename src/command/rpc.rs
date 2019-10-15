// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use clap::ArgMatches;
use futures::future::Future;
use jsonrpc_core::{Params, Value};
use jsonrpc_core_client::{transports::http::connect, RawClient};
use jsonrpc_http_server::hyper::rt;
use serde_json::Map;
use std::{str::FromStr, sync::mpsc::channel};

pub struct RpcCommand {
    pub url: String,
    pub method: String,
    pub args: Params,
}

impl RpcCommand {
    pub fn parse(matches: &ArgMatches) -> Result<Option<RpcCommand>, String> {
        let method = match matches.value_of("rpc-method") {
            Some(method) => method,
            None => return Ok(None),
        };

        let url = matches
            .value_of("url")
            .ok_or(String::from("RPC URL not specified"))?;

        let args = match matches.values_of("rpc-args") {
            Some(args) => args,
            None => {
                return Ok(Some(RpcCommand {
                    url: url.into(),
                    method: method.into(),
                    args: Params::None,
                }));
            }
        };

        let mut params = Vec::new();
        for arg in args {
            match ArgSchema::parse(arg).value(matches)? {
                Some(val) => params.push(val),
                None => break,
            }
        }

        Ok(Some(RpcCommand {
            url: url.into(),
            method: method.into(),
            args: Params::Array(params),
        }))
    }

    pub fn execute(self) -> Result<String, String> {
        let (sender, receiver) = channel();

        rt::run(
            connect::<RawClient>(self.url.as_str())
                .and_then(move |client| {
                    client.call_method(self.method.as_str(), self.args).then(
                        move |result| {
                            sender
                                .send(result)
                                .expect("channel should work fine");
                            Ok(())
                        },
                    )
                })
                .map_err(|e| eprintln!("future error: {:?}", e)),
        );

        receiver
            .recv()
            .expect("channel should work fine")
            .map(|result| format!("{:#}", result))
            .map_err(|e| format!("{:?}", e))
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

    fn value(&self, matches: &ArgMatches) -> Result<Option<Value>, String> {
        match self.arg_type {
            "string" => match matches.value_of(self.arg_name) {
                Some(val) => Ok(Some(Value::String(val.into()))),
                None => Ok(None),
            },
            "bool" => Ok(Some(Value::Bool(matches.is_present(self.arg_name)))),
            "u64" => self.u64(matches),
            _ => {
                if self.arg_type.starts_with("map(")
                    && self.arg_type.ends_with(")")
                {
                    return Ok(Some(self.object(matches)?));
                }

                panic!("unsupported RPC argument type: {}", self.arg_type);
            }
        }
    }

    fn u64(&self, matches: &ArgMatches) -> Result<Option<Value>, String> {
        let val = match matches.value_of(self.arg_name) {
            Some(val) => val,
            None => return Ok(None),
        };

        let val = u64::from_str(val).map_err(|e| {
            format!("failed to parse argument [--{}]: {:?}", self.arg_name, e)
        })?;

        Ok(Some(Value::String(format!("{:#x}", val))))
    }

    fn object(&self, matches: &ArgMatches) -> Result<Value, String> {
        let fields: Vec<&str> = self
            .arg_type
            .trim_start_matches("map(")
            .trim_end_matches(")")
            .split(";")
            .collect();

        let mut object = Map::new();

        for field in fields {
            let schema = ArgSchema::parse(field);
            if let Some(val) = schema.value(matches)? {
                object.insert(schema.arg_name.into(), val);
            }
        }

        Ok(Value::Object(object))
    }
}
