use clap::{load_yaml, App, ArgMatches};
use futures::future::Future;
use jsonrpc_core::{Params, Value};
use jsonrpc_core_client::{transports::http::connect, RawClient};
use jsonrpc_http_server::hyper::rt;
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
        match parse_arg(arg, opts)? {
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

fn parse_arg(arg: &str, opts: &ArgMatches) -> Result<Option<Value>, String> {
    let arg: Vec<&str> = arg.split(":").collect();
    let arg_name = arg[0];

    if arg.len() == 1 {
        return match opts.value_of(arg_name) {
            Some(val) => Ok(Some(Value::String(val.into()))),
            None => Ok(None),
        };
    }

    match arg[1] {
        "bool" => Ok(Some(Value::Bool(opts.is_present(arg[0])))),
        "u64" => {
            let val = match opts.value_of(arg_name) {
                Some(val) => val,
                None => return Ok(None),
            };

            let val = u64::from_str(val).map_err(|e| {
                format!("failed to parse argument [--{}]: {:?}", arg_name, e)
            })?;

            Ok(Some(Value::String(format!("{:#x}", val))))
        }
        _ => panic!("unsupported RPC argument type: {}", arg[1]),
    }
}
