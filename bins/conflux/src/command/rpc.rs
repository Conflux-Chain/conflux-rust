// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::command::helpers::{input_password, password_prompt};
use clap::ArgMatches;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use serde_json::{Map, Value};
use std::str::FromStr;

pub struct RpcCommand {
    pub url: String,
    pub method: String,
    pub args: Vec<Value>,
}

impl RpcCommand {
    pub fn parse(matches: &ArgMatches) -> Result<Option<RpcCommand>, String> {
        let method = match matches.value_of("rpc-method") {
            Some(method) => method,
            None => return Ok(None),
        };

        let url = matches
            .value_of("url")
            .ok_or_else(|| String::from("RPC URL not specified"))?;

        let args = match matches.values_of("rpc-args") {
            Some(args) => {
                let mut params = Vec::new();

                for arg in args {
                    match ArgSchema::parse(arg).value(matches)? {
                        Some(val) => params.push(val),
                        None => break,
                    }
                }
                params
            }
            None => Vec::new(),
        };

        Ok(Some(RpcCommand {
            url: url.into(),
            method: method.into(),
            args,
        }))
    }

    pub async fn execute(self) -> Result<String, String> {
        let client = HttpClientBuilder::default()
            .build(&self.url)
            .map_err(|e| e.to_string())?;
        let result: Value = client
            .request(&self.method, self.args)
            .await
            .map_err(|e| e.to_string())?;
        Ok(format!("{:#}", result))
    }
}

struct ArgSchema<'a> {
    arg_name: &'a str,
    arg_type: &'a str,
}

impl<'a> ArgSchema<'a> {
    fn parse(arg: &'a str) -> Self {
        let schema: Vec<&str> = arg.splitn(2, ':').collect();
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
            "password" => Ok(Some(self.password()?)),
            "password2" => Ok(Some(self.password2()?)),
            _ => {
                if self.arg_type.starts_with("map(")
                    && self.arg_type.ends_with(')')
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
            .trim_end_matches(')')
            .split(';')
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

    fn password(&self) -> Result<Value, String> {
        input_password().map(|pwd| Value::String(pwd.as_str().to_string()))
    }

    fn password2(&self) -> Result<Value, String> {
        password_prompt().map(|pwd| Value::String(pwd.as_str().to_string()))
    }
}

#[cfg(test)]

mod tests {
    use super::*;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use tokio;

    async fn run_rpc_test(
        method: &str, args: Vec<Value>, expected_result_value: Value,
    ) {
        let mut server = Server::new_async().await;
        let url = server.url();

        let expected_request_body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": args.clone(),
            "id": 0
        });

        let mock_response_body = json!({
          "jsonrpc": "2.0",
          "id": 0,
          "result": expected_result_value.clone()
        });

        let mock = server
            .mock("POST", "/")
            .match_header("content-type", "application/json")
            .match_body(Matcher::Json(expected_request_body.clone()))
            .with_status(200)
            .with_body(mock_response_body.to_string())
            .create_async()
            .await;

        let command = RpcCommand {
            url,
            method: method.to_string(),
            args,
        };

        let result = command.execute().await;

        mock.assert_async().await;
        assert!(result.is_ok());
        let result_str = result.unwrap();
        assert_eq!(result_str, format!("{:#}", expected_result_value));
    }

    #[tokio::test]
    async fn test_rpc_execute_without_args() {
        let method = "cfx_getStatus";
        let args: Vec<Value> = vec![];
        let expected_result = json!({
            "bestHash": "0x64c936773e434069ede6bec161419b37ab6110409095a1d91d2bb91c344b523f",
            "chainId": "0x1",
            "ethereumSpaceChainId": "0x47",
            "networkId": "0x1",
            "epochNumber": "0xcdee1fd",
            "blockNumber": "0x10be2f9b",
            "pendingTxNumber": "0x8cf",
            "latestCheckpoint": "0xcdd7500",
            "latestConfirmed": "0xcdee1c3",
            "latestState": "0xcdee1f9",
            "latestFinalized": "0xcdee0ac"
        });

        run_rpc_test(method, args, expected_result).await;
    }

    #[tokio::test]
    async fn test_rpc_execute_cfx_epoch_number_with_param() {
        let method = "cfx_epochNumber";
        let args: Vec<Value> = vec![json!("0x4350b21")];
        let expected_result = json!("0x4350b21");

        run_rpc_test(method, args, expected_result).await;
    }
}
