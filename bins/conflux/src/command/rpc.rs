// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::command::helpers::{input_password, password_prompt};
use clap::ArgMatches;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder};
use serde_json::{Map, Value};

pub struct RpcCommand {
    pub url: String,
    pub method: String,
    pub args: Vec<Value>,
}

impl RpcCommand {
    pub fn parse(matches: &ArgMatches) -> Result<Option<RpcCommand>, String> {
        let method = match matches.get_one::<String>("rpc-method") {
            Some(method) => method,
            None => return Ok(None),
        };

        let url = match matches.get_one::<String>("url") {
            Some(url) => url,
            None => return Err(String::from("RPC URL not specified")),
        };

        let args: Vec<Value> = match matches.try_get_many::<String>("rpc-args")
        {
            Ok(Some(args)) => {
                let mut params = Vec::new();

                for arg in args {
                    match ArgSchema::parse(arg).value(matches)? {
                        Some(val) => params.push(val),
                        None => break,
                    }
                }
                params
            }
            Ok(None) => Vec::new(),
            Err(_e) => Vec::new(),
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
            "string" => match matches.get_one::<String>(self.arg_name) {
                Some(val) => Ok(Some(Value::String(val.into()))),
                None => Ok(None),
            },
            "bool" => Ok(Some(Value::Bool(matches.get_flag(self.arg_name)))),
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
        let val = match matches.get_one::<u64>(self.arg_name) {
            Some(val) => val,
            None => return Ok(None),
        };

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
    use std::vec;

    use crate::cli::Cli;

    use super::*;
    use clap::CommandFactory;
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

    #[test]
    fn test_rpc_command_parse() {
        #[derive(Debug)]
        struct TestCase {
            name: &'static str,
            args: Vec<&'static str>,
            expected_method: &'static str,
            expected_url: &'static str,
            expected_params: Vec<Value>,
        }

        let test_cases = vec![
            TestCase {
                name: "estimate-gas with many arguments",
                args: vec![
                    "conflux",
                    "rpc",
                    "estimate-gas",
                    "--from",
                    "addr_from",
                    "--to",
                    "addr_to",
                    "--gas-price",
                    "gp_val",
                    "--type",
                    "type_val",
                    "--max-fee-per-gas",
                    "mfpg_val",
                    "--max-priority-fee-per-gas",
                    "mpfpg_val",
                    "--gas",
                    "gas_val",
                    "--value",
                    "value_val",
                    "--data",
                    "data_val",
                    "--nonce",
                    "nonce_val",
                    "--epoch",
                    "epoch_val",
                ],
                expected_method: "cfx_estimateGas",
                expected_url: "http://localhost:12539",
                expected_params: vec![
                    json!({
                        "data": "data_val",
                        "from": "addr_from",
                        "gas": "gas_val",
                        "gas-price": "gp_val",
                        "max-fee-per-gas": "mfpg_val",
                        "max-priority-fee-per-gas": "mpfpg_val",
                        "nonce": "nonce_val",
                        "to": "addr_to",
                        "type": "type_val",
                        "value": "value_val"
                    }),
                    json!("epoch_val"),
                ],
            },
            TestCase {
                name: "balance with custom URL",
                args: vec![
                    "conflux",
                    "rpc",
                    "balance",
                    "--url",
                    "http://0.0.0.0:8080",
                    "--address",
                    "test_address_001",
                    "--epoch",
                    "latest_state",
                ],
                expected_method: "cfx_getBalance",
                expected_url: "http://0.0.0.0:8080",
                expected_params: vec![
                    json!("test_address_001"),
                    json!("latest_state"),
                ],
            },
            TestCase {
                name: "block-by-hash",
                args: vec![
                    "conflux",
                    "rpc",
                    "block-by-hash",
                    "--hash",
                    "0x654321fedcba",
                ],
                expected_method: "cfx_getBlockByHash",
                expected_url: "http://localhost:12539",
                expected_params: vec![json!("0x654321fedcba"), json!(false)],
            },
            TestCase {
                name: "voting_status",
                args: vec!["conflux", "rpc", "local", "pos", "voting_status"],
                expected_method: "test_posVotingStatus",
                expected_params: vec![],
                expected_url: "http://localhost:12539",
            },
            TestCase {
                name: "voting_status_with_custom_url",
                args: vec![
                    "conflux",
                    "rpc",
                    "local",
                    "pos",
                    "voting_status",
                    "--url",
                    "http://localhost:9999",
                ],
                expected_method: "test_posVotingStatus",
                expected_params: vec![],
                expected_url: "http://localhost:9999",
            },
        ];

        for test_case in test_cases {
            let cli = Cli::command().get_matches_from(test_case.args);
            let mut subcmd_matches = &cli;
            while let Some(m) = subcmd_matches.subcommand() {
                subcmd_matches = m.1;
            }

            let rpc_command = match RpcCommand::parse(subcmd_matches) {
                Ok(Some(cmd)) => cmd,
                Ok(None) => panic!(
                    "Test case '{}': Expected RpcCommand but got None",
                    test_case.name
                ),
                Err(e) => panic!(
                    "Test case '{}': Error parsing RpcCommand: {}",
                    test_case.name, e
                ),
            };

            assert_eq!(
                rpc_command.method, test_case.expected_method,
                "Test case '{}': Method mismatch",
                test_case.name
            );

            assert_eq!(
                rpc_command.url, test_case.expected_url,
                "Test case '{}': URL mismatch",
                test_case.name
            );

            assert_eq!(
                rpc_command.args, test_case.expected_params,
                "Test case '{}': Parameters mismatch",
                test_case.name
            );
        }
    }
}
