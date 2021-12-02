// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]
use diem_genesis_tool::command::Command;
use structopt::StructOpt;

fn main() {
    match Command::from_args().execute() {
        Ok(output) => println!("{}", output),
        Err(err) => {
            println!("Operation unsuccessful: {}", err);
            std::process::exit(1);
        }
    }
}
