// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity Ethereum.

// Parity Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity Ethereum.  If not, see <http://www.gnu.org/licenses/>.

// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use ethkey::Password;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Write},
};

pub use dir::helpers::{replace_home, replace_home_and_local};

/// Flush output buffer.
pub fn flush_stdout() {
    io::stdout().flush().expect("stdout is flushable; qed");
}

/// Prompts user asking for password.
pub fn password_prompt() -> Result<Password, String> {
    use rpassword::read_password;
    const STDIN_ERROR: &'static str =
        "Unable to ask for password on non-interactive terminal.";

    println!("Please note that password is NOT RECOVERABLE.");
    print!("Type password: ");
    flush_stdout();

    let password = read_password().map_err(|_| STDIN_ERROR.to_owned())?.into();

    print!("Repeat password: ");
    flush_stdout();

    let password_repeat =
        read_password().map_err(|_| STDIN_ERROR.to_owned())?.into();

    if password != password_repeat {
        return Err("Passwords do not match!".into());
    }

    Ok(password)
}

/// Read a password from password file.
pub fn password_from_file(path: String) -> Result<Password, String> {
    let passwords = passwords_from_files(&[path])?;
    // use only first password from the file
    passwords
        .get(0)
        .map(Password::clone)
        .ok_or_else(|| "Password file seems to be empty.".to_owned())
}

/// Reads passwords from files. Treats each line as a separate password.
pub fn passwords_from_files(files: &[String]) -> Result<Vec<Password>, String> {
    let passwords = files.iter().map(|filename| {
		let file = File::open(filename).map_err(|_| format!("{} Unable to read password file. Ensure it exists and permissions are correct.", filename))?;
		let reader = BufReader::new(&file);
		let lines = reader.lines()
			.filter_map(|l| l.ok())
			.map(|pwd| pwd.trim().to_owned().into())
			.collect::<Vec<Password>>();
		Ok(lines)
	}).collect::<Result<Vec<Vec<Password>>, String>>();
    Ok(passwords?.into_iter().flat_map(|x| x).collect())
}
