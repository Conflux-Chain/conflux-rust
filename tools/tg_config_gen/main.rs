// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate env_logger;
extern crate ethkey;
extern crate keccak_hash;
extern crate rustc_hex;
extern crate serde;
extern crate serde_derive;

use docopt::Docopt;
use ethkey::{Error as EthkeyError, Generator, Public, Random};
use keccak_hash::keccak;
use log::*;
use rustc_hex::FromHexError;
use serde::Deserialize;
use std::{
    env,
    fmt::{self, Write as FmtWrite},
    fs::File,
    io::{self, Read, Write},
    num::ParseIntError,
    path::PathBuf,
    process,
    result::Result,
    str::FromStr,
    writeln,
};

const USAGE: &str = r#"
Usage:
    tgconfig random [--num-validator=<nv>]
    tgconfig frompub <pkfile>

Options:
    -h, --help              Display this message and exit.
    --num-validator=<nv>    The number of validators.

Commands:
    random                  Generate random key pairs for validators.
    frompub                 Generate config file from pubkey file.
"#;

#[derive(Debug, Deserialize)]
struct Args {
    cmd_random: bool,
    cmd_frompub: bool,
    arg_pkfile: String,
    flag_num_validator: usize,
}

#[derive(Debug)]
enum Error {
    Ethkey(EthkeyError),
    FromHex(FromHexError),
    ParseInt(ParseIntError),
    Docopt(docopt::Error),
    Io(io::Error),
    Fmt(fmt::Error),
}

impl From<EthkeyError> for Error {
    fn from(err: EthkeyError) -> Self { Error::Ethkey(err) }
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self { Error::FromHex(err) }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self { Error::ParseInt(err) }
}

impl From<docopt::Error> for Error {
    fn from(err: docopt::Error) -> Self { Error::Docopt(err) }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self { Error::Io(err) }
}

impl From<std::fmt::Error> for Error {
    fn from(err: std::fmt::Error) -> Self { Error::Fmt(err) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Ethkey(ref e) => write!(f, "{}", e),
            Error::FromHex(ref e) => write!(f, "{}", e),
            Error::ParseInt(ref e) => write!(f, "{}", e),
            Error::Docopt(ref e) => write!(f, "{}", e),
            Error::Io(ref e) => write!(f, "{}", e),
            Error::Fmt(ref e) => write!(f, "{}", e),
        }
    }
}

/// A struct that represents an account address.
/// Currently Public Key is used.
#[derive(Ord, PartialOrd, Eq, PartialEq, Hash, Default, Clone, Copy)]
pub struct AccountAddress([u8; 32]);

fn main() {
    env_logger::try_init().expect("Logger initialized only once.");

    match execute(env::args()) {
        Ok(ok) => println!("{}", ok),
        Err(Error::Docopt(ref e)) => e.exit(),
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
}

fn execute<S, I>(command: I) -> Result<String, Error>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Args =
        Docopt::new(USAGE).and_then(|d| d.argv(command).deserialize())?;

    info!("args {:?}", args);

    if args.cmd_random {
        let num_validator = if args.flag_num_validator == 0 {
            1
        } else {
            args.flag_num_validator
        };

        let pivate_key_path = PathBuf::from("./private_key");
        let mut private_key_file = File::create(&pivate_key_path)?;
        let public_key_path = PathBuf::from("./public_key");
        let mut public_key_file = File::create(&public_key_path)?;
        let peer_config_path = PathBuf::from("./consensus_peers.config.toml");
        let mut peer_config_file = File::create(&peer_config_path)?;

        for i in 0..num_validator {
            let key_pair = Random.generate()?;
            let private_key = key_pair.secret().clone();
            let public_key = key_pair.public().clone();
            let peer_hash = keccak(&public_key);

            let mut private_key_str = String::new();
            writeln!(&mut private_key_str, "{:?}", private_key.to_hex())?;
            let private_key_str = private_key_str.replace("\"", "");
            private_key_file.write_all(private_key_str.as_str().as_bytes())?;

            let mut public_key_str = String::new();
            writeln!(&mut public_key_str, "{:?}", public_key)?;
            let public_key_str = &public_key_str[2..];
            public_key_file.write_all(public_key_str.as_bytes())?;

            if i > 0 {
                writeln!(peer_config_file, "")?;
            }

            let mut peer_hash_str = String::new();
            write!(&mut peer_hash_str, "{:?}", peer_hash)?;
            let peer_str = &peer_hash_str[2..];
            let mut peer_hash_str = String::new();
            writeln!(&mut peer_hash_str, "{:?}", peer_str)?;
            let peer_hash_str = peer_hash_str.replacen("\"", "[", 1);
            let peer_hash_str = peer_hash_str.replacen("\"", "]", 1);
            peer_config_file.write_all(peer_hash_str.as_str().as_bytes())?;

            let mut pubkey_str = String::new();
            write!(&mut pubkey_str, "{:?}", public_key)?;
            let pubkey_str = &pubkey_str[2..];
            let mut peer_pubkey_str = String::new();
            writeln!(&mut peer_pubkey_str, "c = {:?}", pubkey_str)?;
            peer_config_file.write_all(peer_pubkey_str.as_str().as_bytes())?;
        }
        Ok("Ok".into())
    } else if args.cmd_frompub {
        let public_key_path = PathBuf::from(args.arg_pkfile.as_str());
        let mut public_key_file = File::open(&public_key_path)?;
        let mut contents = String::new();
        public_key_file.read_to_string(&mut contents)?;
        let mut lines = contents.as_str().lines();
        let mut line_num = 0;
        let peer_config_path = PathBuf::from("./consensus_peers.config.toml");
        let mut peer_config_file = File::create(&peer_config_path)?;
        while let Some(pubkey_str) = lines.next() {
            let public_key = Public::from_str(pubkey_str).unwrap();
            let peer_hash = keccak(&public_key);

            if line_num > 0 {
                writeln!(peer_config_file, "")?;
            }

            let mut peer_hash_str = String::new();
            write!(&mut peer_hash_str, "{:?}", peer_hash)?;
            let peer_str = &peer_hash_str[2..];
            let mut peer_hash_str = String::new();
            writeln!(&mut peer_hash_str, "{:?}", peer_str)?;
            let peer_hash_str = peer_hash_str.replacen("\"", "[", 1);
            let peer_hash_str = peer_hash_str.replacen("\"", "]", 1);
            peer_config_file.write_all(peer_hash_str.as_str().as_bytes())?;

            let mut pubkey_str = String::new();
            write!(&mut pubkey_str, "{:?}", public_key)?;
            let pubkey_str = &pubkey_str[2..];
            let mut peer_pubkey_str = String::new();
            writeln!(&mut peer_pubkey_str, "c = {:?}", pubkey_str)?;
            peer_config_file.write_all(peer_pubkey_str.as_str().as_bytes())?;

            line_num += 1;
        }
        Ok("Ok".into())
    } else {
        Ok(USAGE.to_string())
    }
}
