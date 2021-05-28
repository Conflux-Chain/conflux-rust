// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate cfxkey;
extern crate env_logger;
extern crate keccak_hash;
extern crate rustc_hex;
extern crate serde;
extern crate serde_derive;

use cfxkey::{Error as EthkeyError, Generator, Public, Random};
use diem_crypto::{
    ed25519::{Ed25519PrivateKey, Ed25519PublicKey, ED25519_PUBLIC_KEY_LENGTH},
    Uniform,
};
use diem_types::{
    account_address::{from_public_key, AccountAddress},
    contract_event::ContractEvent,
    on_chain_config::{new_epoch_event_key, ValidatorSet},
    transaction::{ChangeSet, Transaction, WriteSetPayload},
    validator_config::ValidatorConfig,
    validator_info::ValidatorInfo,
    waypoint::Waypoint,
    write_set::WriteSet,
};
use diemdb::DiemDB;
use docopt::Docopt;
use executor::{
    db_bootstrapper::{calculate_genesis, generate_waypoint, maybe_bootstrap},
    vm::FakeVM,
    Executor,
};
use keccak_hash::keccak;
use log::*;
use move_core_types::language_storage::TypeTag;
use primitives::account::AddressSpace::Contract;
use rand::{rngs::StdRng, SeedableRng};
use rustc_hex::{FromHexError, ToHex};
use serde::Deserialize;
use std::{
    convert::TryFrom,
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
use storage_interface::DbReaderWriter;
use tempdir::TempDir;

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

fn execute_genesis_transaction(genesis_txn: Transaction) -> Waypoint {
    let tmp_dir = TempDir::new("example").unwrap();
    let (_, db) = DbReaderWriter::wrap(
        DiemDB::open(
            tmp_dir.path(),
            false, /* readonly */
            Some(1_000_000),
            Default::default(),
        )
        .expect("DB should open."),
    );

    generate_waypoint::<FakeVM>(&db, &genesis_txn).unwrap()
}

fn generate_genesis_from_public_keys(public_keys: Vec<Ed25519PublicKey>) {
    let genesis_path = PathBuf::from("./genesis_file");
    let waypoint_path = PathBuf::from("./waypoint_config");
    let mut genesis_file = File::create(&genesis_path).unwrap();
    let mut waypoint_file = File::create(&waypoint_path).unwrap();

    let mut validators = Vec::new();
    for public_key in public_keys {
        let account_address = from_public_key(&public_key);
        let validator_config = ValidatorConfig::new(public_key, vec![], vec![]);
        validators.push(ValidatorInfo::new(
            account_address,
            1,
            validator_config,
        ));
    }
    let validator_set = ValidatorSet::new(validators);
    let validator_set_bytes = bcs::to_bytes(&validator_set).unwrap();
    let contract_event = ContractEvent::new(
        new_epoch_event_key(),
        0,
        TypeTag::Address,
        validator_set_bytes,
    );
    let change_set = ChangeSet::new(WriteSet::default(), vec![contract_event]);
    let write_set_paylod = WriteSetPayload::Direct(change_set);
    let genesis_transaction = Transaction::GenesisTransaction(write_set_paylod);
    let genesis_bytes = bcs::to_bytes(&genesis_transaction).unwrap();
    genesis_file.write_all(&genesis_bytes).unwrap();

    let waypoint = execute_genesis_transaction(genesis_transaction);
    waypoint_file
        .write_all(waypoint.to_string().as_bytes())
        .unwrap();
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
        let mut rng = StdRng::from_seed([0u8; 32]);
        let mut public_keys = Vec::new();

        for i in 0..num_validator {
            let private_key = Ed25519PrivateKey::generate(&mut rng);
            let public_key = Ed25519PublicKey::from(&private_key);
            public_keys.push(public_key.clone());

            let mut private_key_str = String::new();
            writeln!(
                &mut private_key_str,
                "{:?}",
                hex::encode(private_key.to_bytes())
            )?;
            let private_key_str = private_key_str.replace("\"", "");
            private_key_file.write_all(private_key_str.as_str().as_bytes())?;

            let mut public_key_str = String::new();
            writeln!(
                &mut public_key_str,
                "{:?}",
                hex::encode(public_key.to_bytes())
            )?;
            let public_key_str = &public_key_str[2..];
            public_key_file.write_all(public_key_str.as_bytes())?;
        }
        generate_genesis_from_public_keys(public_keys);
        Ok("Ok".into())
    } else if args.cmd_frompub {
        let public_key_path = PathBuf::from(args.arg_pkfile.as_str());
        let mut public_key_file = File::open(&public_key_path)?;
        let mut contents = String::new();
        public_key_file.read_to_string(&mut contents)?;
        let mut lines = contents.as_str().lines();
        let mut line_num = 0;

        let mut public_keys = Vec::new();
        while let Some(public_key_str) = lines.next() {
            let public_key_bytes = hex::decode(public_key_str).unwrap();
            let public_key =
                Ed25519PublicKey::try_from(public_key_bytes.as_slice())
                    .unwrap();
            public_keys.push(public_key);
        }
        generate_genesis_from_public_keys(public_keys);
        Ok("Ok".into())
    } else {
        Ok(USAGE.to_string())
    }
}
