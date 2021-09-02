// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

extern crate cfxkey;
extern crate env_logger;
extern crate keccak_hash;
extern crate rustc_hex;
extern crate serde;
extern crate serde_derive;

use std::{
    env, fmt,
    fs::File,
    io::{self, Read, Write},
    num::ParseIntError,
    path::PathBuf,
    process,
    result::Result,
};

use docopt::Docopt;
use log::*;
use rand::{rngs::StdRng, SeedableRng};
use rustc_hex::FromHexError;
use serde::Deserialize;
use tempdir::TempDir;

use cfxcore::spec::genesis::{
    register_transaction, GenesisPosNodeInfo, GenesisPosState,
};
use cfxkey::{Error as EthkeyError, Generator, KeyPair, Random};
use client::configuration::save_initial_nodes_to_file;
use diem_crypto::{
    key_file::save_pri_key, Uniform, ValidCryptoMaterialStringExt,
};
use diem_types::{
    account_address::from_consensus_public_key,
    contract_event::ContractEvent,
    on_chain_config::{new_epoch_event_key, ValidatorSet},
    transaction::{ChangeSet, Transaction, WriteSetPayload},
    validator_config::{
        ConsensusPrivateKey, ConsensusPublicKey, ConsensusVRFPrivateKey,
        ConsensusVRFPublicKey, ValidatorConfig,
    },
    validator_info::ValidatorInfo,
    waypoint::Waypoint,
    write_set::WriteSet,
};
use diemdb::DiemDB;
use executor::{db_bootstrapper::generate_waypoint, vm::FakeVM};
use move_core_types::language_storage::TypeTag;
use std::path::Path;
use storage_interface::DbReaderWriter;

const USAGE: &str = r#"
Usage:
    tgconfig random [--num-validator=<nv> --num-genesis-validator=<ng> --chain-id=<id>]
    tgconfig frompub <pkfile>

Options:
    -h, --help              Display this message and exit.
    --num-validator=<nv>    The number of validators.
    --num-genesis-validator=<ng>    The number of validators included in the genesis.
    --chain-id=<id>         The chain id of the PoW chain.

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
    flag_num_genesis_validator: usize,
    flag_chain_id: u32,
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

fn generate_genesis_from_public_keys(
    public_keys: Vec<(ConsensusPublicKey, ConsensusVRFPublicKey, u64)>,
) {
    let genesis_path = PathBuf::from("../../run/pos_config/genesis_file");
    let waypoint_path = PathBuf::from("./waypoint_config");
    let mut genesis_file = File::create(&genesis_path).unwrap();
    let mut waypoint_file = File::create(&waypoint_path).unwrap();

    let mut validators = Vec::new();
    for (public_key, vrf_public_key, voting_power) in public_keys {
        let account_address =
            from_consensus_public_key(&public_key, &vrf_public_key);
        let validator_config = ValidatorConfig::new(
            public_key,
            Some(vrf_public_key),
            vec![],
            vec![],
        );
        validators.push(ValidatorInfo::new(
            account_address,
            voting_power,
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

        let num_genesis_validator = if args.flag_num_genesis_validator == 0 {
            num_validator
        } else if args.flag_num_genesis_validator > num_validator {
            panic!("The number of genesis validators cannot be more than the total number of \
            validators: {} > {}", args.flag_num_genesis_validator, num_validator);
        } else {
            args.flag_num_genesis_validator
        };

        let chain_id = args.flag_chain_id;

        let private_key_dir = PathBuf::from("./private_keys");
        std::fs::create_dir(&private_key_dir)?;
        let public_key_path = PathBuf::from("./public_key");
        let mut public_key_file = File::create(&public_key_path)?;
        let mut rng = StdRng::from_seed([0u8; 32]);
        let mut genesis_nodes = Vec::new();

        for i in 0..num_validator {
            let pow_keypair: KeyPair = Random.generate().unwrap();
            let private_key = ConsensusPrivateKey::generate(&mut rng);
            let vrf_private_key = ConsensusVRFPrivateKey::generate(&mut rng);
            save_pri_key(
                private_key_dir.join(PathBuf::from(i.to_string())),
                &[],
                &(&private_key, &vrf_private_key),
            )
            .expect("Error saving private keys");
            File::create(
                private_key_dir.join(Path::new(&format!("pow_sk{}", i))),
            )?
            .write_all(pow_keypair.secret().as_bytes())?;

            let public_key = ConsensusPublicKey::from(&private_key);
            let vrf_public_key = ConsensusVRFPublicKey::from(&vrf_private_key);
            let register_tx = register_transaction(
                private_key,
                vrf_public_key.clone(),
                1,
                chain_id,
            );
            let public_key_str = public_key.to_encoded_string().unwrap();
            let vrf_public_key_str =
                vrf_public_key.to_encoded_string().unwrap();
            let public_key_str =
                format!("{},{}\n", public_key_str, vrf_public_key_str);
            public_key_file.write_all(public_key_str.as_bytes())?;
            genesis_nodes.push(GenesisPosNodeInfo {
                address: pow_keypair.address(),
                bls_key: public_key,
                vrf_key: vrf_public_key,
                voting_power: 1,
                register_tx,
            });
        }
        save_initial_nodes_to_file(
            "./initial_nodes.json",
            GenesisPosState {
                initial_nodes: genesis_nodes[..num_genesis_validator].to_vec(),
            },
        );
        generate_genesis_from_public_keys(
            genesis_nodes
                .into_iter()
                .take(num_genesis_validator)
                .map(|node| (node.bls_key, node.vrf_key, node.voting_power))
                .collect(),
        );
        Ok("Ok".into())
    } else if args.cmd_frompub {
        let public_key_path = PathBuf::from(args.arg_pkfile.as_str());
        let mut public_key_file = File::open(&public_key_path)?;
        let mut contents = String::new();
        public_key_file.read_to_string(&mut contents)?;
        let mut lines = contents.as_str().lines();

        let mut public_keys = Vec::new();
        while let Some(key_str) = lines.next() {
            let key_array: Vec<_> = key_str.split(",").collect();
            let public_key =
                ConsensusPublicKey::from_encoded_string(key_array[0]).unwrap();
            let vrf_public_key =
                ConsensusVRFPublicKey::from_encoded_string(key_array[1])
                    .unwrap();
            public_keys.push((public_key, vrf_public_key, 1));
        }
        generate_genesis_from_public_keys(public_keys);
        Ok("Ok".into())
    } else {
        Ok(USAGE.to_string())
    }
}
