// Copyright 2020 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

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

use std::{fmt, io, num::ParseIntError, process, sync};

use cfxkey::{
    brain_recover, sign, verify_address, verify_public, Brain, BrainPrefix,
    Error as EthkeyError, Generator, KeyPair, Prefix, Random,
};
use clap::{Parser, Subcommand};
use rustc_hex::{FromHex, FromHexError};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Display only the secret key.
    #[arg(short, long, default_value_t = false)]
    secret: bool,
    /// Display only the public key.
    #[arg(short, long, default_value_t = false)]
    public: bool,
    /// Display only the address.
    #[arg(short, long, default_value_t = false)]
    address: bool,
    /// Use parity brain wallet algorithm. Not recommended.
    #[arg(short, long, default_value_t = false)]
    brain: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Display public key and address of the secret.
    Info {
        #[arg()]
        secret_or_phrase: String,
    },
    Generate {
        #[command(subcommand)]
        command: GenerateCommands,
    },

    /// Sign message using a secret key.
    Sign {
        #[arg()]
        secret: String,
        #[arg()]
        message: String,
    },

    /// Verify signer of the signature by public key or address.
    Verify {
        #[command(subcommand)]
        command: VerifyCommands,
    },

    ///  Try to find brain phrase matching given address from partial phrase.
    Recover {
        #[arg()]
        known_phrase: String,
        #[arg()]
        address: String,
    },
}

#[derive(Subcommand)]
enum GenerateCommands {
    /// Generates new random Ethereum key.
    Random {},
    /// Random generation, but address must start with a prefix ("vanity
    /// address").
    Prefix {
        #[arg()]
        prefix: String,
    },
}

#[derive(Subcommand)]
enum VerifyCommands {
    Public {
        #[arg()]
        public: String,
        #[arg()]
        signature: String,
        #[arg()]
        message: String,
    },
    Address {
        #[arg()]
        address: String,
        #[arg()]
        signature: String,
        #[arg()]
        message: String,
    },
}

#[derive(Debug)]
enum Error {
    Ethkey(EthkeyError),
    FromHex(FromHexError),
    ParseInt(ParseIntError),
    Io(io::Error),
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

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self { Error::Io(err) }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Ethkey(ref e) => write!(f, "{}", e),
            Error::FromHex(ref e) => write!(f, "{}", e),
            Error::ParseInt(ref e) => write!(f, "{}", e),
            Error::Io(ref e) => write!(f, "{}", e),
        }
    }
}

enum DisplayMode {
    KeyPair,
    Secret,
    Public,
    Address,
}

impl DisplayMode {
    fn new(args: &Cli) -> Self {
        if args.secret {
            DisplayMode::Secret
        } else if args.public {
            DisplayMode::Public
        } else if args.address {
            DisplayMode::Address
        } else {
            DisplayMode::KeyPair
        }
    }
}

fn main() {
    panic_hook::set_abort();
    env_logger::try_init().expect("Logger initialized only once.");
    let cli = Cli::parse();
    match execute(cli) {
        Ok(ok) => println!("{}", ok),
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
}

fn display(result: (KeyPair, Option<String>), mode: DisplayMode) -> String {
    let keypair = result.0;
    match mode {
        DisplayMode::KeyPair => match result.1 {
            Some(extra_data) => format!("{}\n{}", extra_data, keypair),
            None => format!("{}", keypair),
        },
        DisplayMode::Secret => format!("{:x}", keypair.secret()),
        DisplayMode::Public => format!("{:x}", keypair.public()),
        DisplayMode::Address => format!("{:x}", keypair.address()),
    }
}

fn execute(cli: Cli) -> Result<String, Error> {
    let display_mode = DisplayMode::new(&cli);
    return match &cli.command {
        Commands::Info { secret_or_phrase } => {
            execute_info(secret_or_phrase, cli.brain, display_mode)
        }
        Commands::Generate { command } => {
            execute_generate(command, cli.brain, display_mode)
        }
        Commands::Sign { secret, message } => {
            execute_sign(secret.clone(), message.clone())
        }
        Commands::Verify { command } => execute_verify(command),
        Commands::Recover {
            known_phrase,
            address,
        } => execute_recover(known_phrase, address, display_mode),
    };
}

fn execute_info(
    secret_or_phrase: &str, brain: bool, display_mode: DisplayMode,
) -> Result<String, Error> {
    let result = if brain {
        let phrase = secret_or_phrase.to_string();
        let phrase_info = validate_phrase(&phrase);
        let keypair = Brain::new(phrase)
            .generate()
            .expect("Brain wallet generator is infallible; qed");
        (keypair, Some(phrase_info))
    } else {
        let secret = secret_or_phrase
            .parse()
            .map_err(|_| EthkeyError::InvalidSecret)?;
        (KeyPair::from_secret(secret)?, None)
    };
    Ok(display(result, display_mode))
}

fn execute_generate(
    command: &GenerateCommands, brain: bool, display_mode: DisplayMode,
) -> Result<String, Error> {
    let result = match &command {
        GenerateCommands::Random {} => {
            if brain {
                let mut brain =
                    BrainPrefix::new(vec![0], usize::max_value(), BRAIN_WORDS);
                let keypair = brain.generate()?;
                let phrase = format!("recovery phrase: {}", brain.phrase());
                (keypair, Some(phrase))
            } else {
                (Random.generate()?, None)
            }
        }
        GenerateCommands::Prefix { prefix } => {
            let prefix: Vec<u8> = prefix.from_hex()?;
            let brain = brain;
            in_threads(move || {
                let iterations = 1024;
                let prefix = prefix.clone();
                move || {
                    let prefix = prefix.clone();
                    let res = if brain {
                        let mut brain =
                            BrainPrefix::new(prefix, iterations, BRAIN_WORDS);
                        let result = brain.generate();
                        let phrase =
                            format!("recovery phrase: {}", brain.phrase());
                        result.map(|keypair| (keypair, Some(phrase)))
                    } else {
                        let result = Prefix::new(prefix, iterations).generate();
                        result.map(|res| (res, None))
                    };

                    Ok(res.map(Some).unwrap_or(None))
                }
            })?
        }
    };
    Ok(display(result, display_mode))
}

fn execute_sign(secret: String, message: String) -> Result<String, Error> {
    let secret = secret.parse().map_err(|_| EthkeyError::InvalidSecret)?;
    let message = message.parse().map_err(|_| EthkeyError::InvalidMessage)?;
    let signature = sign(&secret, &message)?;
    Ok(format!("{}", signature))
}

fn execute_verify(command: &VerifyCommands) -> Result<String, Error> {
    let result = match &command {
        VerifyCommands::Public {
            public,
            signature,
            message,
        } => {
            let signature = signature
                .parse()
                .map_err(|_| EthkeyError::InvalidSignature)?;
            let message =
                message.parse().map_err(|_| EthkeyError::InvalidMessage)?;

            let public =
                public.parse().map_err(|_| EthkeyError::InvalidPublic)?;
            verify_public(&public, &signature, &message)?
        }
        VerifyCommands::Address {
            address,
            signature,
            message,
        } => {
            let signature = signature
                .parse()
                .map_err(|_| EthkeyError::InvalidSignature)?;
            let message =
                message.parse().map_err(|_| EthkeyError::InvalidMessage)?;
            let address =
                address.parse().map_err(|_| EthkeyError::InvalidAddress)?;
            verify_address(&address, &signature, &message)?
        }
    };
    Ok(format!("{}", result))
}

fn execute_recover(
    known_phrase: &str, address: &str, display_mode: DisplayMode,
) -> Result<String, Error> {
    let known_phrase = known_phrase;
    let address = address.parse().map_err(|_| EthkeyError::InvalidAddress)?;
    let (phrase, keypair) = in_threads(move || {
        let mut it = brain_recover::PhrasesIterator::from_known_phrase(
            &known_phrase,
            BRAIN_WORDS,
        )
        .enumerate();
        move || {
            for (i, phrase) in &mut it {
                let keypair = Brain::new(phrase.clone()).generate().unwrap();
                if keypair.address() == address {
                    return Ok(Some((phrase, keypair)));
                }

                if i >= 1024 {
                    return Ok(None);
                }
            }

            Err(EthkeyError::Custom("Couldn't find any results.".into()))
        }
    })?;
    Ok(display((keypair, Some(phrase)), display_mode))
}
const BRAIN_WORDS: usize = 12;

fn validate_phrase(phrase: &str) -> String {
    match Brain::validate_phrase(phrase, BRAIN_WORDS) {
        Ok(()) => "The recovery phrase looks correct.\n".to_string(),
        Err(err) => {
            format!("The recover phrase was not generated by Conflux: {}", err)
        }
    }
}

fn in_threads<F, X, O>(prepare: F) -> Result<O, EthkeyError>
where
    O: Send + 'static,
    X: Send + 'static,
    F: Fn() -> X,
    X: FnMut() -> Result<Option<O>, EthkeyError>,
{
    let pool = threadpool::Builder::new().build();

    let (tx, rx) = sync::mpsc::sync_channel(1);
    let is_done = sync::Arc::new(sync::atomic::AtomicBool::default());

    for _ in 0..pool.max_count() {
        let is_done = is_done.clone();
        let tx = tx.clone();
        let mut task = prepare();
        pool.execute(move || {
            loop {
                if is_done.load(sync::atomic::Ordering::SeqCst) {
                    return;
                }

                let res = match task() {
                    Ok(None) => continue,
                    Ok(Some(v)) => Ok(v),
                    Err(err) => Err(err),
                };

                // We are interested only in the first response.
                let _ = tx.send(res);
            }
        });
    }

    if let Ok(solution) = rx.recv() {
        is_done.store(true, sync::atomic::Ordering::SeqCst);
        return solution;
    }

    Err(EthkeyError::Custom("No results found.".into()))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use crate::Cli;

    use super::execute;

    #[test]
    fn info() {
        let cli = Cli::parse_from([
            "cfxkey",
            "info",
            "17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55",
        ]);

        let expected =
            "secret:  17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55
public:  689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124
address: 16d1ec50b4e62c1d1a40d16e7cacc6a6580757d5".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn brain() {
        let cli =
            Cli::parse_from(["cfxkey", "--brain", "info", "this is sparta"]);

        let expected =
            "The recover phrase was not generated by Conflux: The word 'this' does not come from the dictionary.

secret:  a6bb621db2721ee05c44de651dde50ef85feefc5e91ae23bedcae69b874a22e7
public:  756cb3f7ad1516b7c0ee34bd5e8b3a519922d3737192a58115e47df57ff3270873360a61de523ce08c0ebd7d3801bcb1d03c0364431d2b8633067f3d79e1fb25
address: 10a33d9f95b22fe53024331c036db6e824a25bab".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn secret() {
        let cli = Cli::parse_from([
            "cfxkey",
            "--brain",
            "--secret",
            "info",
            "this is sparta",
        ]);

        let expected =
            "a6bb621db2721ee05c44de651dde50ef85feefc5e91ae23bedcae69b874a22e7"
                .to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn public() {
        let cli = Cli::parse_from([
            "cfxkey",
            "--brain",
            "--public",
            "info",
            "this is sparta",
        ]);

        let expected = "756cb3f7ad1516b7c0ee34bd5e8b3a519922d3737192a58115e47df57ff3270873360a61de523ce08c0ebd7d3801bcb1d03c0364431d2b8633067f3d79e1fb25".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn address() {
        let cli = Cli::parse_from([
            "cfxkey",
            "-b",
            "--address",
            "info",
            "this is sparta",
        ]);

        let expected = "10a33d9f95b22fe53024331c036db6e824a25bab".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn sign() {
        let cli = Cli::parse_from([
            "cfxkey",
            "sign",
            "17d08f5fe8c77af811caa0c9a187e668ce3b74a99acc3f6d976f075fa8e0be55",
            "bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987",
        ]);

        let expected = "c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn verify_valid_public() {
        let cli = Cli::parse_from(["cfxkey", "verify", "public", "689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124", "c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200", "bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987"]);

        let expected = "true".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn verify_valid_address() {
        let cli = Cli::parse_from(["cfxkey", "verify", "address", "16d1ec50b4e62c1d1a40d16e7cacc6a6580757d5", "c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200", "bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec987"]);

        let expected = "true".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }

    #[test]
    fn verify_invalid() {
        let cli = Cli::parse_from(["cfxkey", "verify", "public", "689268c0ff57a20cd299fa60d3fb374862aff565b20b5f1767906a99e6e09f3ff04ca2b2a5cd22f62941db103c0356df1a8ed20ce322cab2483db67685afd124", "c1878cf60417151c766a712653d26ef350c8c75393458b7a9be715f053215af63dfd3b02c2ae65a8677917a8efa3172acb71cb90196e42106953ea0363c5aaf200", "bd50b7370c3f96733b31744c6c45079e7ae6c8d299613246d28ebcef507ec986"]);

        let expected = "false".to_owned();
        assert_eq!(execute(cli).unwrap(), expected);
    }
}
