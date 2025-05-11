// Copyright 2019-2020 Conflux Foundation. All rights reserved.
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

use std::{collections::VecDeque, env, fmt, fs, io::Read, process};

use cfxstore::{
    accounts_dir::{KeyDirectory, RootDiskDirectory},
    cfxkey::{Address, Password, Secret},
    import_accounts, CfxStore, PresaleWallet, SecretStore, SecretVaultRef,
    SimpleSecretStore, StoreAccountRef,
};

use clap::{Parser, Subcommand};

mod crack;

#[derive(Parser, Debug)]
#[command(
    version,
    about("Conflux key management tool. \nCopyright 2020 Conflux Foundation")
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Save account with password.
    Insert {
        #[arg()]
        secret: String,

        #[arg()]
        password: String,

        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },

    /// Change password.
    ChangePwd {
        #[arg()]
        address: String,
        #[arg()]
        old_pwd: String,
        #[arg()]
        new_pwd: String,

        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },
    /// List accounts.
    List {
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },

    /// Import accounts from src.
    Import {
        #[arg(long, default_value_t = String::new())]
        password: String,
        /// Specify import source. It may be either  parity, parity-(chain),
        /// geth, geth-test or a path [default: geth].
        #[arg(default_value_t = String::from("geth"), long)]
        src: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
    },

    /// Import presale wallet.
    ImportWallet {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },

    /// Tries to open a wallet with list of passwords given.
    FindWalletPass {
        #[arg(long)]
        path: String,
        #[arg(long)]
        password: String,
    },

    /// Remove account.
    Remove {
        #[arg()]
        address: String,
        #[arg()]
        password: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },

    /// Sign message.
    Sign {
        #[arg()]
        address: String,
        #[arg()]
        password: String,
        #[arg()]
        message: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },

    /// Displays public key for an address.
    Public {
        #[arg()]
        address: String,
        #[arg()]
        password: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },

    /// List vaults.
    ListVaults {
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
    },

    /// Create new vault.
    CreateVault {
        #[arg()]
        vault: String,
        #[arg()]
        password: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
    },

    /// Change vault password.
    ChangeVaultPwd {
        #[arg()]
        vault: String,
        #[arg()]
        old_pwd: String,
        #[arg()]
        new_pwd: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
    },
    /// Move account to vault from another vault/root directory.
    MoveToVault {
        #[arg()]
        address: String,
        #[arg()]
        password: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
        /// Specify vault to use in this operation.
        #[arg(long, default_value_t = String::new())]
        vault: String,
        /// Specify vault password to use in this operation. Please note that
        /// this option is required when vault option is set. Otherwise it is
        /// ignored.
        #[arg(long("vault-pwd"))]
        vault_pwd: String,
    },

    /// Move account to root directory from given vault.
    MoveFromVault {
        #[arg()]
        address: String,
        #[arg()]
        vault: String,
        #[arg()]
        password: String,
        /// Specify the secret store directory. It may be either  parity,
        /// parity-(chain), geth, geth-test or a path [default: parity].
        #[arg(default_value_t = String::from("parity"), long)]
        dir: String,
    },
}
enum Error {
    Ethstore(cfxstore::Error),
}

impl From<cfxstore::Error> for Error {
    fn from(err: cfxstore::Error) -> Self {
        Error::Ethstore(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Ethstore(ref err) => fmt::Display::fmt(err, f),
        }
    }
}

fn main() {
    panic_hook::set_abort();
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "warn")
    }
    env_logger::try_init().expect("Logger initialized only once.");
    let cli = Cli::parse();

    match execute(cli) {
        Ok(result) => println!("{}", result),
        Err(err) => {
            eprintln!("{}", err);
            process::exit(1);
        }
    }
}

fn key_dir(
    location: &str, password: Option<Password>,
) -> Result<Box<dyn KeyDirectory>, Error> {
    let dir: RootDiskDirectory = match location {
        "geth" => RootDiskDirectory::create(dir::geth(false))?,
        "geth-test" => RootDiskDirectory::create(dir::geth(true))?,
        path if path.starts_with("parity") => {
            let chain = path.split('-').nth(1).unwrap_or("ethereum");
            let path = dir::parity(chain);
            RootDiskDirectory::create(path)?
        }
        path => RootDiskDirectory::create(path)?,
    };

    Ok(Box::new(dir.with_password(password)))
}

fn open_args_vault(
    store: &CfxStore, flag_vault: &str, flag_vault_pwd: &str,
) -> Result<SecretVaultRef, Error> {
    if flag_vault.is_empty() {
        return Ok(SecretVaultRef::Root);
    }

    let vault_pwd = load_password(&flag_vault_pwd)?;
    store.open_vault(&flag_vault, &vault_pwd)?;
    Ok(SecretVaultRef::Vault(flag_vault.to_string()))
}

fn open_args_vault_account(
    store: &CfxStore, address: Address, flag_vault: &str, flag_vault_pwd: &str,
) -> Result<StoreAccountRef, Error> {
    match open_args_vault(store, flag_vault, flag_vault_pwd)? {
        SecretVaultRef::Root => Ok(StoreAccountRef::root(address)),
        SecretVaultRef::Vault(name) => {
            Ok(StoreAccountRef::vault(&name, address))
        }
    }
}

fn format_accounts(accounts: &[Address]) -> String {
    accounts
        .iter()
        .enumerate()
        .map(|(i, a)| format!("{:2}: 0x{:x}", i, a))
        .collect::<Vec<String>>()
        .join("\n")
}

fn format_vaults(vaults: &[String]) -> String {
    vaults.join("\n")
}

fn load_password(path: &str) -> Result<Password, Error> {
    let mut file = fs::File::open(path).map_err(|e| {
        cfxstore::Error::Custom(format!(
            "Error opening password file '{}': {}",
            path, e
        ))
    })?;
    let mut password = String::new();
    file.read_to_string(&mut password).map_err(|e| {
        cfxstore::Error::Custom(format!(
            "Error reading password file '{}': {}",
            path, e
        ))
    })?;
    // drop EOF
    let _ = password.pop();
    Ok(password.into())
}

fn execute(cli: Cli) -> Result<String, Error> {
    return match &cli.command {
        Commands::Insert {
            secret,
            password,
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let secret =
                secret.parse().map_err(|_| cfxstore::Error::InvalidSecret)?;
            let password = load_password(&password)?;
            let vault_ref = open_args_vault(&store, vault, vault_pwd)?;
            let account_ref =
                store.insert_account(vault_ref, secret, &password)?;
            Ok(format!("0x{:x}", account_ref.address))
        }
        Commands::ChangePwd {
            address,
            old_pwd,
            new_pwd,
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let address = address
                .parse()
                .map_err(|_| cfxstore::Error::InvalidAccount)?;
            let old_pwd = load_password(old_pwd)?;
            let new_pwd = load_password(new_pwd)?;
            let account_ref =
                open_args_vault_account(&store, address, vault, vault_pwd)?;
            let ok = store
                .change_password(&account_ref, &old_pwd, &new_pwd)
                .is_ok();
            Ok(format!("{}", ok))
        }
        Commands::List {
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let vault_ref = open_args_vault(&store, vault, vault_pwd)?;
            let accounts = store.accounts()?;
            let accounts: Vec<_> = accounts
                .into_iter()
                .filter(|a| &a.vault == &vault_ref)
                .map(|a| a.address)
                .collect();
            Ok(format_accounts(&accounts))
        }

        Commands::Import { password, src, dir } => {
            let password = match password.as_ref() {
                "" => None,
                _ => Some(load_password(&password)?),
            };
            let src = key_dir(src, password)?;
            let dst = key_dir(dir, None)?;

            let accounts = import_accounts(&*src, &*dst)?;
            Ok(format_accounts(&accounts))
        }
        Commands::ImportWallet {
            path,
            password,
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let wallet = PresaleWallet::open(path)?;
            let password = load_password(password)?;
            let kp = wallet.decrypt(&password)?;
            let vault_ref = open_args_vault(&store, vault, vault_pwd)?;
            let secret = Secret::from(kp.secret().to_fixed_bytes());
            let account_ref =
                store.insert_account(vault_ref, secret, &password)?;
            Ok(format!("0x{:x}", account_ref.address))
        }
        Commands::FindWalletPass { path, password } => {
            let passwords = load_password(password)?;
            let passwords = passwords
                .as_str()
                .lines()
                .map(|line| str::to_owned(line).into())
                .collect::<VecDeque<_>>();
            crack::run(passwords, path)?;
            Ok(format!("Password not found."))
        }
        Commands::Remove {
            address,
            password,
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;

            let address = address
                .parse()
                .map_err(|_| cfxstore::Error::InvalidAccount)?;
            let password = load_password(password)?;
            let account_ref =
                open_args_vault_account(&store, address, vault, vault_pwd)?;
            let ok = store.remove_account(&account_ref, &password).is_ok();
            Ok(format!("{}", ok))
        }
        Commands::Sign {
            address,
            password,
            message,
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let address = address
                .parse()
                .map_err(|_| cfxstore::Error::InvalidAccount)?;
            let message = message
                .parse()
                .map_err(|_| cfxstore::Error::InvalidMessage)?;
            let password = load_password(password)?;
            let account_ref =
                open_args_vault_account(&store, address, vault, vault_pwd)?;
            let signature = store.sign(&account_ref, &password, &message)?;
            Ok(format!("0x{}", signature))
        }
        Commands::Public {
            address,
            password,
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let address = address
                .parse()
                .map_err(|_| cfxstore::Error::InvalidAccount)?;
            let password = load_password(password)?;
            let account_ref =
                open_args_vault_account(&store, address, vault, vault_pwd)?;
            let public = store.public(&account_ref, &password)?;
            Ok(format!("0x{:x}", public))
        }

        Commands::ListVaults { dir } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let vaults = store.list_vaults()?;
            Ok(format_vaults(&vaults))
        }
        Commands::CreateVault {
            vault,
            password,
            dir,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let password = load_password(password)?;
            store.create_vault(vault, &password)?;
            Ok("OK".to_owned())
        }

        Commands::ChangeVaultPwd {
            vault,
            old_pwd,
            new_pwd,
            dir,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let old_pwd = load_password(old_pwd)?;
            let new_pwd = load_password(new_pwd)?;
            store.open_vault(vault, &old_pwd)?;
            store.change_vault_password(vault, &new_pwd)?;
            Ok("OK".to_owned())
        }

        Commands::MoveToVault {
            address,
            password,
            dir,
            vault,
            vault_pwd,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let address = address
                .parse()
                .map_err(|_| cfxstore::Error::InvalidAccount)?;
            let password = load_password(password)?;
            let account_ref =
                open_args_vault_account(&store, address, vault, vault_pwd)?;
            store.open_vault(vault, &password)?;
            store.change_account_vault(
                SecretVaultRef::Vault(vault.to_string()),
                account_ref,
            )?;
            Ok("OK".to_owned())
        }
        Commands::MoveFromVault {
            address,
            vault,
            password,
            dir,
        } => {
            let store = CfxStore::open(key_dir(dir, None)?)?;
            let address = address
                .parse()
                .map_err(|_| cfxstore::Error::InvalidAccount)?;
            let password = load_password(password)?;
            store.open_vault(vault, &password)?;
            store.change_account_vault(
                SecretVaultRef::Root,
                StoreAccountRef::vault(vault, address),
            )?;
            Ok("OK".to_owned())
        }
    };
}
