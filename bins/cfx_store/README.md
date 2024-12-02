## cfxstore-cli

Conflux key management. It is built on top of the Parity Ethereum counterpart.

### Usage

```
Conflux key management tool.
  Copyright 2020 Conflux Foundation

Usage:
    cfxstore insert <secret> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore change-pwd <address> <old-pwd> <new-pwd> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore list [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore import [--src DIR] [--dir DIR]
    cfxstore import-wallet <path> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore find-wallet-pass <path> <password>
    cfxstore remove <address> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore sign <address> <password> <message> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore public <address> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore list-vaults [--dir DIR]
    cfxstore create-vault <vault> <password> [--dir DIR]
    cfxstore change-vault-pwd <vault> <old-pwd> <new-pwd> [--dir DIR]
    cfxstore move-to-vault <address> <vault> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]
    cfxstore move-from-vault <address> <vault> <password> [--dir DIR]
    cfxstore [-h | --help]

Options:
    -h, --help               Display this message and exit.
    --dir DIR                Specify the secret store directory. It may be either
                             parity, parity-(chain), geth, geth-test
                             or a path [default: parity].
    --vault VAULT            Specify vault to use in this operation.
    --vault-pwd VAULTPWD     Specify vault password to use in this operation. Please note
                             that this option is required when vault option is set.
                             Otherwise it is ignored.
    --src DIR                Specify import source. It may be either
                             parity, parity-(chain), geth, geth-test
                             or a path [default: geth].

Commands:
    insert             Save account with password.
    change-pwd         Change password.
    list               List accounts.
    import             Import accounts from src.
    import-wallet      Import presale wallet.
    find-wallet-pass   Tries to open a wallet with list of passwords given.
    remove             Remove account.
    sign               Sign message.
    public             Displays public key for an address.
    list-vaults        List vaults.
    create-vault       Create new vault.
    change-vault-pwd   Change vault password.
    move-to-vault      Move account to vault from another vault/root directory.
    move-from-vault    Move account to root directory from given vault.
```

### Examples

#### `insert <secret> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*Encrypt secret with a password and save it in secret store.*

- `<secret>` - conflux secret, 32 bytes long
- `<password>` - account password, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - vault to use in this operation
- `[--vault-pwd VAULTPWD]` - vault password to use in this operation, file path

```
cfxstore insert 7d29fab185a33e2cd955812397354c472d2b84615b645aa135ff539f6b0d70d5 password.txt
```

```
a8fa5dd30a87bb9e3288d604eb74949c515ab66e
```

--

```
cfxstore insert `cfxkey generate random -s` "this is sparta"
```

```
24edfff680d536a5f6fe862d36df6f8f6f40f115
```

--

#### `change-pwd <address> <old-pwd> <new-pwd> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*Change account password.*

- `<address>` - conflux address, 20 bytes long
- `<old-pwd>` - old account password, file path
- `<new-pwd>` - new account password, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - vault to use in this operation
- `[--vault-pwd VAULTPWD]` - vault password to use in this operation, file path

```
cfxstore change-pwd a8fa5dd30a87bb9e3288d604eb74949c515ab66e old_pwd.txt new_pwd.txt
```

```
true
```

--

#### `list [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*List secret store accounts.*

- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - vault to use in this operation
- `[--vault-pwd VAULTPWD]` - vault password to use in this operation, file path

```
cfxstore list
```

```
 0: 24edfff680d536a5f6fe862d36df6f8f6f40f115
 1: 6edddfc6349aff20bc6467ccf276c5b52487f7a8
 2: e6a3d25a7cb7cd21cb720df5b5e8afd154af1bbb
```

--

#### `import [--src DIR] [--dir DIR]`
*Import accounts from src.*

- `[--src DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: geth
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity

```
cfxstore import
```

```
 0: e6a3d25a7cb7cd21cb720df5b5e8afd154af1bbb
 1: 6edddfc6349aff20bc6467ccf276c5b52487f7a8
```

--

#### `import-wallet <path> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*Import account from presale wallet.*

- `<path>` - presale wallet path
- `<password>` - account password, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - vault to use in this operation
- `[--vault-pwd VAULTPWD]` - vault password to use in this operation, file path

```
cfxstore import-wallet ethwallet.json password.txt
```

```
e6a3d25a7cb7cd21cb720df5b5e8afd154af1bbb
```


--

#### `find-wallet-pass <path> <password>`
Try to open presale wallet given a list of passwords from a file.
The list of passwords can be generated using e.g. [Phildo/brutedist](https://github.com/Phildo/brutedist).

- `<path>` - presale wallet path
- `<password>` - possible passwords, file path

```
cfxstore find-wallet-pass ethwallet.json passwords.txt
```

```
Found password: test
```


--

#### `remove <address> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*Remove account from secret store.*

- `<address>` - conflux address, 20 bytes long
- `<password>` - account password, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - vault to use in this operation
- `[--vault-pwd VAULTPWD]` - vault password to use in this operation, file path

```
cfxstore remove a8fa5dd30a87bb9e3288d604eb74949c515ab66e password.txt
```

```
true
```

--

#### `sign <address> <password> <message> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*Sign message with account's secret.*

- `<address>` - conflux address, 20 bytes long
- `<password>` - account password, file path
- `<message>` - message to sign, 32 bytes long
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - vault to use in this operation
- `[--vault-pwd VAULTPWD]` - vault password to use in this operation, file path

```
cfxstore sign 24edfff680d536a5f6fe862d36df6f8f6f40f115 password.txt 7d29fab185a33e2cd955812397354c472d2b84615b645aa135ff539f6b0d70d5
```

```
c6649f9555232d90ff716d7e552a744c5af771574425a74860e12f763479eb1b708c1f3a7dc0a0a7f7a81e0a0ca88c6deacf469222bb3d9c5bf0847f98bae54901
```

--

#### `public <address> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*Displays public key for an address.*

- `<address>` - conflux address, 20 bytes long
- `<password>` - account password, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - vault to use in this operation
- `[--vault-pwd VAULTPWD]` - vault password to use in this operation, file path

```
cfxstore public 00e63fdb87ceb815ec96ae185b8f7381a0b4a5ea account_password.txt --vault vault_name --vault-pwd vault_password.txt
```

```
0x84161d8c05a996a534efbec50f24485cfcc07458efaef749a1b22156d7836c903eeb39bf2df74676e702eacc4cfdde069e5fd86692b5ef6ef81ba906e9e77d82
```

--

#### `list-vaults [--dir DIR]`
*List vaults.*

- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity

```
cfxstore list-vaults
```

```
vault1
vault2
vault3
```

--

#### `create-vault <vault> <password> [--dir DIR]`
*Create new vault.*

- `<vault>` - name of new vault. This can only contain letters, digits, whitespaces, dashes and underscores
- `<password>` - vault password, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity

```
cfxstore create-vault vault3 vault3_password.txt
```

```
OK
```

--

#### `change-vault-pwd <vault> <old-pwd> <new-pwd> [--dir DIR]`
*Change vault password.*

- `<vault>` - name of existing vault
- `<old-pwd>` - old vault password, file path
- `<new-pwd>` - new vault password, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity

```
cfxstore change-vault-pwd vault3 vault3_password.txt new_vault3_password.txt
```

```
OK
```

--

#### `move-to-vault <address> <vault> <password> [--dir DIR] [--vault VAULT] [--vault-pwd VAULTPWD]`
*Move account to vault from another vault/root directory.*

- `<address>` - conflux address, 20 bytes long
- `<vault>` - name of existing vault to move account to
- `<password>` - password of existing `<vault>` to move account to, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity
- `[--vault VAULT]` - current vault of the `<address>` argument, if set
- `[--vault-pwd VAULTPWD]` - password for the current vault of the `<address>` argument, if any. file path


```
cfxstore move-to-vault 00e63fdb87ceb815ec96ae185b8f7381a0b4a5ea vault3 vault3_password.txt
cfxstore move-to-vault 00e63fdb87ceb815ec96ae185b8f7381a0b4a5ea vault1 vault1_password.txt --vault vault3 --vault-pwd vault3_password.txt
```

```
OK
OK
```

--

#### `move-from-vault <address> <vault> <password> [--dir DIR]`
*Move account to root directory from given vault.*

- `<address>` - conflux address, 20 bytes long
- `<vault>` - name of existing vault to move account to
- `<password>` - password of existing `<vault>` to move account to, file path
- `[--dir DIR]` - secret store directory, It may be either parity, parity-test, geth, geth-test or a path. default: parity


```
cfxstore move-from-vault 00e63fdb87ceb815ec96ae185b8f7381a0b4a5ea vault1 vault1_password.txt
```

```
OK
```
