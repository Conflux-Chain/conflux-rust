---
id: secure_storage
title: Secure Storage
---
# Secure Storage

Secure storage provides a secure, persistent data store for sensitive data in the
PoS consensus layer. Examples of sensitive data include information required for
safety and identity, such as cryptographic keys and consensus safety rules.

## Overview

This crate defines the secure storage API, made up of two separate Rust traits:
- `KVStorage`: Offers a key-value storage abstraction (e.g., to get and set
key-value pairs).
- `CryptoStorage`: Offers a cryptographic-key based storage abstraction for
Ed25519 keys (e.g., key creation, rotation and signing).

This crate provides a single storage implementation, `OnDiskStorage`, that
implements both `KVStorage` and `CryptoStorage`. It is backed by a JSON file
on local disk and rewrites the file atomically on every write.

## How is this module organized?
```
    secure/storage/
    ├── src                # Storage API, error types, and the OnDiskStorage implementation.
    └── src/tests          # Testsuite for OnDiskStorage.
```
