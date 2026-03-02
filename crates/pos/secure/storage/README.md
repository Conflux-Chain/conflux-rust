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

This crate provides two storage implementations, each of which implements
both `KVStorage` and `CryptoStorage`:
- `InMemory`: A simple in-memory storage engine, primarily used for testing.
- `OnDisk`: An on-disk storage engine backed by a single file on local disk.

In addition, this crate also offers a `NamespacedStorage` wrapper around secure
storage implementations. Using the NamespacedStorage wrapper, different entities
can share the same secure storage instance under different namespaces.

## How is this module organized?
```
    secure/storage/
    ├── src                # Contains the definitions for secure storage (e.g., API and error types),
                                as well as the InMemory and OnDisk implementations.
    └── src/tests          # Contains the testsuite for all secure storage implementations.
```
