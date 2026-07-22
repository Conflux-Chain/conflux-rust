// Copyright (c) The Diem Core Contributors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#![forbid(unsafe_code)]

//! `diem_channel` is an mpmc-style channel with per-key queues, providing
//! load isolation across senders and eviction-on-full semantics (FIFO, LIFO,
//! or KLAST).

pub mod diem_channel;
#[cfg(test)]
mod diem_channel_test;

pub mod message_queues;
#[cfg(test)]
mod message_queues_test;
