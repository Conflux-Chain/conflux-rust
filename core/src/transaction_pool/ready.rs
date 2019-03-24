// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// The transaction is stale (and should/will be removed from the pool).
    Stale,
    /// The transaction is ready to be included in ready set.
    Ready,
    /// The transaction is not yet ready, should be added in pending set.
    Future,
    /// The transaction is in too distant future.
    TooDistantFuture,
}

/// A readiness indicator.
pub trait Ready<T> {
    /// Returns true if transaction is ready to be included in new block,
    /// given all previous dependent transactions that were ready are already
    /// included.
    fn is_ready(&mut self, tx: &T) -> Readiness;
}
