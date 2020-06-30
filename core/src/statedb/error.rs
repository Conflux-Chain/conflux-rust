// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

use crate::storage::Error as StorageError;
use cfx_types::Address;
use primitives::account::AccountError;
use rlp::DecoderError;

error_chain! {
    links {
    }

    foreign_links {
        Account(AccountError);
        Storage(StorageError);
        Decoder(DecoderError);
    }

    errors {
        IncompleteDatabase(address: Address) {
            description("incomplete database")
            display("incomplete database: address={:?}", address)
        }
    }
}
