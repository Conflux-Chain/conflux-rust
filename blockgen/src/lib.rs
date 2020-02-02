// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

mod block_generator;
mod tg_block_generator;

pub use self::{
    block_generator::BlockGenerator, tg_block_generator::TGBlockGenerator,
};
