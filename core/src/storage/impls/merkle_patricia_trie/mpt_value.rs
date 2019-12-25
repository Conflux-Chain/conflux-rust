// Copyright 2019 Conflux Foundation. All rights reserved.
// Conflux is free software and distributed under GNU General Public License.
// See http://www.gnu.org/licenses/

#[derive(Clone, Debug, PartialEq)]
pub enum MptValue<ValueType> {
    None,
    TombStone,
    Some(ValueType),
}

impl<ValueType: Default> MptValue<ValueType> {
    pub fn is_some(&self) -> bool {
        match self {
            MptValue::Some(_) => true,
            _ => false,
        }
    }

    pub fn into_option(self) -> Option<ValueType> {
        match self {
            MptValue::None => None,
            MptValue::TombStone => Some(ValueType::default()),
            MptValue::Some(x) => Some(x),
        }
    }

    pub fn take(&mut self) -> Self { std::mem::replace(self, MptValue::None) }

    pub fn unwrap(self) -> ValueType {
        match self {
            MptValue::None => unreachable!(),
            MptValue::TombStone => ValueType::default(),
            MptValue::Some(x) => x,
        }
    }
}
