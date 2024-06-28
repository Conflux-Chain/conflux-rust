use bls_signatures::{
    sigma_protocol::{decode_answer, decode_commit, verify},
    Error as CryptoError, PublicKey, Serialize,
};
use tiny_keccak::{Hasher, Keccak};

use cfx_parameters::{
    internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS,
    staking::POS_VOTE_PRICE,
};
use cfx_statedb::Result as DbResult;
use cfx_types::{Address, BigEndianHash, H256, U256};
use cfx_vm_types::{self as vm, ActionParams};
use pow_types::StakingEvent::{self, IncreaseStake, Register, Retire};
use primitives::log_entry::LogEntry;
use solidity_abi::ABIDecodable;

use crate::internal_bail;

use super::super::{
    components::{InternalRefContext, SolidityEventTrait},
    contracts::pos::{IncreaseStakeEvent, RegisterEvent, RetireEvent},
};

use self::entries::*;

pub struct IndexStatus {
    pub registered: u64,
    pub unlocked: u64,
}

impl From<U256> for IndexStatus {
    fn from(input: U256) -> Self {
        IndexStatus {
            registered: input.0[0],
            unlocked: input.0[1],
        }
    }
}

impl IndexStatus {
    #[allow(unused)]
    pub fn inc_unlocked(&mut self, number: u64) -> Result<(), &'static str> {
        match self.unlocked.checked_add(number) {
            None => Err("u64 overflow"),
            Some(answer) if answer > self.registered => {
                Err("The unlocked votes exceeds registered votes")
            }
            Some(answer) => {
                self.unlocked = answer;
                Ok(())
            }
        }
    }

    pub fn set_unlocked(&mut self, number: u64) { self.unlocked = number; }

    pub fn locked(&self) -> u64 { self.registered - self.unlocked }
}

impl Into<U256> for IndexStatus {
    fn into(self) -> U256 { U256([self.registered, self.unlocked, 0, 0]) }
}

type Bytes = Vec<u8>;

#[inline]
fn address_to_u256(value: Address) -> U256 { H256::from(value).into_uint() }

#[inline]
fn u256_to_address(value: &U256) -> Address {
    let addr: H256 = BigEndianHash::from_uint(value);
    Address::from(addr)
}

fn decode_bls_pubkey(bls_pubkey: Bytes) -> Result<PublicKey, CryptoError> {
    PublicKey::from_bytes(bls_pubkey.as_slice())
}

fn verify_bls_pubkey(
    bls_pubkey: Bytes, bls_proof: [Bytes; 2], legacy: bool,
) -> Result<Option<Bytes>, CryptoError> {
    let pubkey = decode_bls_pubkey(bls_pubkey)?;
    let commit = decode_commit(bls_proof[0].as_slice())?;
    let answer = decode_answer(bls_proof[1].as_slice())?;
    let verified_pubkey = if verify(pubkey.clone(), commit, answer, legacy) {
        let mut serialized_pubkey: Vec<u8> = Vec::new();
        pubkey
            .write_bytes(&mut serialized_pubkey)
            .expect("Write to `Vec<u8>` should never fail");
        Some(serialized_pubkey)
    } else {
        None
    };
    Ok(verified_pubkey)
}

fn update_vote_power(
    identifier: H256, sender: Address, vote_power: u64, initialize_mode: bool,
    params: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()> {
    let status: IndexStatus = context
        .storage_at(params, &index_entry(&identifier))?
        .into();

    if !initialize_mode && status.registered == 0 {
        internal_bail!("uninitialized identifier");
    }
    if initialize_mode && status.registered != 0 {
        internal_bail!("identifier has already been initialized");
    }

    let votes = status
        .locked()
        .checked_add(vote_power)
        .ok_or(vm::Error::InternalContract("locked votes overflow".into()))?;
    if context.state.staking_balance(&sender)? < *POS_VOTE_PRICE * votes {
        internal_bail!("Not enough staking balance");
    }

    let mut status = status;
    status.registered = status.registered.checked_add(vote_power).ok_or(
        vm::Error::InternalContract("registered index overflow".into()),
    )?;
    context
        .state
        .add_total_pos_staking(*POS_VOTE_PRICE * vote_power);

    IncreaseStakeEvent::log(&identifier, &vote_power, params, context)?;
    context.set_storage(params, index_entry(&identifier), status.into())?;
    Ok(())
}

fn is_identifier_changeable(
    sender: Address, params: &ActionParams, context: &mut InternalRefContext,
) -> DbResult<bool> {
    let identifier = address_to_identifier(sender, params, context)?;
    if identifier.is_zero() {
        return Ok(true);
    }
    let status = get_status(identifier, params, context)?;
    Ok(status.registered == status.unlocked)
}

pub fn register(
    identifier: H256, sender: Address, vote_power: u64, bls_pubkey: Bytes,
    vrf_pubkey: Bytes, bls_proof: [Bytes; 2], param: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()> {
    if vote_power == 0 {
        internal_bail!("vote_power should be none zero");
    }

    if !is_identifier_changeable(sender, param, context)? {
        internal_bail!("can not change identifier");
    }

    let verified_bls_pubkey = match verify_bls_pubkey(
        bls_pubkey,
        bls_proof,
        !context.spec.cip_sigma_fix,
    ) {
        Err(e) => {
            internal_bail!("Crypto decoding error {:?}", e);
        }
        Ok(None) => {
            internal_bail!("Can not verify bls pubkey");
        }
        Ok(Some(key)) => key,
    };

    let mut hasher = Keccak::v256();
    hasher.update(verified_bls_pubkey.as_slice());
    hasher.update(vrf_pubkey.as_slice());
    let mut computed_identifier = H256::default();
    hasher.finalize(computed_identifier.as_bytes_mut());

    if computed_identifier != identifier {
        internal_bail!("Inconsistent identifier");
    }
    if identifier_to_address(identifier, param, context)? != Address::zero() {
        internal_bail!("identifier has already been registered");
    }

    RegisterEvent::log(
        &identifier,
        &(verified_bls_pubkey, vrf_pubkey),
        param,
        context,
    )?;

    context.set_storage(
        param,
        address_entry(&identifier),
        address_to_u256(sender),
    )?;
    context.set_storage(
        param,
        identifier_entry(&sender),
        identifier.into_uint(),
    )?;
    update_vote_power(
        identifier, sender, vote_power, /* allow_uninitialized */ true,
        param, context,
    )
}

pub fn increase_stake(
    sender: Address, vote_power: u64, params: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()> {
    if vote_power == 0 {
        internal_bail!("vote_power should be none zero");
    }

    let identifier = address_to_identifier(sender, params, context)?;

    if identifier.is_zero() {
        internal_bail!("The sender has not register a PoS identifier");
    }

    update_vote_power(
        identifier, sender, vote_power, /* allow_uninitialized */ false,
        params, context,
    )
}

pub fn retire(
    sender: Address, votes: u64, params: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()> {
    let identifier = address_to_identifier(sender, params, context)?;

    if identifier.is_zero() {
        internal_bail!("The sender has not register a PoS identifier");
    }

    let status: IndexStatus = context
        .storage_at(params, &index_entry(&identifier))?
        .into();

    if status.locked() == 0 {
        internal_bail!("The PoS account is fully unlocked");
    }

    RetireEvent::log(&identifier, &votes, params, context)?;
    Ok(())
}

pub fn get_status(
    identifier: H256, params: &ActionParams, context: &mut InternalRefContext,
) -> DbResult<IndexStatus> {
    Ok(context
        .storage_at(params, &index_entry(&identifier))?
        .into())
}

pub fn identifier_to_address(
    identifier: H256, params: &ActionParams, context: &mut InternalRefContext,
) -> DbResult<Address> {
    Ok(u256_to_address(
        &context.storage_at(params, &address_entry(&identifier))?,
    ))
}

pub fn address_to_identifier(
    address: Address, params: &ActionParams, context: &mut InternalRefContext,
) -> DbResult<H256> {
    Ok(BigEndianHash::from_uint(
        &context.storage_at(params, &identifier_entry(&address))?,
    ))
}

pub fn decode_register_info(event: &LogEntry) -> Option<StakingEvent> {
    if event.address != POS_REGISTER_CONTRACT_ADDRESS {
        return None;
    }

    match event.topics.first().expect("First topic is event sig") {
        sig if sig == &RegisterEvent::EVENT_SIG => {
            let identifier =
                event.topics.get(1).expect("Second topic is identifier");
            let (verified_bls_pubkey, vrf_pubkey) =
                <(Bytes, Bytes)>::abi_decode(&event.data).unwrap();
            Some(Register(*identifier, verified_bls_pubkey, vrf_pubkey))
        }
        sig if sig == &IncreaseStakeEvent::EVENT_SIG => {
            let identifier =
                event.topics.get(1).expect("Second topic is identifier");
            let power = u64::abi_decode(&event.data).unwrap();
            Some(IncreaseStake(*identifier, power))
        }
        sig if sig == &RetireEvent::EVENT_SIG => {
            let identifier =
                event.topics.get(1).expect("Second topic is identifier");
            let votes = u64::abi_decode(&event.data).unwrap();
            Some(Retire(*identifier, votes))
        }
        _ => unreachable!(),
    }
}

pub fn make_staking_events(logs: &[LogEntry]) -> Vec<StakingEvent> {
    logs.iter().filter_map(decode_register_info).collect()
}

pub mod entries {
    use super::*;

    pub type StorageEntryKey = Vec<u8>;

    fn prefix_and_hash(prefix: u64, data: &[u8]) -> StorageEntryKey {
        let mut hasher = Keccak::v256();
        hasher.update(&prefix.to_be_bytes());
        hasher.update(data);
        let mut hash = H256::default();
        hasher.finalize(hash.as_bytes_mut());
        hash.as_bytes().to_vec()
    }

    #[inline]
    pub fn index_entry(identifier: &H256) -> StorageEntryKey {
        prefix_and_hash(0, identifier.as_bytes())
    }

    #[inline]
    pub fn address_entry(identifier: &H256) -> StorageEntryKey {
        prefix_and_hash(1, identifier.as_bytes())
    }

    #[inline]
    pub fn identifier_entry(sender: &Address) -> StorageEntryKey {
        prefix_and_hash(2, sender.as_bytes())
    }
}
