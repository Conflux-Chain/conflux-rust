use super::super::contracts::{IncreaseStakeEvent, RegisterEvent};
use crate::{
    executive::{internal_contract::SolidityEventTrait, InternalRefContext},
    vm::{self, ActionParams},
};
use bls_signatures::{
    sigma_protocol::{decode_answer, decode_commit, verify},
    Error as CryptoError, PublicKey, Serialize,
};
use cfx_types::{H256, U256};
use tiny_keccak::{Hasher, Keccak};

pub struct IndexStatus {
    registered: u64,
    unlocked: u64,
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

    pub fn locked(&self) -> u64 { self.registered - self.unlocked }
}

impl Into<U256> for IndexStatus {
    fn into(self) -> U256 { U256([self.registered, self.unlocked, 0, 0]) }
}

type Bytes = Vec<u8>;

fn decode_bls_pubkey(bls_pubkey: Bytes) -> Result<PublicKey, CryptoError> {
    PublicKey::from_bytes(bls_pubkey.as_slice())
}

fn verify_bls_pubkey(
    bls_pubkey: Bytes, bls_proof: [Bytes; 2],
) -> Result<Option<Bytes>, CryptoError> {
    let pubkey = decode_bls_pubkey(bls_pubkey)?;
    let commit = decode_commit(bls_proof[0].as_slice())?;
    let answer = decode_answer(bls_proof[1].as_slice())?;
    let verified_pubkey = if verify(pubkey.clone(), commit, answer) {
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
    identifier: H256, vote_power: u64, initialize_mode: bool,
    param: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<()>
{
    let mut status: IndexStatus =
        context.storage_at(param, identifier.as_bytes())?.into();
    if !initialize_mode && status.registered == 0 {
        return Err(vm::Error::InternalContract(
            "uninitialized identifier".into(),
        ));
    }
    if initialize_mode && status.registered != 0 {
        return Err(vm::Error::InternalContract(
            "identifier has already been initialized".into(),
        ));
    }
    status.registered = status.registered.checked_add(vote_power).ok_or(
        vm::Error::InternalContract("registered index overflow".into()),
    )?;
    IncreaseStakeEvent::log(&identifier, &status.registered, param, context)?;
    context.set_storage(
        param,
        identifier.as_bytes().to_vec(),
        status.into(),
    )?;
    Ok(())
}

pub fn register(
    identifier: H256, vote_power: u64, bls_pubkey: Bytes, vrf_pubkey: Bytes,
    bls_proof: [Bytes; 2], param: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()>
{
    if vote_power == 0 {
        return Err(vm::Error::InternalContract(
            "vote_power should be none zero".into(),
        ));
    }

    let maybe_verified_bls_pubkey = verify_bls_pubkey(bls_pubkey, bls_proof)?;
    let verified_bls_pubkey = maybe_verified_bls_pubkey.ok_or(
        vm::Error::InternalContract("Can not verify bls pubkey".into()),
    )?;

    let mut hasher = Keccak::v256();
    hasher.update(verified_bls_pubkey.as_slice());
    hasher.update(vrf_pubkey.as_slice());
    let mut computed_identifier = H256::default();
    hasher.finalize(computed_identifier.as_bytes_mut());

    if computed_identifier != identifier {
        return Err(vm::Error::InternalContract(
            "Inconsistent identifier".into(),
        ));
    }
    RegisterEvent::log(
        &identifier,
        &(verified_bls_pubkey, vrf_pubkey),
        param,
        context,
    )?;

    update_vote_power(
        identifier, vote_power, /* allow_uninitialized */ true, param,
        context,
    )
}

pub fn increase_stake(
    identifier: H256, vote_power: u64, param: &ActionParams,
    context: &mut InternalRefContext,
) -> vm::Result<()>
{
    if vote_power == 0 {
        return Err(vm::Error::InternalContract(
            "vote_power should be none zero".into(),
        ));
    }
    update_vote_power(
        identifier, vote_power, /* allow_uninitialized */ false, param,
        context,
    )
}

pub fn get_status(
    identifier: H256, param: &ActionParams, context: &mut InternalRefContext,
) -> vm::Result<(u64, u64)> {
    let status: IndexStatus =
        context.storage_at(param, identifier.as_bytes())?.into();
    Ok((status.registered, status.unlocked))
}

pub fn decode_register_info(event: &LogEntry) -> Option<StakingEvent> {
    if event.address != *POS_REGISTER_CONTRACT_ADDRESS {
        return None;
    }

    match event
        .topics
        .first()
        .expect("First topic is event sig")
        .clone()
    {
        sig if sig == RegisterEvent::event_sig() => {
            let identifier =
                event.topics.get(1).expect("Second topic is identifier");
            let (verified_bls_pubkey, vrf_pubkey) =
                <(Bytes, Bytes)>::abi_decode(&event.data).unwrap();
            Some(Register((*identifier, verified_bls_pubkey, vrf_pubkey)))
        }
        sig if sig == IncreaseStakeEvent::event_sig() => {
            let identifier =
                event.topics.get(1).expect("Second topic is identifier");
            let power = u64::abi_decode(&event.data).unwrap();
            Some(IncreaseStake((*identifier, power)))
        }
        _ => unreachable!(),
    }
}

use cfx_parameters::internal_contract_addresses::POS_REGISTER_CONTRACT_ADDRESS;
use diem_types::validator_config::ConsensusPublicKey;
use move_core_types::account_address::AccountAddress;
use pow_types::StakingEvent::{self, IncreaseStake, Register};
use primitives::log_entry::LogEntry;
use solidity_abi::ABIDecodable;
