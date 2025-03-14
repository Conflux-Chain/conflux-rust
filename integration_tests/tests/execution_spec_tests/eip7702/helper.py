from hashlib import sha256
from itertools import count
from dataclasses import dataclass
from enum import Enum, auto

import pytest

from ethereum_test_base_types import HexNumber
from ethereum_test_forks import Fork
from ethereum_test_tools import (
    AccessList,
    Account,
    Address,
    Alloc,
    AuthorizationTuple,
    Block,
    BlockchainTestFiller,
    Bytecode,
    Bytes,
    CodeGasMeasure,
    Conditional,
    Environment,
    EVMCodeType,
    Hash,
    Initcode,
    Requests,
    StateTestFiller,
    Storage,
    Transaction,
    TransactionException,
    add_kzg_version,
    call_return_code,
    compute_create_address,
)
from ethereum_test_tools import Macros as Om
from ethereum_test_tools import Opcodes as Op
from ethereum_test_tools.eof.v1 import Container, Section

class AddressType(Enum):
    """
    Different types of addresses used to specify the type of authority that signs an authorization,
    and the type of address to which the authority authorizes to set the code to.
    """

    EMPTY_ACCOUNT = auto()
    EOA = auto()
    EOA_WITH_SET_CODE = auto()
    CONTRACT = auto()
    


class ChainIDType(Enum):
    """Different types of chain IDs used in the authorization list."""

    GENERIC = auto()
    CHAIN_SPECIFIC = auto()

@dataclass(frozen=True)
class Spec:
    """
    Parameters from the EIP-7702 specifications as defined at
    https://eips.ethereum.org/EIPS/eip-7702.
    """

    SET_CODE_TX_TYPE = 0x04
    MAGIC = 0x05
    PER_AUTH_BASE_COST = 12_500
    PER_EMPTY_ACCOUNT_COST = 25_000
    DELEGATION_DESIGNATION = Bytes("ef0100")
    RESET_DELEGATION_ADDRESS = Address(0)

    MAX_AUTH_CHAIN_ID = 2**256 - 1
    MAX_NONCE = 2**64 - 1

    @staticmethod
    def delegation_designation(address: Address) -> Bytes:
        """Return delegation designation for the given address."""
        return Bytes(Spec.DELEGATION_DESIGNATION + bytes(address))

