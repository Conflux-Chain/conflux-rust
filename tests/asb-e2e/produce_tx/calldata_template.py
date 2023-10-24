from dataclasses import dataclass
from typing import List
from enum import Enum
from web3 import Web3
import re
from .transaction import TxParam
from . import log


@dataclass
class ReplacePosition:
    start: str
    length: str


class PlaceholderType(Enum):
    Hex = 0
    Address = 1
    Number = 2


def placeholder(index: int, bytes: int, ty: PlaceholderType):
    assert index < 256
    assert bytes % 4 == 0
    pattern = "252525" + f"{index:#04x}"[2:]

    output = pattern * (bytes // 4)

    if ty == PlaceholderType.Address:
        return Web3.toChecksumAddress("0x" + output)
    elif ty == PlaceholderType.Number:
        return int(output, 16)
    elif ty == PlaceholderType.Hex:
        return output
    
def address_ph(index: int):
    return placeholder(index, 20, PlaceholderType.Address)


def hex_no_prefix(input: str):
    if input[:2] == "0x":
        input = input[2:]

    return input.lower()


class CalldataTemplate:
    def __init__(self, template, address):
        template = hex_no_prefix(template)

        self.template = template
        self.address = address
        self.params: List[ReplacePosition] = []

        for i in range(256):
            pattern = placeholder(i, 4, PlaceholderType.Hex)
            m = re.search(f"({pattern})+", template[8:])
            if m:
                self.params.append(ReplacePosition(
                    m.start() + 8, m.end() - m.start()))
            else:
                break        

    def build_tx_param(self, sender_index, *params):
        calldata = self.fill(*params)
        return TxParam(sender_index=sender_index, action=bytearray.fromhex(self.address[2:]), data = bytearray.fromhex(calldata))

    def fill(self, *params):
        def detect_length(input):
            if type(input) is int:
                return None
            elif type(input) is hex:
                input = hex_no_prefix(input)
                return len(input)
            elif type(input) is bytearray:
                return len(input) * 2
            elif type(input) is bytes:
                return len(input) * 2
            else:
                raise Exception(f"Unknown type {type(input)}")

        def formalize_input(input, length):
            if type(input) is int:
                return hex(input)[2:].zfill(length)
            elif type(input) is hex:
                input = hex_no_prefix(input)
                return input.lower()
            elif type(input) is bytearray:
                return input.hex()
            elif type(input) is bytes:
                return input.hex()
            else:
                raise Exception(f"Unknown type {type(input)}")

        output = self.template
        for (data, pos) in zip(params, self.params):
            expect_length = detect_length(data)
            if expect_length is not None:
                assert expect_length == pos.length

            start = pos.start
            end = pos.start + pos.length
            output = output[:start] + formalize_input(data, pos.length) + output[end:]

        # log.critical(output)
            
        return output
