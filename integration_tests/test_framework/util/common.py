import json

NULL_ADDRESS = "0x0000000000000000000000000000000000000000"

def encode_u256(number):
    return ("%x" % number).zfill(64)


def encode_bytes20(hex):
    return hex.ljust(64, "0")


def number_to_topic(number):
    return "0x" + encode_u256(number)


def reserialize_json(json_str: str) -> str:
    return json.dumps(json.loads(json_str), sort_keys=True)
