from eth_utils import decode_hex

default_config = dict(
    GENESIS_DIFFICULTY=0,
    GENESIS_PREVHASH=b'\x00' * 32,
    GENESIS_COINBASE=b'\x00' * 20,
    GENESIS_PRI_KEY=decode_hex("46b9e861b63d3509c88b7817275a30d22d62c8cd8fa6486ddee35ef0d8e0495f"),
    TOTAL_COIN=10**18,
    GENESIS_STATE_ROOT=decode_hex("0x8771088c8f539a28e9005f7a4133151b377dad2c2cfec5366536e27ab3035c96"),
    GENESIS_RECEIPTS_ROOT=decode_hex("0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
)
