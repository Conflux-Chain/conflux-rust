from conflux.address import hex_to_b32_address, b32_address_to_hex

print(hex_to_b32_address("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9") == "cfx:ad458wfxw9rssc9jfp8pyv6x9dzw05g43eaexucerd")
print(b32_address_to_hex("cfx:ad458wfxw9rssc9jfp8pyv6x9dzw05g43eaexucerd") == "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9".lower())
