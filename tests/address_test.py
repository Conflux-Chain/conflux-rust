from conflux.address import hex_to_b32_address, b32_address_to_hex

print(hex_to_b32_address("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9") == "cfx:03uvyj5kjzdee2z85cycmhwkz3njpv6ut404kg24d3")
print(b32_address_to_hex("cfx:03uvyj5kjzdee2z85cycmhwkz3njpv6ut404kg24d3") == "F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9".lower())
