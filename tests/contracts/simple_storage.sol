pragma solidity >=0.4.22;

// based on https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getstorageat

contract Storage {
    uint pos0;
    mapping(address => uint) pos1;

    constructor() public {
        pos0 = 1234;
        pos1[0x391694e7E0B0cCE554cb130d723A9d27458F9298] = 5678;
    }
}