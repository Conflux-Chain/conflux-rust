pragma solidity ^0.8;

contract Storage {
    mapping(uint64 => uint) data;

    constructor() {}

    function change(uint64 index) public {
        data[index] += 1;
    }

    function set(uint64 index) public {
        data[index] = 1;
    }

    function reset(uint64 index) public {
        data[index] = 0;
    }
}