pragma solidity >=0.7.0;

contract BlackHole {
    constructor() payable {
    }

    receive() external payable {
        // Accept payments.
    }
}
