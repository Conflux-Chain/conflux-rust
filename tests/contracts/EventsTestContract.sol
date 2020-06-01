pragma solidity >=0.4.22 <0.6.0;
contract EventsTestContract {

    uint32 counter;

    event Constructed(address indexed by, address data);
    event Called(address indexed by, uint32 indexed num);

    constructor() public {
        emit Constructed(msg.sender, msg.sender);
    }

    function foo() public {
        counter += 1;
        emit Called(msg.sender, counter);
    }
}
