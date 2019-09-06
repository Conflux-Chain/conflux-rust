pragma solidity >=0.4.22 <0.6.0;
contract EventsTestContract {

    uint32 counter;
    event Constructed(address indexed by);
    event Called(address indexed by, uint32 indexed num);
    
    modifier testmodifier(uint32 x) {
        require(hoo() <= x, "x < counter!");
        _;
    }

    constructor() public {
        emit Constructed(msg.sender);
    }

    function foo() public {
        counter += 1;
        emit Called(msg.sender, counter);
    }
    
    function goo(uint32 x) public testmodifier(x){
        counter += x;
        emit Called(msg.sender, counter);
    }
    
    function hoo() public view returns (uint32) {
        return counter;
    }
    
    function byte32oo(bytes32 x) public pure returns (bytes32){
        return x;
    }
    
    function getSha256(bytes32 _x)
        public
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(_x));
    }
}

