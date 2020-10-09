pragma solidity >=0.6.12;

contract RevertMessage {
    function foo() public pure {
        require(false, "A");
    }
}