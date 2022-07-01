pragma solidity >=0.7.0;

contract CIP98Test {
    function query() public view returns(bytes32) {
        return blockhash(block.number-1);
    }
}
