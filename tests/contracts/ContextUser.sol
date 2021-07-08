pragma solidity >=0.8.0;

interface Context {
    function epochNumber() external view returns (uint64);
}

contract ContextUser {
    event Notify(uint256);

    function getBlockNumber() external returns (uint256) {
        emit Notify(block.number);
        return block.number;
    }

    function getEpochNumber() external returns (uint256) {
        uint256 epochNumber = Context(0x0888000000000000000000000000000000000004).epochNumber();
        emit Notify(epochNumber);
        return epochNumber;
    }
}