pragma solidity >=0.8.0;

interface Context {
    function epochNumber() external view returns (uint64);
}

contract ContextUser {
    function getBlockNumber() external view returns (uint256) {
        return block.number;
    }

    function getEpochNumber() external view returns (uint256) {
        return Context(0x0888000000000000000000000000000000000004).epochNumber();
    }
}