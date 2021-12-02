pragma solidity >=0.4.15;

contract Staking {
    /*** Query Functions ***/
    /**
     * @dev get user's staking balance
     * @param user The address of specific user
     */
    function getStakingBalance(address user) public view returns (uint256) {}

    /**
     * @dev get user's locked staking balance at given blockNumber
     * @param user The address of specific user
     * @param blockNumber The blockNumber as index.
     */
    // ------------------------------------------------------------------------
    // Note: if the blockNumber is less than the current block number, function
    // will return current locked staking balance.
    // ------------------------------------------------------------------------
    function getLockedStakingBalance(address user, uint256 blockNumber) public view returns (uint256) {}


    /**
     * @dev get user's vote power staking balance at given blockNumber
     * @param user The address of specific user
     * @param blockNumber The blockNumber as index.
     */
    // ------------------------------------------------------------------------
    // Note: if the blockNumber is less than the current block number, function
    // will return current vote power.
    // ------------------------------------------------------------------------
    function getVotePower(address user, uint256 blockNumber) public view returns (uint256) {}

    function deposit(uint256 amount) external {}

    function withdraw(uint256 amount) external {}

    function voteLock(uint256 amount, uint256 unlockBlockNumber) external {}
}