pragma solidity >=0.4.15;


contract AdminControl {
    struct Vote {
        uint8 index;
        uint256[3] votes;
    }

    /*** Query Functions ***/
    /**
     * @dev cast vote for parameters
     * @param version The parameter version number to vote for
     * @param vote_data The list of votes to cast
     */
    function castVote(uint64 version, Vote[] calldata vote_data) public {}

    /**
     * @dev read the vote data of an account
     * @param addr The address of the account to read
     */
    function readVote(address addr) public view returns (Vote[] memory) {}
}
