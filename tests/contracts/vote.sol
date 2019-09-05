pragma solidity ^0.5.0;

contract DummyErc20 {
    string public name = "BasicErc20Token";
    string public symbol = "BET";
    uint8 public decimals = 0;

    function balanceOf(address) public pure returns (uint256) {
        return 500;
    }
}


contract AdvancedTokenVote1202 {
    mapping(uint/*issueId*/ => string/*issueDesc*/) public issueDescriptions;
    mapping(uint/*issueId*/ => uint[]/*option*/) internal options;
    mapping(uint/*issueId*/ => mapping(uint/*option*/ => string/*desc*/)) internal optionDescMap;
    mapping(uint/*issueId*/ => bool) internal isOpen;

    mapping(uint/*issueId*/ => mapping (address/*user*/ => uint256/*weight*/)) public weights;
    mapping(uint/*issueId*/ => mapping (uint => uint256)) public weightedVoteCounts;
    mapping(uint/*issueId*/ => mapping (address => uint)) public  ballots;

    constructor() public {
        // This is a hack, remove until string[] is supported for a function parameter
        optionDescMap[0][1] = "No";
        optionDescMap[0][2] = "Yes, 100 more";
        optionDescMap[0][3] = "Yes, 200 more";

        optionDescMap[1][1] = "No";
        optionDescMap[1][2] = "Yes";
    }

    function createIssue(uint issueId, address _tokenAddr, uint[] memory options_,
        address[] memory qualifiedVoters_, string memory issueDesc_
    ) public {
        require(options_.length >= 2);
        options[issueId] = options_;
        DummyErc20 token = DummyErc20(_tokenAddr);
        isOpen[issueId] = true;

        // We realize the ERC20 will need to be extended to support snapshoting the weights/balances.
        for (uint i = 0; i < qualifiedVoters_.length; i++) {
            address voter = qualifiedVoters_[i];
            weights[issueId][voter] = token.balanceOf(voter);
        }
        issueDescriptions[issueId] = issueDesc_;

    }

    function vote(uint issueId, uint option) public returns (bool success) {
        require(isOpen[issueId]);
        // TODO check if option is valid

        uint256 weight = weights[issueId][msg.sender];
        weightedVoteCounts[issueId][option] += weight;  // initial value is zero
        ballots[issueId][msg.sender] = option;
        emit OnVote(issueId, msg.sender, option);
        return true;
    }

    function setStatus(uint issueId, bool isOpen_) public returns (bool success) {
        // Should have a sense of ownership. Only Owner should be able to set the status
        isOpen[issueId] = isOpen_;
        emit OnStatusChange(issueId, isOpen_);
        return true;
    }

    function ballotOf(uint issueId, address addr) public view returns (uint option) {
        return ballots[issueId][addr];
    }

    function weightOf(uint issueId, address addr) public view returns (uint weight) {
        return weights[issueId][addr];
    }

    function getStatus(uint issueId) public view returns (bool isOpen_) {
        return isOpen[issueId];
    }

    function weightedVoteCountsOf(uint issueId, uint option) public view returns (uint count) {
        return weightedVoteCounts[issueId][option];
    }

    // TODO: changed to topOptions if determined
    function winningOption(uint issueId) public view returns (uint option) {
        uint ci = 0;
        for (uint i = 1; i < options[issueId].length; i++) {
            uint optionI = options[issueId][i];
            uint optionCi = options[issueId][ci];
            if (weightedVoteCounts[issueId][optionI] > weightedVoteCounts[issueId][optionCi]) {
                ci = i;
            } // else keep it there
        }
        return options[issueId][ci];
    }

    function issueDescription(uint issueId) public view returns (string memory desc) {
        return issueDescriptions[issueId];
    }

    function availableOptions(uint issueId) public view returns (uint[] memory options_) {
        return options[issueId];
    }

    function optionDescription(uint issueId, uint option) public view returns (string memory desc) {
        return optionDescMap[issueId][option];
    }

    event OnVote(uint issueId, address indexed _from, uint _value);
    event OnStatusChange(uint issueId, bool newIsOpen);

}
