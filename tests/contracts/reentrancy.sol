pragma solidity >=0.4.15;

contract Reentrance {
    mapping (address => uint) balances;

    function balanceOf(address owner) public view returns (uint balance) {
        return balances[owner];
    }

    function addBalance() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawBalance() public {
        uint x = balances[msg.sender];
        (bool success, ) = msg.sender.call.value(x)("");
        require(success, "Fails to withdraw by callback.");
        balances[msg.sender] = 0;
    }
}
